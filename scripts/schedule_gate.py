#!/usr/bin/env python3
"""Wall-clock slots, not nominal cron timestamps. Asia/Shanghai, fail closed on bad state."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import urllib.request
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Asia/Shanghai')
STATE = Path('.schedule/success.json')
MORNING_SLOT = '11:00'
EVENING_SLOT = '21:00'
MORNING_START_MINUTE = 11 * 60
EVENING_START_MINUTE = 21 * 60
# GitHub's own cron is often hours late; a late evening tick that lands after
# midnight still belongs to the previous day's 21:00 slot until this cutoff.
EVENING_GRACE_END_MINUTE = 6 * 60
# workflow_dispatch with trigger=timer comes from .github/workflows/timer.yml and
# is a clock tick (deduplicated by slot); a plain manual dispatch always runs.
TIMER_TRIGGER = 'timer'
# The site's publish time varies (observed 08:20-14:00 CST). The 11:00 slot only
# counts as done once the fetched content is that day's issue; until then the
# timer polls the page's "最后更新" date instead of grabbing yesterday's nodes.
SOURCE_PAGE = 'https://jcnode.com/posts/free-nodes/'
SOURCE_DATE_RE = re.compile(r'最后更新\s*[：:]\s*(\d{4})-(\d{1,2})-(\d{1,2})')
META = Path('sub/meta.json')

def parse_source_date(html):
    m = SOURCE_DATE_RE.search(html or '')
    return f'{int(m[1]):04d}-{int(m[2]):02d}-{int(m[3]):02d}' if m else None

def fetch_source_date(timeout=20):
    """Site's "最后更新" date (YYYY-MM-DD), or None when unknown (never blocks on errors)."""
    try:
        req = urllib.request.Request(SOURCE_PAGE, headers={
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36',
            'Cache-Control': 'no-cache'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return parse_source_date(resp.read().decode('utf-8', 'ignore'))
    except Exception as exc:  # network trouble must not stop the schedule
        print(f'source date check failed: {type(exc).__name__}: {exc}')
        return None

def is_morning(slot):
    return bool(slot) and slot.endswith('/' + MORNING_SLOT)

def slot_done(slot, state):
    """A morning slot is only done when it published that day's issue."""
    if not slot or state.get('slot') != slot:
        return False
    return not is_morning(slot) or state.get('source_date') == slot[:10]

def source_stale(slot, source_date):
    """True only when the site is known to still show an older issue."""
    return is_morning(slot) and source_date is not None and source_date != slot[:10]

def is_clock_tick(event, trigger=''):
    return event == 'schedule' or (event == 'workflow_dispatch' and trigger == TIMER_TRIGGER)

def slot_at(now):
    local = now.astimezone(TZ)
    minute = local.hour * 60 + local.minute
    if minute < EVENING_GRACE_END_MINUTE:
        return f'{local - timedelta(days=1):%Y-%m-%d}/{EVENING_SLOT}'
    if minute < MORNING_START_MINUTE:  # Morning window opens at 11:00.
        return None
    slot_name = EVENING_SLOT if minute >= EVENING_START_MINUTE else MORNING_SLOT
    return f'{local:%Y-%m-%d}/{slot_name}'

def run_mode(slot, state, event='schedule', trigger=''):
    """'alive' = evening re-test only (skip fetch/merge), 'full' = whole pipeline.

    The site publishes once a day, so the 21:00 slot only needs to drop nodes
    that died during the day -- but only if that day's 11:00 slot actually
    published that day's issue; otherwise the evening run must still fetch.
    Manual runs are full.
    """
    if not is_clock_tick(event, trigger) or not slot or not slot.endswith('/' + EVENING_SLOT):
        return 'full'
    morning = slot[:-len(EVENING_SLOT)] + MORNING_SLOT
    return 'alive' if slot_done(morning, state) else 'full'

def next_slot_start(now):
    """Start of the next slot strictly after ``now`` (aware datetime)."""
    local = now.astimezone(TZ)
    day = local.replace(hour=0, minute=0, second=0, microsecond=0)
    for offset in (0, 1):
        base = day + timedelta(days=offset)
        for minute in (MORNING_START_MINUTE, EVENING_START_MINUTE):
            start = base + timedelta(minutes=minute)
            if start > local:
                return start
    raise AssertionError('unreachable')

def needs_source_check(now, state):
    slot = slot_at(now)
    return is_morning(slot) and not slot_done(slot, state)

def decide(now, state, event='schedule', trigger='', source_date=None):
    slot = slot_at(now)
    if not is_clock_tick(event, trigger):
        return True, slot or '', 'manual override'
    if slot is None:
        return False, '', 'before first window'
    if slot_done(slot, state):
        return False, slot, 'already published successfully'
    if source_stale(slot, source_date):
        return False, slot, f'source not updated yet (最后更新 {source_date})'
    return True, slot, 'due or retry'


# ---- Precise timer (.github/workflows/timer.yml) ---------------------------
# GitHub's own cron for this repo was measured hours late with ~85-90% of ticks
# dropped. timer.yml keeps one job chain alive: each job calls ``--plan``,
# optionally dispatches update.yml (trigger=timer), sleeps (<= 5.5 h, under the
# 6 h job limit) and re-dispatches itself via workflow_dispatch (allowed with
# GITHUB_TOKEN).
MAX_ATTEMPTS_PER_SLOT = 4             # dispatches per slot before giving up until the next slot
RETRY_GAP = timedelta(minutes=30)     # minimum spacing between two dispatches of the same slot
BUSY_POLL = timedelta(minutes=15)     # re-check interval while update.yml is queued/running
SOURCE_POLL = timedelta(minutes=10)   # re-check interval while the site still shows an older issue
MAX_WAIT = timedelta(hours=5, minutes=30)
MIN_WAIT = timedelta(seconds=30)


def _parse(value):
    try:
        result = datetime.fromisoformat(str(value))
        return result if result.tzinfo else None
    except (TypeError, ValueError):
        return None


def _wait_until(now, target):
    return max(MIN_WAIT, min(target - now, MAX_WAIT))


def plan(now, state, attempt_slot='', attempts=0, last_dispatch='', update_busy=False,
         source_date=None):
    """Return what this timer job should do.

    Keys: dispatch (bool), wait_seconds (int), attempt_slot, attempts,
    last_dispatch (carry for the next job) and reason.
    """
    slot = slot_at(now)
    done = slot_done(slot, state)
    if attempt_slot != slot:
        attempts, last_dispatch = 0, ''
    carry = {'attempt_slot': slot or '', 'attempts': attempts, 'last_dispatch': last_dispatch}

    def result(dispatch, wait, reason, **override):
        return {'dispatch': dispatch, 'wait_seconds': int(wait.total_seconds()),
                'reason': reason, **carry, **override}

    if not slot or done:
        return result(False, _wait_until(now, next_slot_start(now)),
                      'slot already published' if done else 'waiting for next slot')
    if update_busy:
        return result(False, BUSY_POLL, 'update workflow queued/running')
    if source_stale(slot, source_date):
        wait = min(SOURCE_POLL, next_slot_start(now) - now)
        return result(False, max(MIN_WAIT, wait), f'source not updated yet (最后更新 {source_date})')
    if attempts >= MAX_ATTEMPTS_PER_SLOT:
        return result(False, _wait_until(now, next_slot_start(now)),
                      f'gave up after {attempts} attempts for {slot}')
    last = _parse(last_dispatch)
    if last is not None and now - last < RETRY_GAP:
        return result(False, max(MIN_WAIT, RETRY_GAP - (now - last)), 'retry backoff')
    return result(True, BUSY_POLL, f'dispatch attempt {attempts + 1} for {slot}',
                  attempts=attempts + 1, last_dispatch=now.isoformat(timespec='seconds'))


def run_plan(args, now):
    try:
        state = json.loads(STATE.read_text()) if STATE.exists() else {}
    except ValueError:
        state = {}
    if not isinstance(state, dict):
        state = {}
    try:
        attempts = max(0, int(args.attempts or 0))
    except ValueError:
        attempts = 0
    source_date = fetch_source_date() if needs_source_check(now, state) else None
    decision = plan(now, state, args.attempt_slot, attempts, args.last_dispatch,
                    args.update_busy.strip().lower() == 'true', source_date)
    print(json.dumps({'now': now.isoformat(timespec='seconds'), 'state_slot': state.get('slot'),
                      'state_source_date': state.get('source_date'), 'site_source_date': source_date,
                      **decision}, ensure_ascii=False))
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a') as f:
            for key in ('dispatch', 'wait_seconds', 'attempt_slot', 'attempts', 'last_dispatch'):
                value = decision[key]
                f.write(f'{key}={str(value).lower() if isinstance(value, bool) else value}\n')
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as f:
            wake = now + timedelta(seconds=decision['wait_seconds'])
            f.write(f"## Precise timer\n\n- now (UTC): {now.isoformat(timespec='seconds')}\n"
                    f"- decision: dispatch={decision['dispatch']} — {decision['reason']}\n"
                    f"- next wake (UTC): {wake.isoformat(timespec='seconds')}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mark', default=None)
    parser.add_argument('--plan', action='store_true', help='precise timer decision (timer.yml)')
    parser.add_argument('--attempt-slot', default='')
    parser.add_argument('--attempts', default='0')
    parser.add_argument('--last-dispatch', default='')
    parser.add_argument('--update-busy', default='false')
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    if args.plan:
        return run_plan(args, now)
    if args.mark is not None:
        # Mark the slot picked by gate, not the slot at completion.
        if not args.mark:
            return
        datetime.strptime(args.mark, '%Y-%m-%d/%H:%M')
        if args.mark[-5:] not in (MORNING_SLOT, EVENING_SLOT):
            raise ValueError('invalid slot')
        try:
            source_date = str(json.loads(META.read_text(encoding='utf-8')).get('source_date') or '')
        except (OSError, ValueError, AttributeError):
            source_date = ''
        if is_morning(args.mark) and source_date != args.mark[:10]:
            print(f'⚠️ 来源仍是 {source_date or "未知"} 的内容，不关闭 {args.mark}；定时器会继续等待来源更新')
            return
        STATE.parent.mkdir(exist_ok=True)
        temp = STATE.with_suffix('.tmp')
        temp.write_text(json.dumps({'slot': args.mark, 'completedAt': now.isoformat(),
                                    'runId': os.environ.get('GITHUB_RUN_ID', ''),
                                    'source_date': source_date}, indent=2)+'\n')
        temp.replace(STATE)
        return
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if not isinstance(state, dict):
        raise ValueError('invalid scheduling state')
    event = os.environ.get('GITHUB_EVENT_NAME', 'schedule')
    trigger = os.environ.get('GATE_TRIGGER', '')
    source_date = (fetch_source_date()
                   if is_clock_tick(event, trigger) and needs_source_check(now, state) else None)
    due, slot, reason = decide(now, state, event, trigger, source_date)
    mode = run_mode(slot, state, event, trigger)
    print(f'{now.isoformat()} slot={slot} due={due} mode={mode}: {reason}')
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a') as f:
            f.write(f'due={str(due).lower()}\nslot={slot}\nmode={mode}\n')
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as f:
            f.write(f'## Scheduling\n\nActual UTC: {now.isoformat()}\n\nCST slot: `{slot}`; due: {due}; mode: {mode}; {reason}.\n')

if __name__ == '__main__':
    main()
