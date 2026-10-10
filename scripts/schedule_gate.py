#!/usr/bin/env python3
"""Wall-clock slots, not nominal cron timestamps. Asia/Shanghai, fail closed on bad state."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo('Asia/Shanghai')
STATE = Path('.schedule/success.json')
MORNING_SLOT = '11:58'
EVENING_SLOT = '18:00'
MORNING_START_MINUTE = 11 * 60 + 58
EVENING_START_MINUTE = 18 * 60

def slot_at(now):
    local = now.astimezone(TZ)
    minute = local.hour * 60 + local.minute
    if minute < MORNING_START_MINUTE:  # Never replay before today's morning slot.
        return None
    slot_name = EVENING_SLOT if minute >= EVENING_START_MINUTE else MORNING_SLOT
    return f'{local:%Y-%m-%d}/{slot_name}'

def decide(now, state, event='schedule'):
    slot = slot_at(now)
    if event != 'schedule':
        return True, slot or '', 'manual override'
    if slot is None:
        return False, '', 'before first window'
    if state.get('slot') == slot:
        return False, slot, 'already published successfully'
    return True, slot, 'due or retry'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mark', default=None)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    if args.mark is not None:
        # Mark the slot picked by gate, not the slot at completion.
        if not args.mark:
            return
        datetime.strptime(args.mark, '%Y-%m-%d/%H:%M')
        if args.mark[-5:] not in (MORNING_SLOT, EVENING_SLOT):
            raise ValueError('invalid slot')
        STATE.parent.mkdir(exist_ok=True)
        temp = STATE.with_suffix('.tmp')
        temp.write_text(json.dumps({'slot': args.mark, 'completedAt': now.isoformat(),
                                    'runId': os.environ.get('GITHUB_RUN_ID', '')}, indent=2)+'\n')
        temp.replace(STATE)
        return
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    if not isinstance(state, dict):
        raise ValueError('invalid scheduling state')
    due, slot, reason = decide(now, state, os.environ.get('GITHUB_EVENT_NAME', 'schedule'))
    print(f'{now.isoformat()} slot={slot} due={due}: {reason}')
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a') as f:
            f.write(f'due={str(due).lower()}\nslot={slot}\n')
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as f:
            f.write(f'## Scheduling\n\nActual UTC: {now.isoformat()}\n\nCST slot: `{slot}`; due: {due}; {reason}.\n')

if __name__ == '__main__':
    main()
