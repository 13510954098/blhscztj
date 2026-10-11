import importlib.util
from pathlib import Path
import unittest
from datetime import datetime
spec = importlib.util.spec_from_file_location('gate', Path(__file__).parents[1]/'scripts/schedule_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

M = {'slot': '2026-10-05/11:00', 'source_date': '2026-10-05'}

class ScheduleTests(unittest.TestCase):
    def at(self, time, state=None, event='schedule', day='2026-10-05', trigger=''):
        return gate.decide(datetime.fromisoformat(day+'T'+time+'+08:00'), state or {}, event, trigger)
    def test_boundaries(self):
        self.assertFalse(self.at('10:59:59')[0])
        self.assertEqual(self.at('11:00:00')[1], '2026-10-05/11:00')
        self.assertEqual(self.at('20:59:59')[1], '2026-10-05/11:00')
        self.assertEqual(self.at('21:00:00')[1], '2026-10-05/21:00')
    def test_delayed_trigger_uses_current_slot(self):
        self.assertEqual(self.at('23:04:55')[1], '2026-10-05/21:00')
    def test_after_midnight_belongs_to_previous_evening(self):
        self.assertEqual(self.at('00:26:00', day='2026-10-06')[1], '2026-10-05/21:00')
        self.assertEqual(self.at('05:59:59', day='2026-10-06')[1], '2026-10-05/21:00')
        self.assertFalse(self.at('01:00:00', {'slot':'2026-10-05/21:00'}, day='2026-10-06')[0])
        self.assertTrue(self.at('01:00:00', M, day='2026-10-06')[0])
    def test_no_stale_run_in_early_morning(self):
        self.assertFalse(self.at('06:00:00')[0])
        self.assertFalse(self.at('09:00:00')[0])
    def test_success_deduplicates(self):
        self.assertFalse(self.at('20:00:00', M)[0])
        self.assertTrue(self.at('21:00:00', M)[0])
    def test_failure_retries(self):
        self.assertTrue(self.at('11:30:00', {'slot':'2026-10-04/21:00'})[0])
    def test_timer_dispatch_is_deduplicated_like_schedule(self):
        wd='workflow_dispatch'
        self.assertFalse(self.at('11:30:00', M, wd, trigger='timer')[0])
        self.assertTrue(self.at('11:30:00', {'slot':'2026-10-04/21:00'}, wd, trigger='timer')[0])
        self.assertFalse(self.at('09:00:00', event=wd, trigger='timer')[0])
        self.assertTrue(self.at('09:00:00', event=wd, trigger='manual')[0])
    def test_evening_mode_is_alive_only_after_morning_published(self):
        m=gate.run_mode
        self.assertEqual(m('2026-10-05/21:00', M), 'alive')
        self.assertEqual(m('2026-10-05/21:00', M, 'workflow_dispatch', 'timer'), 'alive')
        self.assertEqual(m('2026-10-05/21:00', {'slot':'2026-10-04/21:00'}), 'full')   # morning never published
        self.assertEqual(m('2026-10-05/11:00', {'slot':'2026-10-04/21:00'}), 'full')
        self.assertEqual(m('2026-10-05/21:00', M, 'workflow_dispatch', 'manual'), 'full')
        self.assertEqual(m('', {}), 'full')
    def test_next_slot_start(self):
        f=lambda t: gate.next_slot_start(datetime.fromisoformat(t)).isoformat()
        self.assertEqual(f('2026-10-05T09:00:00+08:00'),'2026-10-05T11:00:00+08:00')
        self.assertEqual(f('2026-10-05T11:00:00+08:00'),'2026-10-05T21:00:00+08:00')
        self.assertEqual(f('2026-10-05T22:00:00+08:00'),'2026-10-06T11:00:00+08:00')
        self.assertEqual(f('2026-10-05T03:00:00+00:00'),'2026-10-05T21:00:00+08:00')
    def test_manual_bypass(self):
        self.assertTrue(self.at('09:00:00', event='workflow_dispatch')[0])

def t(s):
    return datetime.fromisoformat('2026-10-05T' + s + '+08:00')

class PreciseTimerTests(unittest.TestCase):
    def test_sleeps_until_morning_slot(self):
        r = gate.plan(t('09:00:00'), {})
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], 2 * 3600)
    def test_long_waits_are_capped_under_job_limit(self):
        r = gate.plan(t('22:00:00'), {'slot': '2026-10-05/21:00'})
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], int(gate.MAX_WAIT.total_seconds()))
    def test_dispatches_when_slot_due(self):
        r = gate.plan(t('11:00:05'), {'slot': '2026-10-04/21:00'})
        self.assertTrue(r['dispatch']); self.assertEqual((r['attempt_slot'], r['attempts']), ('2026-10-05/11:00', 1))
        self.assertEqual(r['wait_seconds'], 15 * 60)
    def test_waits_while_update_running(self):
        r = gate.plan(t('11:15:00'), {}, '2026-10-05/11:00', 1, t('11:00:05').isoformat(), update_busy=True)
        self.assertFalse(r['dispatch']); self.assertEqual(r['attempts'], 1)
    def test_retry_backoff_and_limit(self):
        last = t('11:00:00').isoformat()
        r = gate.plan(t('11:20:00'), {}, '2026-10-05/11:00', 1, last)
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], 600)
        r = gate.plan(t('11:31:00'), {}, '2026-10-05/11:00', 1, last)
        self.assertTrue(r['dispatch']); self.assertEqual(r['attempts'], 2)
        r = gate.plan(t('13:00:00'), {}, '2026-10-05/11:00', gate.MAX_ATTEMPTS_PER_SLOT, last)
        self.assertFalse(r['dispatch']); self.assertIn('gave up', r['reason'])
        self.assertEqual(r['wait_seconds'], int(gate.MAX_WAIT.total_seconds()))
    def test_attempts_reset_for_new_slot(self):
        r = gate.plan(t('21:00:10'), M, '2026-10-05/11:00', 4, t('12:30:00').isoformat())
        self.assertTrue(r['dispatch']); self.assertEqual((r['attempt_slot'], r['attempts']), ('2026-10-05/21:00', 1))
    def test_published_slot_sleeps_to_next(self):
        r = gate.plan(t('11:40:00'), M)
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], int(gate.MAX_WAIT.total_seconds()))
        r = gate.plan(t('19:00:00'), M)
        self.assertEqual(r['wait_seconds'], 2 * 3600)
    def test_late_evening_catch_up_after_midnight(self):
        now = datetime.fromisoformat('2026-10-06T00:30:00+08:00')
        r = gate.plan(now, M)
        self.assertTrue(r['dispatch']); self.assertEqual(r['attempt_slot'], '2026-10-05/21:00')


STALE = {'slot': '2026-10-05/11:00'}                              # old state / stale fetch
OLD_ISSUE = {'slot': '2026-10-05/11:00', 'source_date': '2026-10-04'}


class SourceFreshnessTests(unittest.TestCase):
    def test_parse_source_date(self):
        self.assertEqual(gate.parse_source_date('<p>最后更新：2026-10-10 11:12（北京时间）</p>'), '2026-10-10')
        self.assertEqual(gate.parse_source_date('最后更新: 2026-9-7'), '2026-09-07')
        self.assertIsNone(gate.parse_source_date('<html>nothing</html>'))
        self.assertIsNone(gate.parse_source_date(None))

    def test_morning_needs_that_days_issue(self):
        self.assertTrue(gate.slot_done('2026-10-05/11:00', M))
        self.assertFalse(gate.slot_done('2026-10-05/11:00', STALE))
        self.assertFalse(gate.slot_done('2026-10-05/11:00', OLD_ISSUE))
        self.assertTrue(gate.slot_done('2026-10-05/21:00', {'slot': '2026-10-05/21:00', 'source_date': '2026-10-04'}))

    def test_evening_runs_full_when_morning_got_old_issue(self):
        self.assertEqual(gate.run_mode('2026-10-05/21:00', STALE), 'full')
        self.assertEqual(gate.run_mode('2026-10-05/21:00', OLD_ISSUE), 'full')
        self.assertEqual(gate.run_mode('2026-10-05/21:00', M), 'alive')

    def test_gate_skips_clock_tick_while_site_is_stale(self):
        now = t('11:30:00')
        self.assertFalse(gate.decide(now, STALE, 'schedule', '', '2026-10-04')[0])
        self.assertFalse(gate.decide(now, STALE, 'workflow_dispatch', 'timer', '2026-10-04')[0])
        self.assertTrue(gate.decide(now, STALE, 'workflow_dispatch', 'timer', '2026-10-05')[0])
        self.assertTrue(gate.decide(now, STALE, 'workflow_dispatch', 'timer', None)[0])   # unknown -> try
        self.assertTrue(gate.decide(now, STALE, 'workflow_dispatch', 'manual', '2026-10-04')[0])
        self.assertTrue(gate.decide(t('21:00:05'), M, 'schedule', '', '2026-10-04')[0])  # evening ignores site

    def test_needs_source_check(self):
        self.assertTrue(gate.needs_source_check(t('11:00:05'), STALE))
        self.assertFalse(gate.needs_source_check(t('11:00:05'), M))
        self.assertFalse(gate.needs_source_check(t('21:00:05'), STALE))
        self.assertFalse(gate.needs_source_check(t('09:00:00'), {}))

    def test_timer_polls_until_site_updates(self):
        r = gate.plan(t('11:00:05'), STALE, source_date='2026-10-04')
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], 600)
        self.assertEqual(r['attempts'], 0)                      # polling does not burn attempts
        self.assertIn('source not updated', r['reason'])
        r = gate.plan(t('11:10:05'), STALE, source_date='2026-10-05')
        self.assertTrue(r['dispatch']); self.assertEqual(r['attempts'], 1)
        r = gate.plan(t('11:10:05'), STALE, source_date=None)    # check failed -> fall back to dispatch
        self.assertTrue(r['dispatch'])

    def test_poll_never_sleeps_past_evening_slot(self):
        r = gate.plan(t('20:55:00'), STALE, source_date='2026-10-04')
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], 300)
        r = gate.plan(t('21:00:05'), STALE, source_date='2026-10-04')
        self.assertTrue(r['dispatch']); self.assertEqual(r['attempt_slot'], '2026-10-05/21:00')

    def test_busy_update_wins_over_source_poll(self):
        r = gate.plan(t('11:20:00'), STALE, '2026-10-05/11:00', 1, t('11:10:00').isoformat(),
                      update_busy=True, source_date='2026-10-04')
        self.assertEqual(r['wait_seconds'], 15 * 60)


class MarkTests(unittest.TestCase):
    def run_mark(self, slot, meta):
        import json, os, sys, tempfile
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                if meta is not None:
                    Path('sub').mkdir()
                    Path('sub/meta.json').write_text(json.dumps(meta), encoding='utf-8')
                argv, sys.argv = sys.argv, ['schedule_gate.py', '--mark', slot]
                try:
                    gate.main()
                finally:
                    sys.argv = argv
                f = Path('.schedule/success.json')
                return json.loads(f.read_text()) if f.exists() else None
            finally:
                os.chdir(old)

    def test_morning_mark_requires_todays_issue(self):
        self.assertIsNone(self.run_mark('2026-10-05/11:00', {'source_date': '2026-10-04'}))
        self.assertIsNone(self.run_mark('2026-10-05/11:00', {}))
        self.assertIsNone(self.run_mark('2026-10-05/11:00', None))
        r = self.run_mark('2026-10-05/11:00', {'source_date': '2026-10-05'})
        self.assertEqual((r['slot'], r['source_date']), ('2026-10-05/11:00', '2026-10-05'))

    def test_evening_mark_always_closes(self):
        r = self.run_mark('2026-10-05/21:00', {'source_date': '2026-10-04'})
        self.assertEqual((r['slot'], r['source_date']), ('2026-10-05/21:00', '2026-10-04'))
