import importlib.util
from pathlib import Path
import unittest
from datetime import datetime
spec = importlib.util.spec_from_file_location('gate', Path(__file__).parents[1]/'scripts/schedule_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

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
        self.assertTrue(self.at('01:00:00', {'slot':'2026-10-05/11:00'}, day='2026-10-06')[0])
    def test_no_stale_run_in_early_morning(self):
        self.assertFalse(self.at('06:00:00')[0])
        self.assertFalse(self.at('09:00:00')[0])
    def test_success_deduplicates(self):
        self.assertFalse(self.at('20:00:00', {'slot':'2026-10-05/11:00'})[0])
        self.assertTrue(self.at('21:00:00', {'slot':'2026-10-05/11:00'})[0])
    def test_failure_retries(self):
        self.assertTrue(self.at('11:30:00', {'slot':'2026-10-04/21:00'})[0])
    def test_timer_dispatch_is_deduplicated_like_schedule(self):
        wd='workflow_dispatch'
        self.assertFalse(self.at('11:30:00', {'slot':'2026-10-05/11:00'}, wd, trigger='timer')[0])
        self.assertTrue(self.at('11:30:00', {'slot':'2026-10-04/21:00'}, wd, trigger='timer')[0])
        self.assertFalse(self.at('09:00:00', event=wd, trigger='timer')[0])
        self.assertTrue(self.at('09:00:00', event=wd, trigger='manual')[0])
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
        r = gate.plan(t('21:00:10'), {'slot': '2026-10-05/11:00'}, '2026-10-05/11:00', 4, t('12:30:00').isoformat())
        self.assertTrue(r['dispatch']); self.assertEqual((r['attempt_slot'], r['attempts']), ('2026-10-05/21:00', 1))
    def test_published_slot_sleeps_to_next(self):
        r = gate.plan(t('11:40:00'), {'slot': '2026-10-05/11:00'})
        self.assertFalse(r['dispatch']); self.assertEqual(r['wait_seconds'], int(gate.MAX_WAIT.total_seconds()))
        r = gate.plan(t('19:00:00'), {'slot': '2026-10-05/11:00'})
        self.assertEqual(r['wait_seconds'], 2 * 3600)
    def test_late_evening_catch_up_after_midnight(self):
        now = datetime.fromisoformat('2026-10-06T00:30:00+08:00')
        r = gate.plan(now, {'slot': '2026-10-05/11:00'})
        self.assertTrue(r['dispatch']); self.assertEqual(r['attempt_slot'], '2026-10-05/21:00')
