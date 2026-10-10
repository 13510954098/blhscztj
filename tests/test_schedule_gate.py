import importlib.util
from pathlib import Path
import unittest
from datetime import datetime
spec = importlib.util.spec_from_file_location('gate', Path(__file__).parents[1]/'scripts/schedule_gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class ScheduleTests(unittest.TestCase):
    def at(self, time, state=None, event='schedule'):
        return gate.decide(datetime.fromisoformat('2026-10-05T'+time+'+08:00'), state or {}, event)
    def test_boundaries(self):
        self.assertFalse(self.at('12:59:59')[0])
        self.assertEqual(self.at('13:00:00')[1], '2026-10-05/13:00')
        self.assertEqual(self.at('20:59:59')[1], '2026-10-05/13:00')
        self.assertEqual(self.at('21:00:00')[1], '2026-10-05/21:00')
    def test_delayed_trigger_uses_current_slot(self):
        self.assertEqual(self.at('23:04:55')[1], '2026-10-05/21:00')
    def test_success_deduplicates(self):
        self.assertFalse(self.at('20:00:00', {'slot':'2026-10-05/13:00'})[0])
        self.assertTrue(self.at('21:00:00', {'slot':'2026-10-05/13:00'})[0])
    def test_failure_retries(self):
        self.assertTrue(self.at('13:00:00', {'slot':'2026-10-04/21:00'})[0])
    def test_manual_bypass(self):
        self.assertTrue(self.at('09:00:00', event='workflow_dispatch')[0])
    def test_no_stale_run_after_midnight(self):
        self.assertFalse(self.at('00:01:00')[0])
