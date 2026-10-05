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
        self.assertFalse(self.at('11:29:59')[0])
        self.assertEqual(self.at('11:30:00')[1], '2026-10-05/11:30')
        self.assertEqual(self.at('17:59:59')[1], '2026-10-05/11:30')
        self.assertEqual(self.at('18:00:00')[1], '2026-10-05/18:00')
    def test_delayed_trigger_uses_current_slot(self):
        self.assertEqual(self.at('23:04:55')[1], '2026-10-05/18:00')
    def test_success_deduplicates(self):
        self.assertFalse(self.at('17:00:00', {'slot':'2026-10-05/11:30'})[0])
        self.assertTrue(self.at('18:00:00', {'slot':'2026-10-05/11:30'})[0])
    def test_failure_retries(self):
        self.assertTrue(self.at('12:00:00', {'slot':'2026-10-04/18:00'})[0])
    def test_manual_bypass(self):
        self.assertTrue(self.at('09:00:00', event='workflow_dispatch')[0])
    def test_no_stale_run_after_midnight(self):
        self.assertFalse(self.at('00:01:00')[0])
