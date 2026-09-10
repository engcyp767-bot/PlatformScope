"""Unit tests for CorrelationEngine, Incident creation, and Bounded State Maps."""

import unittest
from logscope.canonical import CanonicalEvent, ConclusionLevel
from logscope.correlation import CorrelationEngine, BoundedStateMap


class CorrelationEngineTests(unittest.TestCase):
    def test_bounded_state_map_eviction(self):
        bmap = BoundedStateMap(max_entries=5)
        for i in range(10):
            bmap.set(f"key_{i}", i)
        self.assertEqual(len(bmap._data), 5)
        self.assertFalse(bmap.contains("key_0"))
        self.assertTrue(bmap.contains("key_9"))

    def test_brute_force_then_account_takeover_chain(self):
        engine = CorrelationEngine(max_state_entries=500)

        # 1. Simulate 6 consecutive failed logons from attacker IP 10.10.10.5
        for i in range(6):
            evt_fail = CanonicalEvent(
                event_time=f"2026-09-03 10:00:{i:02d}",
                event_id="4625",
                source_ip="10.10.10.5",
                username="administrator",
                message="An account failed to log on"
            )
            engine.process_event(evt_fail)

        # On the 6th fail, Brute Force finding should be generated
        self.assertIn("DET-CORR-BRUTEFORCE-001", evt_fail.detection_ids)

        # 2. Simulate 1 successful logon from same IP for same user
        evt_succ = CanonicalEvent(
            event_time="2026-09-03 10:01:00",
            event_id="4624",
            source_ip="10.10.10.5",
            username="administrator",
            message="An account was successfully logged on"
        )
        new_incidents = engine.process_event(evt_succ)

        self.assertEqual(len(new_incidents), 1)
        inc = new_incidents[0]
        self.assertTrue(inc.incident_id.startswith("INC-AUTH"))
        self.assertEqual(inc.conclusion_level, ConclusionLevel.LIKELY_SUCCESSFUL)
        self.assertEqual(inc.risk_score, 95)
        self.assertEqual(inc.confidence_score, 92)
        self.assertEqual(inc.event_count, 7)
        self.assertEqual(evt_succ.incident_id, inc.incident_id)

        # 3. Simulate privilege escalation right after takeover
        evt_priv = CanonicalEvent(
            event_time="2026-09-03 10:01:05",
            event_id="4672",
            source_ip="10.10.10.5",
            username="administrator",
            message="Special privileges assigned"
        )
        engine.process_event(evt_priv)
        self.assertEqual(evt_priv.incident_id, inc.incident_id)
        self.assertEqual(inc.conclusion_level, ConclusionLevel.CONFIRMED)
        self.assertEqual(inc.risk_score, 98)


if __name__ == "__main__":
    unittest.main()
