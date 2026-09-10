"""Unit tests for ForensicKnowledgeBase."""

import unittest
from logscope.knowledge_base import ForensicKnowledgeBase


class KnowledgeBaseTests(unittest.TestCase):
    def setUp(self):
        self.kb = ForensicKnowledgeBase()

    def test_high_value_event_lookup(self):
        item = self.kb.get_by_event_id("1102")
        self.assertIsNotNone(item)
        self.assertEqual(item.name_ar, "مسح وتفريغ سجل التدقيق الأمني")
        self.assertEqual(item.base_severity, 95)
        self.assertIn("Defense Evasion", item.mitre_tactics)
        self.assertIn("T1070.001 - Clear Windows Event Logs", item.mitre_techniques)

    def test_kerberoasting_event_lookup(self):
        item = self.kb.get_by_event_id("4769")
        self.assertIsNotNone(item)
        self.assertIn("Kerberoasting", item.mitre_techniques[0])

    def test_catalog_integrity(self):
        self.assertGreaterEqual(self.kb.count(), 10)


if __name__ == "__main__":
    unittest.main()
