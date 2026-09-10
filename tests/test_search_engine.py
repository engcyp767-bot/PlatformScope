"""Unit tests for platform_core/search_engine.py."""

import unittest
from platform_core.search_engine import GlobalSearchEngine


class TestGlobalSearchEngine(unittest.TestCase):
    def setUp(self):
        self.engine = GlobalSearchEngine.get_instance()

    def test_short_query_returns_empty(self):
        res = self.engine.search("")
        self.assertEqual(res["total_matches"], 0)
        self.assertEqual(len(res["results"]["incidents"]), 0)

        res1 = self.engine.search("a")
        self.assertEqual(res1["total_matches"], 0)

    def test_search_structure_and_keys(self):
        res = self.engine.search("admin", limit_per_entity=3)
        self.assertIn("query", res)
        self.assertEqual(res["query"], "admin")
        self.assertIn("total_matches", res)
        self.assertIn("results", res)
        self.assertIn("incidents", res["results"])
        self.assertIn("assets", res["results"])
        self.assertIn("rules", res["results"])
        self.assertIn("iocs", res["results"])
        self.assertIn("tasks", res["results"])

    def test_scoped_entities_search(self):
        res = self.engine.search("log", entities=["rules"])
        self.assertEqual(len(res["results"]["incidents"]), 0)
        self.assertEqual(len(res["results"]["assets"]), 0)
        self.assertIsInstance(res["results"]["rules"], list)


if __name__ == "__main__":
    unittest.main()
