import unittest
import json
import os
import shutil
import urllib.request
from pathlib import Path
from threading import Thread
from http.server import HTTPServer
import time
import sys

_root = str(Path(__file__).resolve().parent.parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

from logscope.server import RequestHandler, JOBS_DIR
from logscope.result_sink import SQLiteResultSink

class PaginatedAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server on a test port
        cls.port = 19444
        cls.server = HTTPServer(("127.0.0.1", cls.port), RequestHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(1) # wait for server to start

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def setUp(self):
        self.job_id_sqlite = "11111111111111111111111111111111"
        self.job_id_legacy = "22222222222222222222222222222222"
        self.job_id_empty = "33333333333333333333333333333333"
        
        for jid in [self.job_id_sqlite, self.job_id_legacy, self.job_id_empty]:
            path = JOBS_DIR / jid
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
                
        # Setup SQLite job
        os.makedirs(JOBS_DIR / self.job_id_sqlite, exist_ok=True)
        sink = SQLiteResultSink(JOBS_DIR / self.job_id_sqlite / "results.db")
        for i in range(150):
            sink.add({"event_id": f"evt_{i}", "risk_score": i})
        sink.finalize()
        
        with open(JOBS_DIR / self.job_id_sqlite / "analysis.json", "w") as f:
            json.dump({
                "result_storage": {"type": "sqlite", "version": 1}
            }, f)
            
        # Setup Legacy job
        os.makedirs(JOBS_DIR / self.job_id_legacy, exist_ok=True)
        with open(JOBS_DIR / self.job_id_legacy / "analysis.json", "w") as f:
            json.dump({
                "records": [{"event_id": f"leg_{i}", "risk_score": i} for i in range(150)]
            }, f)
            
        # Setup Empty job
        os.makedirs(JOBS_DIR / self.job_id_empty, exist_ok=True)
        sink_empty = SQLiteResultSink(JOBS_DIR / self.job_id_empty / "results.db")
        sink_empty.finalize()
        with open(JOBS_DIR / self.job_id_empty / "analysis.json", "w") as f:
            json.dump({"result_storage": {"type": "sqlite", "version": 1}}, f)

    def tearDown(self):
        for jid in [self.job_id_sqlite, self.job_id_legacy, self.job_id_empty]:
            path = JOBS_DIR / jid
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)

    def _fetch(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_sqlite_first_page_default_limit(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 100)
        self.assertEqual(data["records"][0]["event_id"], "evt_0")
        self.assertEqual(data["pagination"]["limit"], 100)
        self.assertEqual(data["pagination"]["next_cursor"], 100)
        self.assertTrue(data["pagination"]["has_more"])

    def test_sqlite_second_page_with_cursor(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records?cursor=100")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 50)
        self.assertEqual(data["records"][0]["event_id"], "evt_100")
        self.assertFalse(data["pagination"]["has_more"])
        self.assertIsNone(data["pagination"]["next_cursor"])

    def test_sqlite_limit_bounds(self):
        # Max limit
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records?limit=5000")
        self.assertEqual(status, 200)
        # Should clamp to 1000
        self.assertEqual(data["pagination"]["limit"], 1000)
        self.assertEqual(len(data["records"]), 150)

    def test_sqlite_empty_result(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_empty}/records")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 0)
        self.assertFalse(data["pagination"]["has_more"])

    def test_legacy_pagination(self):
        # First page
        status, data = self._fetch(f"/api/jobs/{self.job_id_legacy}/records?limit=50")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 50)
        self.assertEqual(data["records"][0]["event_id"], "leg_0")
        self.assertTrue(data["pagination"]["has_more"])
        self.assertEqual(data["pagination"]["next_cursor"], 50)
        
        # Second page
        status, data2 = self._fetch(f"/api/jobs/{self.job_id_legacy}/records?cursor=50&limit=150")
        self.assertEqual(status, 200)
        self.assertEqual(len(data2["records"]), 100) # Only 100 left
        self.assertFalse(data2["pagination"]["has_more"])

    def test_malformed_cursor(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records?cursor=abc")
        self.assertEqual(status, 400)
        
    def test_invalid_job_id(self):
        status, data = self._fetch(f"/api/jobs/invalid_id/records")
        self.assertEqual(status, 400)
        
    def test_nonexistent_job(self):
        status, data = self._fetch(f"/api/jobs/44444444444444444444444444444444/records")
        self.assertEqual(status, 404)

    def test_sqlite_search(self):
        # The data in sqlite test has event_id "evt_10" etc. Let's search for "evt_12"
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records?q=evt_12")
        self.assertEqual(status, 200)
        # Should match evt_12, evt_120, evt_121... evt_129
        self.assertEqual(len(data["records"]), 11)
        self.assertTrue(all("evt_12" in r["event_id"] for r in data["records"]))
        
    def test_sqlite_search_no_match(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_sqlite}/records?q=notfoundstring")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 0)

    def test_legacy_search(self):
        status, data = self._fetch(f"/api/jobs/{self.job_id_legacy}/records?q=leg_42")
        self.assertEqual(status, 200)
        self.assertEqual(len(data["records"]), 1)
        self.assertEqual(data["records"][0]["event_id"], "leg_42")

if __name__ == "__main__":
    unittest.main()
