from __future__ import annotations

import unittest

import backend_server
from flowscope import server as flow_server
from logscope import server as log_server


class UnifiedBackendRoutingTests(unittest.TestCase):
    @staticmethod
    def _handler(path: str):
        handler = object.__new__(backend_server.UnifiedAPIHandler)
        handler.path = path
        return handler

    def test_logscope_delegate_binds_logscope_background_workers(self):
        handler = self._handler("/api/logscope/analyze")
        observed = {}

        def delegated(current):
            observed["analysis"] = current._run_analysis.__func__
            observed["enrichment"] = current._run_enrichment.__func__
            observed["path"] = current.path

        handler._delegate_log(delegated)

        self.assertIs(observed["analysis"], log_server.RequestHandler._run_analysis)
        self.assertIs(observed["enrichment"], log_server.RequestHandler._run_enrichment)
        self.assertEqual(observed["path"], "/api/analyze")
        self.assertEqual(handler.path, "/api/logscope/analyze")

    def test_flowscope_delegate_binds_flowscope_background_workers(self):
        handler = self._handler("/api/flowscope/analyze")
        observed = {}

        def delegated(current):
            observed["analysis"] = current._run_analysis.__func__
            observed["enrichment"] = current._run_enrichment.__func__

        handler._delegate_flow(delegated)

        self.assertIs(observed["analysis"], flow_server.RequestHandler._run_analysis)
        self.assertIs(observed["enrichment"], flow_server.RequestHandler._run_enrichment)

    def test_logscope_entity_profile_attaches_enrichment(self):
        import tempfile
        import json
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp_dir:
            job_file = Path(tmp_dir) / "analysis.json"
            job_file.write_text(json.dumps({
                "result_storage": {"type": "memory"},
                "enrichment": {
                    "results": {
                        "198.51.100.42": {
                            "virustotal": {"malicious": 14, "verdict": "malicious"},
                            "abuseipdb": {"score": 98, "total_reports": 120}
                        }
                    }
                }
            }, ensure_ascii=False), encoding="utf-8")

            class DummyHandler:
                def __init__(self):
                    self.sent_data = None
                    self.sent_status = None

            handler = DummyHandler()
            from logscope import server as ls_server
            import unittest.mock as mock

            with mock.patch("logscope.server._safe_json_response") as mock_resp:
                ls_server.RequestHandler._handle_get_entity(handler, "dummy_id", job_file, "ip/198.51.100.42")
                self.assertTrue(mock_resp.called)
                profile = mock_resp.call_args[0][1]
                self.assertIn("enrichment", profile)
                self.assertEqual(profile["enrichment"]["virustotal"]["malicious"], 14)
                self.assertEqual(profile["enrichment"]["abuseipdb"]["score"], 98)

    def test_records_routes_permitted_and_matched_across_all_apps(self):
        handler = self._handler("/api")
        apps = [
            ("flowscope", "flowscope.view", handler._flow_route),
            ("threatscope", "threatscope.view", handler._threat_route),
            ("logscope", "logscope.view", handler._log_route),
        ]
        dummy_job = "a" * 32
        for app_name, expected_perm, route_matcher in apps:
            path = f"/api/{app_name}/jobs/{dummy_job}/records"
            perm = handler._route_permission("GET", path)
            self.assertEqual(perm, expected_perm, f"Failed permission for {path}")
            self.assertTrue(route_matcher("GET", path), f"Failed route match for {path}")


if __name__ == "__main__":
    unittest.main()
