from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from platform_core import report_preview


class ReportPreviewTests(unittest.TestCase):
    def test_logscope_uses_the_shared_preview_cache(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            artifact, _ = report_preview.docx_artifact(
                "logscope", "9" * 32, {"total_records": 1}, lambda: b"PK-logscope"
            )
            self.assertEqual(artifact.read_bytes(), b"PK-logscope")

    def test_docx_artifact_is_built_once_for_same_analysis(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            calls = []

            def builder():
                calls.append(True)
                return b"PK-valid-docx"

            first, first_hash = report_preview.docx_artifact("flowscope", "a" * 32, {"summary": {"records": 2}}, builder)
            second, second_hash = report_preview.docx_artifact("flowscope", "a" * 32, {"summary": {"records": 2}}, builder)
            self.assertEqual(first, second)
            self.assertEqual(first_hash, second_hash)
            self.assertEqual(first.read_bytes(), b"PK-valid-docx")
            self.assertEqual(len(calls), 1)

    def test_changed_analysis_replaces_stale_artifact(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            old, _ = report_preview.docx_artifact("threatscope", "b" * 32, {"value": 1}, lambda: b"PK-old")
            new, _ = report_preview.docx_artifact("threatscope", "b" * 32, {"value": 2}, lambda: b"PK-new")
            self.assertFalse(old.exists())
            self.assertTrue(new.exists())

    def test_snapshot_freezes_exact_word_artifact_when_analysis_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            snapshot = "1234567890abcdef"
            first, _ = report_preview.docx_artifact("flowscope", "c" * 32, {"value": 1}, lambda: b"PK-first", snapshot=snapshot)
            second, _ = report_preview.docx_artifact("flowscope", "c" * 32, {"value": 2}, lambda: b"PK-second", snapshot=snapshot)
            self.assertEqual(first, second)
            self.assertEqual(second.read_bytes(), b"PK-first")

    def test_pdf_preview_prefers_microsoft_word(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            def word_converter(_document, preview):
                preview.write_bytes(b"%PDF-word")
                return True, ""

            with patch.object(report_preview, "_convert_with_word", side_effect=word_converter) as word, \
                    patch.object(report_preview, "_convert_with_libreoffice") as libreoffice:
                pdf, docx = report_preview.pdf_artifact("threatscope", "d" * 32, {"value": 1}, lambda: b"PK-docx")

            self.assertEqual(pdf, b"%PDF-word")
            self.assertEqual(docx, b"PK-docx")
            word.assert_called_once()
            libreoffice.assert_not_called()
            marker = next(Path(directory).rglob("*.engine"))
            self.assertEqual(marker.read_text(encoding="ascii"), "microsoft-word")

    def test_pdf_preview_falls_back_to_libreoffice(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(report_preview, "CACHE_ROOT", Path(directory)):
            def libreoffice_converter(_document, preview):
                preview.write_bytes(b"%PDF-libreoffice")

            with patch.object(report_preview, "_convert_with_word", return_value=(False, "no desktop session")) as word, \
                    patch.object(report_preview, "_convert_with_libreoffice", side_effect=libreoffice_converter) as libreoffice:
                pdf, _ = report_preview.pdf_artifact("flowscope", "e" * 32, {"value": 1}, lambda: b"PK-docx")

            self.assertEqual(pdf, b"%PDF-libreoffice")
            word.assert_called_once()
            libreoffice.assert_called_once()
            marker = next(Path(directory).rglob("*.engine"))
            self.assertEqual(marker.read_text(encoding="ascii"), "libreoffice")


if __name__ == "__main__":
    unittest.main()
