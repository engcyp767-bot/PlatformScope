"""MailScope — SQLite Persistence Store & Quarantine Manager.

Provides thread-safe storage for analyzed email reports, quarantine state,
historical metrics, search/filtering, and automatic incident escalation.
"""

from __future__ import annotations

import contextlib
import json
import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from mailscope.models import (
    AuthStatus,
    EmailAnalysisReport,
    EmailFinding,
    EmailURL,
    EmailVerdict,
    ParsedEmail,
    Severity,
)

logger = logging.getLogger("platform.mailscope.store")


class MailStore:
    """Thread-safe SQLite store for MailScope analysis reports and quarantine records."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        if db_path is None:
            data_dir = Path("data")
            data_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = data_dir / "mailscope.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _db_session(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing a managed connection that is always closed."""
        conn = sqlite3.connect(str(self.db_path), timeout=20.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._lock, self._db_session() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS email_reports (
                    id TEXT PRIMARY KEY,
                    analyzed_at TEXT NOT NULL,
                    message_id TEXT,
                    subject TEXT,
                    sender_name TEXT,
                    sender_address TEXT,
                    sender_domain TEXT,
                    recipients TEXT,
                    verdict TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    is_quarantined INTEGER DEFAULT 0,
                    incident_id TEXT,
                    digital_signature TEXT,
                    raw_report_json TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mail_analyzed_at ON email_reports(analyzed_at);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mail_verdict ON email_reports(verdict);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mail_sender ON email_reports(sender_address);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_mail_sender_domain ON email_reports(sender_domain);
            """)

    def save_report(self, report: EmailAnalysisReport) -> None:
        """Saves or updates an email analysis report."""
        with self._lock, self._db_session() as conn:
            recipients = json.dumps(report.parsed_email.to)
            raw_json = json.dumps(report.to_dict())
            is_quar = 1 if "QUARANTINE_EMAIL" in report.recommended_actions else 0

            conn.execute("""
                INSERT OR REPLACE INTO email_reports (
                    id, analyzed_at, message_id, subject, sender_name, sender_address,
                    sender_domain, recipients, verdict, overall_score, risk_level,
                    is_quarantined, incident_id, digital_signature, raw_report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.id,
                report.analyzed_at,
                report.parsed_email.message_id,
                report.parsed_email.subject,
                report.parsed_email.sender_name,
                report.parsed_email.sender_address,
                report.parsed_email.sender_domain,
                recipients,
                report.verdict.value,
                report.overall_score,
                report.risk_level.value,
                is_quar,
                report.incident_id,
                report.digital_signature,
                raw_json,
            ))

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves complete report dictionary by ID."""
        with self._lock, self._db_session() as conn:
            row = conn.execute(
                "SELECT raw_report_json, is_quarantined, incident_id FROM email_reports WHERE id = ?",
                (report_id,)
            ).fetchone()
            if not row:
                return None
            data = json.loads(row["raw_report_json"])
            data["is_quarantined"] = bool(row["is_quarantined"])
            data["incident_id"] = row["incident_id"]
            return data

    def list_reports(
        self,
        verdict: Optional[str] = None,
        search: Optional[str] = None,
        quarantined_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Lists historical analyzed emails with filtering and pagination."""
        query = "SELECT id, analyzed_at, subject, sender_name, sender_address, sender_domain, verdict, overall_score, risk_level, is_quarantined, incident_id FROM email_reports WHERE 1=1"
        params: List[Any] = []

        if verdict:
            query += " AND verdict = ?"
            params.append(verdict.lower())

        if quarantined_only:
            query += " AND is_quarantined = 1"

        if search:
            query += " AND (subject LIKE ? OR sender_address LIKE ? OR sender_name LIKE ?)"
            s_term = f"%{search}%"
            params.extend([s_term, s_term, s_term])

        query += " ORDER BY analyzed_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock, self._db_session() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def set_quarantine(self, report_id: str, quarantined: bool = True) -> bool:
        """Sets the quarantine flag for an email record."""
        with self._lock, self._db_session() as conn:
            cur = conn.execute(
                "UPDATE email_reports SET is_quarantined = ? WHERE id = ?",
                (1 if quarantined else 0, report_id)
            )
            return cur.rowcount > 0

    def link_incident(self, report_id: str, incident_id: str) -> bool:
        """Links an escalated security incident ID to the email report."""
        with self._lock, self._db_session() as conn:
            cur = conn.execute(
                "UPDATE email_reports SET incident_id = ? WHERE id = ?",
                (incident_id, report_id)
            )
            return cur.rowcount > 0

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Aggregates email forensics dashboard metrics."""
        with self._lock, self._db_session() as conn:
            total = conn.execute("SELECT COUNT(*) FROM email_reports").fetchone()[0]
            phishing = conn.execute("SELECT COUNT(*) FROM email_reports WHERE verdict = 'phishing'").fetchone()[0]
            bec = conn.execute("SELECT COUNT(*) FROM email_reports WHERE verdict = 'bec_fraud'").fetchone()[0]
            malicious = conn.execute("SELECT COUNT(*) FROM email_reports WHERE verdict = 'malicious'").fetchone()[0]
            suspicious = conn.execute("SELECT COUNT(*) FROM email_reports WHERE verdict = 'suspicious'").fetchone()[0]
            clean = conn.execute("SELECT COUNT(*) FROM email_reports WHERE verdict = 'clean'").fetchone()[0]
            quarantined = conn.execute("SELECT COUNT(*) FROM email_reports WHERE is_quarantined = 1").fetchone()[0]

            top_senders = conn.execute("""
                SELECT sender_domain, COUNT(*) as count 
                FROM email_reports 
                WHERE sender_domain != '' AND verdict IN ('phishing', 'bec_fraud', 'malicious')
                GROUP BY sender_domain 
                ORDER BY count DESC 
                LIMIT 5
            """).fetchall()

            clean_rate = round((clean / total * 100), 1) if total > 0 else 100.0

            return {
                "total_analyzed": total,
                "phishing_count": phishing,
                "bec_count": bec,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "clean_count": clean,
                "quarantined_count": quarantined,
                "clean_rate_percent": clean_rate,
                "top_threat_domains": [dict(r) for r in top_senders],
            }
