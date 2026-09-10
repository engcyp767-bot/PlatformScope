"""MailScope — Email Security Forensics, Phishing & BEC Defense Engine.

Commercial enterprise module for RFC 822 / MIME deep forensic inspection,
SPF/DKIM/DMARC authentication validation, BEC VIP impersonation detection,
malicious attachment triage, phishing link analysis, and SOC playbooks.
"""

from mailscope.analyzer import MailAnalyzer
from mailscope.models import (
    AuthStatus,
    EmailAnalysisReport,
    EmailAttachment,
    EmailAuthResults,
    EmailFinding,
    EmailHop,
    EmailURL,
    EmailVerdict,
    ParsedEmail,
    Severity,
)
from mailscope.parser import MailParser
from mailscope.store import MailStore

_default_store: MailStore | None = None
_default_analyzer: MailAnalyzer | None = None


def get_mail_store() -> MailStore:
    """Returns singleton MailStore instance."""
    global _default_store
    if _default_store is None:
        _default_store = MailStore()
    return _default_store


def get_mail_analyzer() -> MailAnalyzer:
    """Returns singleton MailAnalyzer instance."""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = MailAnalyzer()
    return _default_analyzer


__all__ = [
    "MailAnalyzer",
    "MailParser",
    "MailStore",
    "get_mail_store",
    "get_mail_analyzer",
    "EmailVerdict",
    "Severity",
    "AuthStatus",
    "EmailHop",
    "EmailAuthResults",
    "EmailAttachment",
    "EmailURL",
    "EmailFinding",
    "ParsedEmail",
    "EmailAnalysisReport",
]

