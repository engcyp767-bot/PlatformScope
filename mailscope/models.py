"""MailScope — Data Models for Email Forensics, Phishing & BEC Detection.

Defines all structures for email headers, hops, SPF/DKIM/DMARC auth results,
URL threat heuristics, attachment triage, BEC impersonation indicators,
verdicts, and forensic analysis reports.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EmailVerdict(str, Enum):
    """Overall verdict of email security analysis."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    MALICIOUS = "malicious"
    BEC_FRAUD = "bec_fraud"
    SPAM = "spam"


class Severity(str, Enum):
    """Severity levels for findings and risks."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuthStatus(str, Enum):
    """Email authentication check status (SPF / DKIM / DMARC)."""
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    PERMERROR = "permerror"
    TEMPERROR = "temperror"


@dataclass
class EmailHop:
    """Represents a single routing hop in the email's Received headers."""
    hop_number: int
    from_host: str = ""
    by_host: str = ""
    with_protocol: str = ""
    timestamp: str = ""
    delay_seconds: float = 0.0
    source_ip: str = ""


@dataclass
class EmailAuthResults:
    """Parsed email authentication results."""
    spf_status: AuthStatus = AuthStatus.NONE
    spf_sender: str = ""
    spf_ip: str = ""
    dkim_status: AuthStatus = AuthStatus.NONE
    dkim_domain: str = ""
    dmarc_status: AuthStatus = AuthStatus.NONE
    dmarc_policy: str = "none"  # none, quarantine, reject
    arc_status: AuthStatus = AuthStatus.NONE
    raw_header: str = ""

    def is_aligned(self) -> bool:
        """Returns True if both SPF and DKIM or DMARC passed."""
        return (
            (self.spf_status == AuthStatus.PASS or self.dkim_status == AuthStatus.PASS)
            and self.dmarc_status != AuthStatus.FAIL
        )


@dataclass
class EmailAttachment:
    """Metadata and forensic findings for an email attachment."""
    filename: str
    content_type: str
    size_bytes: int
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    is_dangerous_type: bool = False
    has_macros: bool = False
    is_archive: bool = False
    is_double_extension: bool = False
    entropy: float = 0.0
    threat_score: int = 0
    findings: List[str] = field(default_factory=list)


@dataclass
class EmailURL:
    """Parsed URL found within email body or headers with threat heuristics."""
    url: str
    display_text: str = ""
    domain: str = ""
    is_mismatched: bool = False
    is_shortened: bool = False
    is_punycode: bool = False
    is_ip_based: bool = False
    has_credential_keywords: bool = False
    reputation_score: int = 0  # 0 (safe) - 100 (malicious)
    category: str = "clean"
    threat_flags: List[str] = field(default_factory=list)


@dataclass
class EmailFinding:
    """Individual security finding identified during forensic analysis."""
    id: str
    category: str  # auth, phishing, attachment, bec, header, content
    severity: Severity
    title: str
    title_ar: str
    description: str
    description_ar: str
    mitre_technique: str = ""
    evidence: str = ""


@dataclass
class ParsedEmail:
    """Structured representation of a parsed RFC 822 email."""
    message_id: str = ""
    subject: str = ""
    sender_name: str = ""
    sender_address: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    date: str = ""
    body_text: str = ""
    body_html: str = ""
    hops: List[EmailHop] = field(default_factory=list)
    auth_results: EmailAuthResults = field(default_factory=EmailAuthResults)
    attachments: List[EmailAttachment] = field(default_factory=list)
    urls: List[EmailURL] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class EmailAnalysisReport:
    """Comprehensive forensic report for an analyzed email."""
    id: str
    analyzed_at: str
    verdict: EmailVerdict
    overall_score: int  # 0 (clean) to 100 (critical threat)
    risk_level: Severity
    parsed_email: ParsedEmail
    findings: List[EmailFinding] = field(default_factory=list)
    auth_summary: Dict[str, Any] = field(default_factory=dict)
    url_summary: Dict[str, Any] = field(default_factory=dict)
    attachment_summary: Dict[str, Any] = field(default_factory=dict)
    bec_summary: Dict[str, Any] = field(default_factory=dict)
    recommended_actions: List[str] = field(default_factory=list)
    remediation_playbook: List[Dict[str, Any]] = field(default_factory=list)
    digital_signature: str = ""
    incident_id: Optional[str] = None

    def compute_signature(self) -> str:
        """Computes a SHA-256 seal of the core forensic report data."""
        payload = f"{self.id}|{self.analyzed_at}|{self.verdict.value}|{self.overall_score}|{self.parsed_email.message_id}|{self.parsed_email.sender_address}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Converts report to dictionary representation."""
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["risk_level"] = self.risk_level.value
        return data
