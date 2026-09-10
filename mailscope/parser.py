"""MailScope — RFC 822 / MIME Email Parser & Forensics Extractor.

Parses raw .eml files and string contents, extracting detailed headers,
routing hop paths, SPF/DKIM/DMARC authentication results, attachments with
cryptographic hashes, and embedded URLs with display-vs-href mismatch detection.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import html
import math
import re
from datetime import datetime, timezone
from email.header import decode_header
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from mailscope.models import (
    AuthStatus,
    EmailAttachment,
    EmailAuthResults,
    EmailHop,
    EmailURL,
    ParsedEmail,
)

# Known dangerous file extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd",
    ".ps1", ".psm1", ".iso", ".img", ".hta", ".cpl", ".msc", ".jar",
    ".wsf", ".wsh", ".pif", ".lnk", ".reg", ".dll", ".sys",
}

# Macro-enabled Office extensions
MACRO_EXTENSIONS = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
}

# Archive extensions
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace",
}

# URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "soo.gd", "goo.gl",
}

# Suspicious credential / phishing keywords in URL
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "auth", "authorize", "authenticate",
    "verify", "verification", "secure-account", "update-payment", "password",
    "credential", "session-expired", "account-suspended", "banking", "mada",
    "knet", "tax-refund", "portal-login", "office365", "webmail-update",
]


def _decode_str(val: Optional[str]) -> str:
    """Safely decodes RFC 2047 encoded header strings."""
    if not val:
        return ""
    try:
        decoded_fragments = decode_header(val)
        result = []
        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                enc = encoding or "utf-8"
                try:
                    result.append(fragment.decode(enc, errors="replace"))
                except Exception:
                    result.append(fragment.decode("latin-1", errors="replace"))
            else:
                result.append(str(fragment))
        return " ".join(result).strip()
    except Exception:
        return str(val).strip()


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of binary payload."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    for count in counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class MailParser:
    """Comprehensive RFC 822 / MIME email parser."""

    @classmethod
    def parse(cls, raw_content: str | bytes) -> ParsedEmail:
        """Parses raw email text or bytes into a structured ParsedEmail object."""
        if isinstance(raw_content, str):
            msg = email.message_from_string(raw_content, policy=email.policy.default)
        else:
            msg = email.message_from_bytes(raw_content, policy=email.policy.default)

        parsed = ParsedEmail()

        # Extract basic headers
        parsed.message_id = _decode_str(msg.get("Message-ID", ""))
        parsed.subject = _decode_str(msg.get("Subject", ""))

        from_header = _decode_str(msg.get("From", ""))
        name, address = email.utils.parseaddr(from_header)
        parsed.sender_name = name or ""
        parsed.sender_address = address or ""
        if "@" in parsed.sender_address:
            parsed.sender_domain = parsed.sender_address.split("@")[-1].lower()

        parsed.reply_to = _decode_str(msg.get("Reply-To", ""))
        parsed.return_path = _decode_str(msg.get("Return-Path", ""))
        parsed.date = _decode_str(msg.get("Date", ""))

        # Recipients
        for hdr, target_list in [
            ("To", parsed.to),
            ("Cc", parsed.cc),
            ("Bcc", parsed.bcc),
        ]:
            val = msg.get(hdr)
            if val:
                addresses = email.utils.getaddresses([_decode_str(val)])
                for _, addr in addresses:
                    if addr:
                        target_list.append(addr)

        # Raw headers mapping
        for k, v in msg.items():
            parsed.headers[k] = _decode_str(v)

        # Parse Hops
        parsed.hops = cls._parse_received_hops(msg)

        # Parse Authentication Results
        parsed.auth_results = cls._parse_auth_results(msg)

        # Extract Body and Attachments
        body_text_parts: List[str] = []
        body_html_parts: List[str] = []
        attachments: List[EmailAttachment] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", "")).lower()
                filename = part.get_filename()

                if filename or "attachment" in disposition:
                    att = cls._process_attachment(part, filename)
                    if att:
                        attachments.append(att)
                elif content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            body_text_parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            body_html_parts.append(payload.decode(charset, errors="replace"))
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    decoded_text = payload.decode(charset, errors="replace")
                    if content_type == "text/html":
                        body_html_parts.append(decoded_text)
                    else:
                        body_text_parts.append(decoded_text)
            except Exception:
                pass

        parsed.body_text = "\n".join(body_text_parts).strip()
        parsed.body_html = "\n".join(body_html_parts).strip()
        parsed.attachments = attachments

        # Extract & inspect URLs from body
        parsed.urls = cls._extract_urls(parsed.body_text, parsed.body_html)

        return parsed

    @classmethod
    def _parse_received_hops(cls, msg: email.message.EmailMessage) -> List[EmailHop]:
        """Extracts and orders routing hops from Received headers."""
        received_headers = msg.get_all("Received", [])
        hops: List[EmailHop] = []
        if not received_headers:
            return hops

        # Received headers are prepended by each hop, so reverse for chronological order
        hop_num = 1
        for raw_hop in reversed(received_headers):
            hop_str = " ".join(str(raw_hop).split())
            hop = EmailHop(hop_number=hop_num)

            # Extract from host
            from_m = re.search(r"from\s+([^\s;]+)", hop_str, re.IGNORECASE)
            if from_m:
                hop.from_host = from_m.group(1).strip("()[]")

            # Extract by host
            by_m = re.search(r"by\s+([^\s;]+)", hop_str, re.IGNORECASE)
            if by_m:
                hop.by_host = by_m.group(1).strip("()[]")

            # Extract protocol
            with_m = re.search(r"with\s+([^\s;]+)", hop_str, re.IGNORECASE)
            if with_m:
                hop.with_protocol = with_m.group(1)

            # Extract IP address
            ip_m = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", hop_str)
            if ip_m:
                hop.source_ip = ip_m.group(1)

            # Extract timestamp
            if ";" in hop_str:
                hop.timestamp = hop_str.split(";")[-1].strip()

            hops.append(hop)
            hop_num += 1

        return hops

    @classmethod
    def _parse_auth_results(cls, msg: email.message.EmailMessage) -> EmailAuthResults:
        """Parses Authentication-Results and Received-SPF headers."""
        results = EmailAuthResults()

        auth_hdr = msg.get("Authentication-Results", "")
        spf_hdr = msg.get("Received-SPF", "")
        results.raw_header = f"Authentication-Results: {auth_hdr}\nReceived-SPF: {spf_hdr}".strip()

        combined = f"{auth_hdr} {spf_hdr}".lower()

        # Parse SPF
        if "spf=pass" in combined or "spf: pass" in combined:
            results.spf_status = AuthStatus.PASS
        elif "spf=fail" in combined or "spf: fail" in combined:
            results.spf_status = AuthStatus.FAIL
        elif "spf=softfail" in combined:
            results.spf_status = AuthStatus.SOFTFAIL
        elif "spf=neutral" in combined:
            results.spf_status = AuthStatus.NEUTRAL
        elif "spf=permerror" in combined:
            results.spf_status = AuthStatus.PERMERROR
        elif "spf=temperror" in combined:
            results.spf_status = AuthStatus.TEMPERROR

        # Extract SPF sender domain/IP
        spf_sender_m = re.search(r"envelope-from=([^\s;]+)", combined)
        if spf_sender_m:
            results.spf_sender = spf_sender_m.group(1).strip("<>")

        spf_ip_m = re.search(r"client-ip=([0-9\.]+)", combined)
        if spf_ip_m:
            results.spf_ip = spf_ip_m.group(1)

        # Parse DKIM
        if "dkim=pass" in combined or "dkim: pass" in combined:
            results.dkim_status = AuthStatus.PASS
        elif "dkim=fail" in combined or "dkim: fail" in combined:
            results.dkim_status = AuthStatus.FAIL
        elif "dkim=neutral" in combined:
            results.dkim_status = AuthStatus.NEUTRAL
        elif "dkim=permerror" in combined:
            results.dkim_status = AuthStatus.PERMERROR

        dkim_dom_m = re.search(r"header\.d=([^\s;]+)", combined)
        if dkim_dom_m:
            results.dkim_domain = dkim_dom_m.group(1)

        # Parse DMARC
        if "dmarc=pass" in combined or "dmarc: pass" in combined:
            results.dmarc_status = AuthStatus.PASS
        elif "dmarc=fail" in combined or "dmarc: fail" in combined:
            results.dmarc_status = AuthStatus.FAIL

        dmarc_pol_m = re.search(r"action=([^\s;]+)", combined) or re.search(r"policy=([^\s;]+)", combined)
        if dmarc_pol_m:
            results.dmarc_policy = dmarc_pol_m.group(1)

        return results

    @classmethod
    def _process_attachment(
        cls, part: email.message.EmailMessage, raw_filename: Optional[str]
    ) -> Optional[EmailAttachment]:
        """Extracts attachment payload, hashes, and forensic indicators."""
        filename = _decode_str(raw_filename or "unnamed_attachment")
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""

        size = len(payload)
        md5 = hashlib.md5(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        entropy = calculate_entropy(payload)

        fn_lower = filename.lower()
        findings: List[str] = []

        # Check dangerous extension
        is_dangerous = False
        for ext in DANGEROUS_EXTENSIONS:
            if fn_lower.endswith(ext):
                is_dangerous = True
                findings.append(f"Dangerous executable/script file extension detected: {ext}")
                break

        # Check macro extension
        has_macros = False
        for ext in MACRO_EXTENSIONS:
            if fn_lower.endswith(ext):
                has_macros = True
                findings.append(f"Macro-enabled Office document detected: {ext}")
                break

        # Check archive extension
        is_archive = any(fn_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)

        # Check double extension trick (e.g., document.pdf.exe)
        is_double = False
        parts = fn_lower.split(".")
        if len(parts) > 2:
            second_last = f".{parts[-2]}"
            last = f".{parts[-1]}"
            if last in DANGEROUS_EXTENSIONS and second_last in {".pdf", ".doc", ".docx", ".jpg", ".png", ".txt"}:
                is_double = True
                findings.append(f"Double extension spoofing detected: {second_last}{last}")

        # High entropy flag
        if entropy > 7.2 and not is_archive:
            findings.append(f"Abnormally high entropy ({entropy:.2f}) indicates encrypted or packed malicious payload")

        return EmailAttachment(
            filename=filename,
            content_type=content_type,
            size_bytes=size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            is_dangerous_type=is_dangerous or is_double,
            has_macros=has_macros,
            is_archive=is_archive,
            is_double_extension=is_double,
            entropy=entropy,
            threat_score=85 if (is_dangerous or is_double) else (60 if has_macros else 0),
            findings=findings,
        )

    @classmethod
    def _extract_urls(cls, body_text: str, body_html: str) -> List[EmailURL]:
        """Extracts and analyzes all URLs from HTML links and plain text."""
        extracted: Dict[str, EmailURL] = {}

        # 1. Parse HTML links (checking display text vs actual href)
        if body_html:
            # Regex for <a href="...">display_text</a>
            a_tags = re.findall(
                r'<a\s+(?:[^>]*?\s+)?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                body_html,
                re.IGNORECASE | re.DOTALL,
            )
            for href, text_content in a_tags:
                clean_href = href.strip()
                if clean_href.startswith(("http://", "https://", "ftp://")):
                    clean_text = re.sub(r"<[^>]+>", "", text_content).strip()
                    clean_text = html.unescape(clean_text)
                    email_url = cls._analyze_url(clean_href, clean_text)
                    extracted[clean_href] = email_url

        # 2. Extract plain text URLs with Regex
        url_regex = r'https?://[^\s<>"\')]+'
        all_text = f"{body_text} {body_html}"
        for match in re.findall(url_regex, all_text):
            clean = match.strip(".,;()[]\"'")
            if clean and clean not in extracted:
                extracted[clean] = cls._analyze_url(clean, "")

        return list(extracted.values())

    @classmethod
    def _analyze_url(cls, url: str, display_text: str) -> EmailURL:
        """Inspects URL structure, domains, punycode, keywords, and mismatches."""
        parsed = urlparse(url)
        domain = (parsed.netloc or "").lower().split(":")[0]

        is_mismatched = False
        is_shortened = domain in SHORTENER_DOMAINS
        is_punycode = "xn--" in domain
        is_ip_based = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain))
        has_keywords = False
        threat_flags: List[str] = []
        rep_score = 0

        # Check Display Text vs Target URL mismatch (e.g. text says microsoft.com but href is evil.com)
        if display_text:
            dt_clean = display_text.lower().strip()
            if dt_clean.startswith(("http://", "https://", "www.")):
                dt_parsed = urlparse(dt_clean if dt_clean.startswith("http") else f"http://{dt_clean}")
                dt_domain = (dt_parsed.netloc or "").lower().split(":")[0]
                if dt_domain and dt_domain != domain and not domain.endswith(f".{dt_domain}"):
                    is_mismatched = True
                    threat_flags.append(f"Deceptive link: Display text points to '{dt_domain}' but actual target is '{domain}'")
                    rep_score += 45

        # Check IP-based URL
        if is_ip_based:
            threat_flags.append(f"Direct IP-based URL detected ({domain}) bypassing DNS reputation")
            rep_score += 35

        # Check Punycode / IDN Homoglyph
        if is_punycode:
            threat_flags.append(f"Punycode / IDN Homoglyph spoofing domain detected: {domain}")
            rep_score += 40

        # Check Shortener
        if is_shortened:
            threat_flags.append(f"URL Shortener service used to mask destination: {domain}")
            rep_score += 25

        # Check Credential / Phishing Keywords in path & query
        url_lower = url.lower()
        matched_kws = [kw for kw in CREDENTIAL_KEYWORDS if kw in url_lower]
        if matched_kws:
            has_keywords = True
            threat_flags.append(f"Suspicious credential/phishing keywords found: {', '.join(matched_kws[:3])}")
            rep_score += 30

        category = "phishing" if rep_score >= 50 else ("suspicious" if rep_score > 0 else "clean")

        return EmailURL(
            url=url,
            display_text=display_text,
            domain=domain,
            is_mismatched=is_mismatched,
            is_shortened=is_shortened,
            is_punycode=is_punycode,
            is_ip_based=is_ip_based,
            has_credential_keywords=has_keywords,
            reputation_score=min(100, rep_score),
            category=category,
            threat_flags=threat_flags,
        )
