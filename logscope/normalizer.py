"""Field Normalizer Pipeline: Converts raw tabular records into typed CanonicalEvents."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from logscope.canonical import ActionDisposition, CanonicalEvent

# Precompiled Fast Regexes
_IPV4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
_SYSLOG_KV_RE = re.compile(r'([a-zA-Z0-9_\-]+)=(?:\"([^\"]*)\"|\'([^\']*)\'|([^\s,;()]+))')
_PORT_SERVICE_MAP = {
    "53": "DNS", "80": "HTTP", "443": "HTTPS", "22": "SSH", "21": "FTP",
    "23": "Telnet", "25": "SMTP", "110": "POP3", "143": "IMAP", "389": "LDAP",
    "636": "LDAPS", "3389": "RDP", "445": "SMB", "139": "NetBIOS", "137": "NetBIOS-NS",
    "88": "Kerberos", "1433": "MSSQL", "1521": "Oracle", "3306": "MySQL", "5432": "PostgreSQL",
    "8080": "HTTP-Proxy", "8443": "HTTPS-Alt", "123": "NTP", "161": "SNMP",
}


def _normalise_header(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text).lower()
    text = re.sub(r"[\s_./\\:()\[\]-]+", " ", text)
    return " ".join(text.split())


def _is_ip(val: str) -> bool:
    if not val or len(val) > 45 or ("." not in val and ":" not in val):
        return False
    val = val.strip().strip("[]()")
    if val in {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"}:
        return True
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        if ":" in val and "." in val:
            try:
                ipaddress.ip_address(val.split(":", 1)[0])
                return True
            except ValueError:
                pass
    return False


def _extract_ips(text: str) -> list[str]:
    if not text or ("." not in text and ":" not in text):
        return []
    candidates = _IPV4_RE.findall(text)
    valid_ips: list[str] = []
    for c in candidates:
        if _is_ip(c) and c not in valid_ips:
            valid_ips.append(c)
    if ":" in text:
        for token in text.split():
            candidate = token.strip(" ,;|()[]{}<>\"'").rsplit("=", 1)[-1]
            if ":" in candidate and "." not in candidate:
                if _is_ip(candidate) and candidate not in valid_ips:
                    valid_ips.append(candidate)
    return valid_ips


def _parse_syslog_key_values(text: str) -> dict[str, str]:
    if not text or "=" not in text:
        return {}
    attrs: dict[str, str] = {}
    for m in _SYSLOG_KV_RE.finditer(text):
        k = m.group(1).strip()
        v = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else m.group(4))
        if k and v is not None:
            attrs[k] = v.strip()
    return attrs


def _parse_stream_ips(raw_text: str) -> tuple[str, str, list[str], int | None, int | None]:
    if not raw_text or "->" not in raw_text:
        return "", "", [], None, None
    all_ips: list[str] = []
    primary_src, primary_dst = "", ""
    src_port, dst_port = None, None
    for pair in raw_text.split(";"):
        pair = pair.strip()
        if "->" in pair:
            parts = pair.split("->", 1)
            s_raw = parts[0].strip()
            d_raw = parts[1].replace(", begin", "").strip()

            s_ip = s_raw.split(":")[0].strip()
            if ":" in s_raw and not _is_ip(s_raw):
                cp = s_raw.split(":", 1)[1].strip()
                if cp.isdigit() and 1 <= int(cp) <= 65535:
                    src_port = int(cp)

            d_ip = d_raw.split(":")[0].strip()
            if ":" in d_raw and not _is_ip(d_raw):
                cp = d_raw.split(":", 1)[1].strip()
                if cp.isdigit() and 1 <= int(cp) <= 65535:
                    dst_port = int(cp)

            if _is_ip(s_ip):
                if not primary_src:
                    primary_src = s_ip
                if s_ip not in all_ips:
                    all_ips.append(s_ip)
            if _is_ip(d_ip):
                if not primary_dst:
                    primary_dst = d_ip
                if d_ip not in all_ips:
                    all_ips.append(d_ip)
    return primary_src, primary_dst, all_ips, src_port, dst_port


# Canonical Field Aliases Mapping
CANONICAL_FIELD_ALIASES: dict[str, set[str]] = {
    "source_ip": {
        "source host ip", "source ip", "src ip", "host", "client ip", "عنوان المصدر",
        "source network address", "ip address", "remote ip", "origin ip", "source address",
        "src addr", "srcip", "source", "src", "client address", "source host", "initiator ip",
        "clientip", "c-ip", "client_ip", "remote_addr", "remote_ip", "caller_ip",
        "source_ip", "src_host", "src_address", "client_address", "cip", "srcip_address",
        "اي بي المصدر", "عنوان العميل",
    },
    "destination_ip": {
        "destination host ip", "destination ip", "dst ip", "destination", "server ip",
        "target ip", "عنوان الوجهة", "dest ip", "dest address", "dst addr", "dstip", "dst",
        "dest", "target", "target address", "target host", "responder ip", "serverip",
        "s-ip", "server_ip", "dst_ip", "dst_host", "dst_address", "dest_address",
        "dip", "dstip_address", "اي بي الوجهة", "عنوان الخادم",
    },
    "source_port": {
        "source port", "src port", "sport", "منفذ المصدر", "client port", "src_port",
        "source_port", "c-port", "client_port", "initiator port", "srcport",
    },
    "destination_port": {
        "destination port", "dst port", "dport", "منفذ الوجهة", "server port", "dest port",
        "dst_port", "dest_port", "s-port", "server_port", "responder port", "dstport", "target port",
    },
    "protocol": {
        "protocol", "transmission protocol", "proto", "البروتوكول", "network protocol",
        "ip protocol", "transport", "transport protocol", "ip_proto",
    },
    "username": {
        "user", "user account", "account", "username", "user name", "المستخدم",
        "target user name", "subject user name", "actor", "owner", "initiated by",
        "src user", "dst user", "source user", "destination user", "operator", "login name",
        "userprincipalname", "targetusername", "subjectusername", "account_name",
        "samaccountname", "userid", "user_id", "caller", "email", "identity",
        "account_id", "اسم الحساب", "اسم المستخدم",
    },
    "hostname": {
        "computer", "computer name", "host name", "hostname", "workstation", "server",
        "machinename", "machine name", "computername", "host_name", "machine_name",
        "computer_name", "اسم الجهاز", "الخادم", "المحطة",
    },
    "device": {
        "device", "device name", "dev name", "firewall", "sensor", "node", "appliance",
        "devicename", "endpoint", "agent_id", "dev ip", "الجهاز", "اسم جدار الحماية",
    },
    "event_id": {
        "event id", "eventid", "event code", "eventcode", "id", "معرف الحدث", "رقم الحدث",
        "signature id", "signid", "sign id", "rule id", "threat id", "attack id",
        "cve", "cve id", "cveid", "alarm id", "alert id", "incident id",
    },
    "action": {
        "action", "disposition", "status", "action taken", "event action", "activity",
        "operation", "command", "firewall action", "audit action", "الإجراء", "العملية",
    },
    "status": {
        "status", "state", "result", "outcome", "compliance status", "device status",
        "connection status", "logon status", "substatus", "sub_status", "الحالة", "النتيجة",
    },
    "priority": {
        "priority", "severity", "level", "log level", "event priority", "event severity",
        "risk level", "threat level", "الخطورة", "الأولوية", "المستوى",
    },
    "message": {
        "message description", "message", "description", "details", "الوصف", "event message",
        "displayname", "display name", "event name", "alert name", "incident name", "rule name",
        "signature name", "attack name", "threat name", "reason", "event description",
        "log text", "raw log", "msg", "log_message", "statement", "command", "query", "url",
        "uri", "cs-uri-stem", "request_url", "threat_name", "event_summary", "payload",
        "cmdline", "commandline", "process_command_line", "نص الرسالة", "تفاصيل الحدث", "الأمر البرمجي",
    },
    "event_time": {
        "event time", "time", "date", "timestamp", "log time", "generation time", "تاريخ الحدث",
        "created time", "datetime", "date time", "start time", "start_time", "end time",
        "end_time", "receive time", "occur time", "الوقت", "التاريخ", "توقيت الحدث",
    },
    "category": {
        "category", "event category", "attack category", "threat category", "classification",
        "alert type", "incident type", "التصنيف", "فئة التهديد", "نوع الحدث",
    },
    "log_source": {
        "source zone", "event source", "log source", "source type", "source system",
        "facility", "service", "system", "component", "مصدر السجل", "النظام المصدر",
    },
}

PRIORITY_COLUMN_MATCHES: dict[str, list[str]] = {
    "message": ["message", "description", "details", "event message", "event description", "msg", "log message", "الوصف", "نص الرسالة", "تفاصيل الحدث"],
    "action": ["action", "action taken", "operation", "activity", "command", "firewall action", "disposition", "الإجراء"],
    "source_ip": ["source ip", "src ip", "client ip", "source address", "src", "عنوان المصدر"],
    "destination_ip": ["destination ip", "dst ip", "server ip", "dest ip", "destination address", "dst", "عنوان الوجهة"],
    "event_id": ["event id", "eventid", "event code", "signature id", "معرف الحدث"],
}


class FieldNormalizer:
    """Performs schema mapping, field extraction, and typing into CanonicalEvent."""

    def __init__(self, headers: list[str]):
        self.headers = headers
        self.mapping: dict[str, int] = {}
        self._build_header_mapping()

    def _build_header_mapping(self) -> None:
        normalised_headers = [_normalise_header(h) for h in self.headers]

        for canonical_name, aliases in CANONICAL_FIELD_ALIASES.items():
            # Check priority list first
            priority_list = PRIORITY_COLUMN_MATCHES.get(canonical_name, [])
            matched_index = None
            for p in priority_list:
                clean_p = _normalise_header(p)
                if clean_p in normalised_headers:
                    matched_index = normalised_headers.index(clean_p)
                    break

            if matched_index is None:
                norm_aliases = {_normalise_header(a) for a in aliases}
                for idx, clean_h in enumerate(normalised_headers):
                    if clean_h in norm_aliases:
                        matched_index = idx
                        break

            if matched_index is not None:
                self.mapping[canonical_name] = matched_index

    def normalize_row(self, row: list[Any]) -> CanonicalEvent:
        raw_fields = {
            (str(header).strip() or f"Column {index + 1}"): str(row[index]).strip()
            for index, header in enumerate(self.headers)
            if index < len(row) and row[index] is not None and str(row[index]).strip()
        }

        def get_mapped(field: str) -> str:
            if field in self.mapping:
                idx = self.mapping[field]
                if idx < len(row) and row[idx] is not None:
                    return str(row[idx]).strip()
            return ""

        # 1. Message / Details & Embedded Key-Value Extraction
        message = get_mapped("message")
        if not message:
            for k in ("Message", "message", "Description", "details", "الوصف"):
                if k in raw_fields and raw_fields[k]:
                    message = raw_fields[k]
                    break
        syslog_attrs = _parse_syslog_key_values(message)

        # 2. Event ID
        event_id = get_mapped("event_id")
        if not event_id or event_id in {"-", "none", "NA", "N/A"}:
            event_id = syslog_attrs.get("SignId") or syslog_attrs.get("SyslogId") or syslog_attrs.get("EventNum") or ""

        # 3. Network IPs
        src_raw = get_mapped("source_ip") or syslog_attrs.get("SrcIp") or ""
        dst_raw = get_mapped("destination_ip") or syslog_attrs.get("DstIp") or ""
        stream_src, stream_dst, stream_ips, stream_sport, stream_dport = _parse_stream_ips(src_raw)

        source_ip = stream_src if stream_src else (src_raw if (src_raw and src_raw != "-") else "")
        destination_ip = stream_dst if stream_dst else (dst_raw if (dst_raw and dst_raw != "-") else "")

        # Fallback IP detection across raw fields if not mapped
        if not source_ip or not _is_ip(source_ip):
            for k, v in raw_fields.items():
                if any(w in _normalise_header(k) for w in ("src", "source", "client")) and _is_ip(v):
                    source_ip = v
                    break

        if not destination_ip or not _is_ip(destination_ip):
            for k, v in raw_fields.items():
                if any(w in _normalise_header(k) for w in ("dst", "dest", "target", "server")) and _is_ip(v):
                    destination_ip = v
                    break

        # 4. Ports & Protocol
        source_port = stream_sport
        destination_port = stream_dport

        raw_sport = get_mapped("source_port") or syslog_attrs.get("SrcPort") or ""
        if source_port is None and raw_sport.isdigit() and 1 <= int(raw_sport) <= 65535:
            source_port = int(raw_sport)

        raw_dport = get_mapped("destination_port") or syslog_attrs.get("DstPort") or ""
        if destination_port is None and raw_dport.isdigit() and 1 <= int(raw_dport) <= 65535:
            destination_port = int(raw_dport)

        protocol = (get_mapped("protocol") or syslog_attrs.get("Protocol") or "").upper()
        service_name = ""
        if destination_port and str(destination_port) in _PORT_SERVICE_MAP:
            service_name = _PORT_SERVICE_MAP[str(destination_port)]
        elif source_port and str(source_port) in _PORT_SERVICE_MAP:
            service_name = _PORT_SERVICE_MAP[str(source_port)]

        # 5. User, Device, Hostname
        user = get_mapped("username") or syslog_attrs.get("User") or ""
        if user.lower() in {"unknown", "none", "null", "undefined", "n/a", "-"}:
            user = ""

        device = get_mapped("device") or syslog_attrs.get("Device") or ""
        hostname = get_mapped("hostname") or syslog_attrs.get("Computer") or ""

        # 6. Action & Disposition
        action = get_mapped("action") or syslog_attrs.get("Action") or ""
        disposition = ActionDisposition.from_string(action)

        # 7. Timestamps
        event_time = get_mapped("event_time") or syslog_attrs.get("begin time") or ""

        # 8. Extracted IPs Pool
        extracted_ips = set()
        if source_ip and _is_ip(source_ip):
            extracted_ips.add(source_ip)
        if destination_ip and _is_ip(destination_ip):
            extracted_ips.add(destination_ip)
        for sip in stream_ips:
            extracted_ips.add(sip)
        if message and ("." in message or ":" in message):
            for ip in _extract_ips(message):
                extracted_ips.add(ip)

        return CanonicalEvent(
            event_time=event_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            service_name=service_name,
            username=user,
            hostname=hostname,
            device=device,
            event_id=event_id,
            action=action,
            action_disposition=disposition,
            status=get_mapped("status") or syslog_attrs.get("Status") or "",
            priority=get_mapped("priority") or syslog_attrs.get("Severity") or "Info",
            message=message,
            category=get_mapped("category") or syslog_attrs.get("Category") or "",
            log_source=get_mapped("log_source") or syslog_attrs.get("Profile") or "generic",
            raw_fields=raw_fields,
            extracted_ips=extracted_ips,
        )
