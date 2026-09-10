"""Unit tests for the Advanced Graph Correlation Layer & Pattern Analyzers."""

import unittest
import time
from platform_core.graph_correlation import (
    SecurityGraph,
    GraphCorrelationEngine,
    NODE_USER,
    NODE_HOST,
    NODE_PROCESS,
    NODE_FILE,
    NODE_NETWORK,
    EDGE_LOGGED_INTO,
    EDGE_ESCALATED_PRIVILEGE,
    EDGE_SPAWNED_PROCESS,
    EDGE_DROPPED_FILE,
    EDGE_COMMUNICATED_WITH,
    EDGE_LATERAL_MOVED_TO
)


class GraphCorrelationTests(unittest.TestCase):
    def setUp(self):
        # Create fresh isolated graph and engine instances
        self.graph = SecurityGraph(max_nodes=50, max_edges=100, ttl_seconds=3600)
        self.engine = GraphCorrelationEngine(graph=self.graph)

    def test_security_graph_bounded_capacity_and_eviction(self):
        """Test that node and edge capacity limits evict oldest entries safely."""
        small_graph = SecurityGraph(max_nodes=5, max_edges=5, ttl_seconds=3600)
        
        # Add 6 nodes, 1st should be evicted
        for i in range(1, 7):
            small_graph.add_node(f"node:{i}", NODE_HOST, f"Host-{i}")

        self.assertEqual(len(small_graph._nodes), 5)
        self.assertIsNone(small_graph.get_node("node:1"))
        self.assertIsNotNone(small_graph.get_node("node:6"))

        # Add edges up to capacity and exceed
        for i in range(2, 8):
            small_graph.add_edge(f"node:{i-1}", f"node:{i}", EDGE_COMMUNICATED_WITH)

        self.assertLessEqual(len(small_graph._edges), 5)

    def test_security_graph_subgraph_extraction(self):
        """Test extracting connected subgraphs around seed nodes."""
        self.graph.add_node("user:alice", NODE_USER, "alice")
        self.graph.add_node("host:ws01", NODE_HOST, "ws01")
        self.graph.add_node("proc:cmd", NODE_PROCESS, "cmd.exe")

        self.graph.add_edge("user:alice", "host:ws01", EDGE_LOGGED_INTO)
        self.graph.add_edge("host:ws01", "proc:cmd", EDGE_SPAWNED_PROCESS)

        subgraph = self.graph.extract_subgraph({"user:alice"}, max_hops=2)
        self.assertEqual(subgraph["node_count"], 3)
        self.assertEqual(subgraph["edge_count"], 2)

    def test_attack_chain_detection(self):
        """Simulate a multi-stage attack: Logon -> PrivEsc -> Process -> Dropped File -> C2."""
        now = time.time()

        # Step 1: User logs on to host
        self.engine.ingest_event({
            "event_id": "4624",
            "username": "attacker",
            "hostname": "DC01",
            "src_ip": "10.0.0.50",
            "action": "allow",
            "timestamp": now - 300,
        })

        # Step 2: Privilege escalation
        self.engine.ingest_event({
            "event_id": "4672",
            "username": "attacker",
            "hostname": "DC01",
            "message": "Special privileges assigned to new logon",
            "timestamp": now - 280,
        })

        # Step 3: Spawn suspicious process (mimikatz / powershell)
        self.engine.ingest_event({
            "process_name": "mimikatz.exe",
            "hostname": "DC01",
            "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_path": "C:\\Windows\\Temp\\mimikatz.exe",
            "timestamp": now - 250,
        })

        # Step 4: External C2 communication
        self.engine.ingest_event({
            "hostname": "DC01",
            "destination_ip": "198.51.100.99",
            "timestamp": now - 200,
        })

        chains = self.engine.find_attack_chains(min_depth=3)
        self.assertGreaterEqual(len(chains), 1)

        chain = chains[0]
        self.assertGreaterEqual(chain.depth, 3)
        self.assertGreaterEqual(chain.risk_score, 80)
        self.assertIn("attacker", chain.involved_entities["users"])
        self.assertIn("DC01", chain.involved_entities["hosts"])
        self.assertIn("mimikatz.exe", chain.involved_entities["processes"])
        self.assertIn("198.51.100.99", chain.involved_entities["external_ips"])

    def test_lateral_movement_detection(self):
        """Simulate a pivot host moving laterally to multiple target internal servers."""
        now = time.time()
        pivot_ip = "192.168.1.10"
        target_a = "192.168.1.20"
        target_b = "192.168.1.30"

        # Hop 1: Pivot to Target A via RDP / 3389
        self.engine.ingest_event({
            "event_id": "4624",
            "src_ip": pivot_ip,
            "destination_ip": target_a,
            "username": "lateral_admin",
            "message": "Remote Interactive Logon via port 3389",
            "timestamp": now - 100,
        })

        # Hop 2: Pivot to Target B via SMB / 445
        self.engine.ingest_event({
            "event_id": "4624",
            "src_ip": pivot_ip,
            "destination_ip": target_b,
            "username": "lateral_admin",
            "message": "Network logon SMB port 445",
            "timestamp": now - 50,
        })

        movements = self.engine.find_lateral_movements(min_hops=2)
        self.assertGreaterEqual(len(movements), 1)
        lm = movements[0]
        self.assertEqual(lm.pivot_host, pivot_ip)
        self.assertEqual(lm.source_user, "lateral_admin")
        self.assertEqual(lm.hop_count, 2)
        self.assertIn(target_a, lm.target_hosts)
        self.assertIn(target_b, lm.target_hosts)

    def test_insider_threat_detection(self):
        """Simulate a user accessing 3 distinct host assets."""
        now = time.time()
        user = "insider_user"

        for i in range(1, 4):
            self.engine.ingest_event({
                "event_id": "4624",
                "username": user,
                "hostname": f"SERVER-CORE-{i}",
                "action": "allow",
                "timestamp": now - (30 * i),
            })

        threats = self.engine.find_insider_threats()
        self.assertGreaterEqual(len(threats), 1)
        it = threats[0]
        self.assertEqual(it.username, user)
        self.assertGreaterEqual(len(it.accessed_assets), 3)

    def test_summary_and_stats(self):
        """Verify summary returns comprehensive metrics."""
        self.engine.ingest_event({
            "event_id": "4624",
            "username": "analyst",
            "hostname": "WORKSTATION-01",
            "timestamp": time.time(),
        })

        summary = self.engine.get_summary()
        self.assertIn("total_nodes", summary)
        self.assertIn("total_edges", summary)
        self.assertGreaterEqual(summary["total_nodes"], 2)
        self.assertGreaterEqual(summary["total_edges"], 1)


if __name__ == "__main__":
    unittest.main()
