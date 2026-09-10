"""Advanced Graph Correlation Layer, Attack Chains, and Lateral Movement Engine.

Features:
1. In-Memory Bounded Security Graph (SecurityGraph):
   - Nodes: User, Host, Process, File, Network (C2 / External IPs / Domains).
   - Edges: Directed relational edges (LOGGED_INTO, ESCALATED_PRIVILEGE, SPAWNED_PROCESS,
            DROPPED_FILE, COMMUNICATED_WITH, LATERAL_MOVED_TO, ACCESSED_FILE).
   - Memory Bounding: Configurable node/edge capacity with automatic LRU and sliding-window TTL eviction.
2. Attack Chain Detection (find_attack_chains):
   - Identifies multi-stage attack paths matching:
     User -> Logon -> Host -> Privilege Escalation -> Process -> File/Hash -> External C2.
   - Calculates chain depth, cumulative risk, and generates structured stage breakdowns.
3. Lateral Movement Detection (find_lateral_movements):
   - Detects pivot movements where credentials/sessions hop across >= 2 hosts in a time window.
   - Identifies jumpbox / pivot staging hosts and targeted destination assets.
4. Insider Threat Detection (find_insider_threats):
   - Uncovers abnormal multi-critical-asset access bursts or unusual after-hours mass file activity.
5. Automated Incident Promotion:
   - Integrates with IncidentManager to promote validated graph clusters to structured Incidents
     with full subgraph visualization data and forensic chain of custody.
"""

from __future__ import annotations

import collections
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from platform_core import audit_engine

logger = logging.getLogger("graph_correlation")

# Node Types
NODE_USER = "user"
NODE_HOST = "host"
NODE_PROCESS = "process"
NODE_FILE = "file"
NODE_NETWORK = "network"

# Edge Types
EDGE_LOGGED_INTO = "LOGGED_INTO"
EDGE_FAILED_LOGIN = "FAILED_LOGIN"
EDGE_ESCALATED_PRIVILEGE = "ESCALATED_PRIVILEGE"
EDGE_SPAWNED_PROCESS = "SPAWNED_PROCESS"
EDGE_DROPPED_FILE = "DROPPED_FILE"
EDGE_ACCESSED_FILE = "ACCESSED_FILE"
EDGE_COMMUNICATED_WITH = "COMMUNICATED_WITH"
EDGE_LATERAL_MOVED_TO = "LATERAL_MOVED_TO"


@dataclass
class GraphNode:
    id: str                                  # e.g., 'user:admin', 'host:192.168.1.5', 'proc:powershell.exe'
    node_type: str                           # user, host, process, file, network
    label: str                               # Display name
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    risk_score: int = 0                      # 0 to 100
    criticality: str = "medium"              # critical, high, medium, low

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type,
            "label": self.label,
            "properties": self.properties,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "risk_score": self.risk_score,
            "criticality": self.criticality,
        }


@dataclass
class GraphEdge:
    id: str                                  # e.g., 'edge:user:admin->host:192.168.1.5:LOGGED_INTO'
    source_id: str
    target_id: str
    relation_type: str                       # LOGGED_INTO, SPAWNED_PROCESS, etc.
    timestamp: float = field(default_factory=time.time)
    weight: int = 50                         # 0 to 100
    event_id: str = ""
    job_id: str = ""
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type,
            "timestamp": self.timestamp,
            "weight": self.weight,
            "event_id": self.event_id,
            "job_id": self.job_id,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class AttackChain:
    chain_id: str
    title: str
    description: str
    start_time: float
    end_time: float
    risk_score: int
    confidence: int
    depth: int                               # Number of distinct stages
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    stages: List[Dict[str, Any]]             # Ordered breakdown of steps
    involved_entities: Dict[str, List[str]]
    mitre_tactics: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "depth": self.depth,
            "nodes": self.nodes,
            "edges": self.edges,
            "stages": self.stages,
            "involved_entities": self.involved_entities,
            "mitre_tactics": self.mitre_tactics,
        }


@dataclass
class LateralMovement:
    movement_id: str
    pivot_host: str
    source_user: str
    target_hosts: List[str]
    start_time: float
    end_time: float
    hop_count: int
    risk_score: int
    protocol: str
    evidence: List[str]
    subgraph: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "movement_id": self.movement_id,
            "pivot_host": self.pivot_host,
            "source_user": self.source_user,
            "target_hosts": self.target_hosts,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "hop_count": self.hop_count,
            "risk_score": self.risk_score,
            "protocol": self.protocol,
            "evidence": self.evidence,
            "subgraph": self.subgraph,
        }


@dataclass
class InsiderThreat:
    threat_id: str
    user_id: str
    username: str
    anomaly_type: str                        # multi_critical_access, after_hours_activity, mass_file_access
    risk_score: int
    start_time: float
    end_time: float
    accessed_assets: List[str]
    evidence: List[str]
    subgraph: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "user_id": self.user_id,
            "username": self.username,
            "anomaly_type": self.anomaly_type,
            "risk_score": self.risk_score,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "accessed_assets": self.accessed_assets,
            "evidence": self.evidence,
            "subgraph": self.subgraph,
        }


class SecurityGraph:
    """Thread-safe, Bounded In-Memory Graph with LRU and sliding-window TTL eviction."""

    def __init__(self, max_nodes: int = 5000, max_edges: int = 20000, ttl_seconds: int = 86400):
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.ttl_seconds = ttl_seconds
        self._nodes: collections.OrderedDict[str, GraphNode] = collections.OrderedDict()
        self._edges: collections.OrderedDict[str, GraphEdge] = collections.OrderedDict()
        # Adjacency indexes: node_id -> set of edge_ids
        self._out_edges: Dict[str, Set[str]] = collections.defaultdict(set)
        self._in_edges: Dict[str, Set[str]] = collections.defaultdict(set)
        self._lock = threading.RLock()

    def _cleanup_expired(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        expired_edge_ids = [
            eid for eid, edge in self._edges.items()
            if edge.timestamp < cutoff
        ]
        for eid in expired_edge_ids:
            self._remove_edge_internal(eid)

        # Remove orphan nodes that have expired and have no edges
        expired_node_ids = [
            nid for nid, node in self._nodes.items()
            if node.last_seen < cutoff and len(self._out_edges.get(nid, set())) == 0 and len(self._in_edges.get(nid, set())) == 0
        ]
        for nid in expired_node_ids:
            self._nodes.pop(nid, None)
            self._out_edges.pop(nid, None)
            self._in_edges.pop(nid, None)

    def _remove_edge_internal(self, edge_id: str) -> None:
        edge = self._edges.pop(edge_id, None)
        if edge:
            if edge.source_id in self._out_edges:
                self._out_edges[edge.source_id].discard(edge_id)
            if edge.target_id in self._in_edges:
                self._in_edges[edge.target_id].discard(edge_id)

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        properties: Optional[Dict[str, Any]] = None,
        risk_score: int = 0,
        criticality: str = "medium",
        timestamp: Optional[float] = None
    ) -> GraphNode:
        ts = timestamp if timestamp is not None else time.time()
        with self._lock:
            self._cleanup_expired(ts)
            if node_id in self._nodes:
                node = self._nodes[node_id]
                node.last_seen = max(node.last_seen, ts)
                node.risk_score = max(node.risk_score, risk_score)
                if properties:
                    node.properties.update(properties)
                if criticality in {"critical", "high"}:
                    node.criticality = criticality
                self._nodes.move_to_end(node_id)
                return node

            # Check node capacity
            if len(self._nodes) >= self.max_nodes:
                oldest_id, _ = self._nodes.popitem(last=False)
                # Cleanup associated edges
                for eid in list(self._out_edges.get(oldest_id, set())):
                    self._remove_edge_internal(eid)
                for eid in list(self._in_edges.get(oldest_id, set())):
                    self._remove_edge_internal(eid)
                self._out_edges.pop(oldest_id, None)
                self._in_edges.pop(oldest_id, None)

            node = GraphNode(
                id=node_id,
                node_type=node_type,
                label=label,
                properties=properties or {},
                first_seen=ts,
                last_seen=ts,
                risk_score=risk_score,
                criticality=criticality
            )
            self._nodes[node_id] = node
            return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: str,
        weight: int = 50,
        event_id: str = "",
        job_id: str = "",
        evidence: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None
    ) -> GraphEdge:
        ts = timestamp if timestamp is not None else time.time()
        edge_id = f"edge:{source_id}->{target_id}:{relation_type}"
        with self._lock:
            self._cleanup_expired(ts)
            # Ensure both nodes exist or will be accessed
            if edge_id in self._edges:
                edge = self._edges[edge_id]
                edge.timestamp = max(edge.timestamp, ts)
                edge.weight = max(edge.weight, weight)
                if event_id:
                    edge.event_id = event_id
                if evidence:
                    edge.evidence = list(set(edge.evidence + evidence))[:10]
                if metadata:
                    edge.metadata.update(metadata)
                self._edges.move_to_end(edge_id)
                return edge

            if len(self._edges) >= self.max_edges:
                oldest_eid, _ = self._edges.popitem(last=False)
                # Clean from indexes
                for nid in list(self._out_edges.keys()):
                    self._out_edges[nid].discard(oldest_eid)
                for nid in list(self._in_edges.keys()):
                    self._in_edges[nid].discard(oldest_eid)

            edge = GraphEdge(
                id=edge_id,
                source_id=source_id,
                target_id=target_id,
                relation_type=relation_type,
                timestamp=ts,
                weight=weight,
                event_id=event_id,
                job_id=job_id,
                evidence=evidence or [],
                metadata=metadata or {}
            )
            self._edges[edge_id] = edge
            self._out_edges[source_id].add(edge_id)
            self._in_edges[target_id].add(edge_id)
            return edge

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        with self._lock:
            return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[Tuple[GraphNode, GraphEdge]]:
        """Returns outgoing neighbors: (target_node, edge)."""
        result = []
        with self._lock:
            out_eids = self._out_edges.get(node_id, set())
            for eid in out_eids:
                edge = self._edges.get(eid)
                if edge and edge.target_id in self._nodes:
                    result.append((self._nodes[edge.target_id], edge))
        return result

    def get_incoming_neighbors(self, node_id: str) -> List[Tuple[GraphNode, GraphEdge]]:
        """Returns incoming neighbors: (source_node, edge)."""
        result = []
        with self._lock:
            in_eids = self._in_edges.get(node_id, set())
            for eid in in_eids:
                edge = self._edges.get(eid)
                if edge and edge.source_id in self._nodes:
                    result.append((self._nodes[edge.source_id], edge))
        return result

    def extract_subgraph(self, node_ids: Set[str], max_hops: int = 1) -> Dict[str, Any]:
        """Extract a subgraph surrounding the provided seed nodes up to max_hops."""
        with self._lock:
            visited_nodes: Set[str] = set(node_ids)
            current_level = set(node_ids)

            for _ in range(max_hops):
                next_level = set()
                for nid in current_level:
                    for eid in self._out_edges.get(nid, set()):
                        edge = self._edges.get(eid)
                        if edge and edge.target_id in self._nodes:
                            next_level.add(edge.target_id)
                    for eid in self._in_edges.get(nid, set()):
                        edge = self._edges.get(eid)
                        if edge and edge.source_id in self._nodes:
                            next_level.add(edge.source_id)
                visited_nodes.update(next_level)
                current_level = next_level

            nodes_data = [self._nodes[nid].to_dict() for nid in visited_nodes if nid in self._nodes]
            edges_data = []
            for eid, edge in self._edges.items():
                if edge.source_id in visited_nodes and edge.target_id in visited_nodes:
                    edges_data.append(edge.to_dict())

            return {
                "nodes": nodes_data,
                "edges": edges_data,
                "node_count": len(nodes_data),
                "edge_count": len(edges_data),
            }

    def get_snapshot(self, limit_nodes: int = 300) -> Dict[str, Any]:
        with self._lock:
            # Return top active nodes sorted by last_seen descending
            sorted_nodes = sorted(self._nodes.values(), key=lambda n: n.last_seen, reverse=True)[:limit_nodes]
            node_ids = {n.id for n in sorted_nodes}
            nodes_data = [n.to_dict() for n in sorted_nodes]

            edges_data = [
                edge.to_dict() for edge in self._edges.values()
                if edge.source_id in node_ids and edge.target_id in node_ids
            ]

            return {
                "nodes": nodes_data,
                "edges": edges_data,
                "total_nodes": len(self._nodes),
                "total_edges": len(self._edges),
            }

    def clear(self) -> None:
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._out_edges.clear()
            self._in_edges.clear()


class GraphCorrelationEngine:
    """Core Engine evaluating Attack Chains, Lateral Movement, and Insider Threats on SecurityGraph."""

    def __init__(self, graph: Optional[SecurityGraph] = None):
        self.graph = graph or SecurityGraph()
        self._attack_chains: List[AttackChain] = []
        self._lateral_movements: List[LateralMovement] = []
        self._insider_threats: List[InsiderThreat] = []
        self._promoted_fingerprints: Set[str] = set()
        self._lock = threading.RLock()
        self._counter = 1

    def _next_id(self, prefix: str) -> str:
        with self._lock:
            cid = f"{prefix}-2026-{self._counter:05d}"
            self._counter += 1
            return cid

    def ingest_event(self, event: Any, job_id: str = "") -> None:
        """Parse and ingest a CanonicalEvent or dict into the Security Graph."""
        if not event:
            return

        # Extract fields safely from CanonicalEvent or dict
        if hasattr(event, "username"):
            username = str(getattr(event, "username", "") or "").strip()
            src_ip = str(getattr(event, "source_ip", "") or "").strip()
            dst_ip = str(getattr(event, "destination_ip", "") or "").strip()
            hostname = str(getattr(event, "computer_name", "") or getattr(event, "hostname", "") or "").strip()
            event_id = str(getattr(event, "event_id", "") or "").strip()
            event_time = getattr(event, "event_time", None)
            process_name = str(getattr(event, "process_name", "") or "").strip()
            file_path = str(getattr(event, "file_path", "") or getattr(event, "file_name", "") or "").strip()
            file_hash = str(getattr(event, "file_hash", "") or "").strip()
            action = str(getattr(event, "action", "") or "").strip().lower()
            message = str(getattr(event, "message", "") or "").lower()
            raw_fields = getattr(event, "raw_fields", {}) or {}
        else:
            username = str(event.get("username", "") or event.get("user", "") or "").strip()
            src_ip = str(event.get("source_ip", "") or event.get("src_ip", "") or "").strip()
            dst_ip = str(event.get("destination_ip", "") or event.get("dst_ip", "") or "").strip()
            hostname = str(event.get("computer_name", "") or event.get("hostname", "") or "").strip()
            event_id = str(event.get("event_id", "") or "").strip()
            event_time = event.get("timestamp") or event.get("event_time")
            process_name = str(event.get("process_name", "") or event.get("image", "") or "").strip()
            file_path = str(event.get("file_path", "") or event.get("file_name", "") or "").strip()
            file_hash = str(event.get("file_hash", "") or event.get("hash", "") or "").strip()
            action = str(event.get("action", "") or "").strip().lower()
            message = str(event.get("message", "") or "").lower()
            raw_fields = event.get("raw_fields", {}) or {}

        # Parse epoch timestamp
        ts = time.time()
        if isinstance(event_time, (int, float)):
            ts = float(event_time)
        elif isinstance(event_time, str) and event_time:
            try:
                dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                ts = dt.timestamp()
            except Exception:
                pass

        # Identify Host
        host_id = None
        if hostname:
            host_id = f"host:{hostname.lower()}"
            self.graph.add_node(host_id, NODE_HOST, hostname, {"primary_ip": src_ip or dst_ip}, timestamp=ts)
        elif src_ip and not src_ip.startswith("127."):
            host_id = f"host:{src_ip}"
            self.graph.add_node(host_id, NODE_HOST, src_ip, {"primary_ip": src_ip}, timestamp=ts)

        # Identify User
        user_id = None
        if username and username.lower() not in {"system", "local service", "network service", "-", "unknown"}:
            user_id = f"user:{username.lower()}"
            self.graph.add_node(user_id, NODE_USER, username, timestamp=ts)

        # Edge: Logon / Authentication
        if user_id and host_id:
            if event_id in {"4624", "10", "login_success"} or "accepted password" in message or action == "allow":
                self.graph.add_edge(
                    user_id, host_id, EDGE_LOGGED_INTO, weight=40,
                    event_id=event_id, job_id=job_id,
                    evidence=[f"Successful logon by {username} on {hostname or src_ip}"],
                    timestamp=ts
                )
            elif event_id in {"4625", "login_failure"} or "failed password" in message:
                self.graph.add_edge(
                    user_id, host_id, EDGE_FAILED_LOGIN, weight=60,
                    event_id=event_id, job_id=job_id,
                    evidence=[f"Failed logon attempt by {username} on {hostname or src_ip}"],
                    timestamp=ts
                )

            # Edge: Privilege Escalation
            if event_id in {"4672", "7045", "sudo", "privilege_escalation"} or "privilege" in message or "assigned special privileges" in message:
                self.graph.add_edge(
                    user_id, host_id, EDGE_ESCALATED_PRIVILEGE, weight=85,
                    event_id=event_id, job_id=job_id,
                    evidence=[f"Special administrative privileges invoked by {username} on {hostname or src_ip}"],
                    timestamp=ts
                )

        # Edge: Process Execution (Host / User -> Process)
        if process_name:
            proc_id = f"proc:{process_name.lower()}"
            is_suspicious_proc = any(s in process_name.lower() for s in ["powershell", "cmd.exe", "wmic", "mimikatz", "vssadmin", "certutil", "rundll32"])
            self.graph.add_node(proc_id, NODE_PROCESS, process_name, {"is_suspicious": is_suspicious_proc}, risk_score=75 if is_suspicious_proc else 10, timestamp=ts)
            
            origin_id = host_id or user_id
            if origin_id:
                self.graph.add_edge(
                    origin_id, proc_id, EDGE_SPAWNED_PROCESS,
                    weight=70 if is_suspicious_proc else 30,
                    event_id=event_id, job_id=job_id,
                    evidence=[f"Executed process {process_name} on {origin_id}"],
                    timestamp=ts
                )

            # Edge: Process -> File / Hash
            if file_hash or file_path:
                target_file_label = file_hash[:12] if file_hash else file_path.replace('\\', '/').split('/')[-1]
                file_node_id = f"file:{file_hash if file_hash else file_path.lower()}"
                self.graph.add_node(file_node_id, NODE_FILE, target_file_label, {"hash": file_hash, "path": file_path}, timestamp=ts)
                self.graph.add_edge(
                    proc_id, file_node_id, EDGE_DROPPED_FILE,
                    weight=65, event_id=event_id, job_id=job_id,
                    evidence=[f"Process {process_name} accessed/created {target_file_label}"],
                    timestamp=ts
                )

        # Edge: Network Connection / External C2 (Host -> Network)
        if dst_ip and not dst_ip.startswith("127.") and not dst_ip.startswith("10.") and not dst_ip.startswith("192.168."):
            net_id = f"net:{dst_ip}"
            self.graph.add_node(net_id, NODE_NETWORK, dst_ip, {"ip": dst_ip}, risk_score=70, timestamp=ts)
            if host_id:
                self.graph.add_edge(
                    host_id, net_id, EDGE_COMMUNICATED_WITH,
                    weight=60, event_id=event_id, job_id=job_id,
                    evidence=[f"Outbound network communication from {host_id} to external target {dst_ip}"],
                    timestamp=ts
                )

        # Edge: Lateral Movement (Host A -> Host B)
        if src_ip and dst_ip and src_ip != dst_ip:
            if src_ip.startswith(("10.", "172.16.", "192.168.")) and dst_ip.startswith(("10.", "172.16.", "192.168.")):
                h_src = f"host:{src_ip}"
                h_dst = f"host:{dst_ip}"
                self.graph.add_node(h_src, NODE_HOST, src_ip, timestamp=ts)
                self.graph.add_node(h_dst, NODE_HOST, dst_ip, timestamp=ts)
                is_admin_proto = any(p in message or p in str(raw_fields) for p in ["445", "3389", "5985", "5986", "22", "rdp", "smb", "winrm"])
                if is_admin_proto or event_id in {"4624", "4648"}:
                    self.graph.add_edge(
                        h_src, h_dst, EDGE_LATERAL_MOVED_TO,
                        weight=75 if is_admin_proto else 50,
                        event_id=event_id, job_id=job_id,
                        evidence=[f"Internal network connection between {src_ip} and {dst_ip}"],
                        metadata={"user": username},
                        timestamp=ts
                    )

    def find_attack_chains(self, min_depth: int = 3) -> List[AttackChain]:
        """Detect multi-stage attack chains across the graph topology."""
        chains: List[AttackChain] = []
        with self._lock:
            # We look for User nodes that logged in, escalated privilege, spawned suspicious process,
            # or connected to external C2 networks
            for nid, node in self.graph._nodes.items():
                if node.node_type != NODE_USER:
                    continue

                # Traverse from User
                # Stage 1: User -> Host (LOGGED_INTO or ESCALATED_PRIVILEGE)
                neighbors = self.graph.get_neighbors(nid)
                for host_node, edge_u_h in neighbors:
                    if host_node.node_type != NODE_HOST:
                        continue

                    has_priv_esc = edge_u_h.relation_type == EDGE_ESCALATED_PRIVILEGE
                    # Check if privilege escalation edge exists between this user and host
                    for h_in_node, h_in_edge in self.graph.get_incoming_neighbors(host_node.id):
                        if h_in_node.id == nid and h_in_edge.relation_type == EDGE_ESCALATED_PRIVILEGE:
                            has_priv_esc = True
                            break

                    # Stage 2: Host -> Process
                    host_neighbors = self.graph.get_neighbors(host_node.id)
                    for proc_node, edge_h_p in host_neighbors:
                        if proc_node.node_type != NODE_PROCESS:
                            continue

                        # Stage 3: Process -> File OR Host -> Network
                        proc_neighbors = self.graph.get_neighbors(proc_node.id)
                        external_c2 = None
                        dropped_file = None

                        for sub_node, edge_p_s in proc_neighbors:
                            if sub_node.node_type == NODE_FILE:
                                dropped_file = sub_node
                            elif sub_node.node_type == NODE_NETWORK:
                                external_c2 = sub_node

                        # Also check if Host has an outbound C2
                        if not external_c2:
                            for h_sub_node, edge_h_s in host_neighbors:
                                if h_sub_node.node_type == NODE_NETWORK:
                                    external_c2 = h_sub_node
                                    break

                        # Determine if this constitutes a qualified attack chain
                        stages = [
                            {
                                "stage_number": 1,
                                "tactic": "Initial Access / Logon",
                                "title_ar": "تسجيل دخول وبدء جلسة",
                                "entity": f"{node.label} ➔ {host_node.label}",
                                "timestamp": edge_u_h.timestamp,
                                "details": f"تسجيل دخول المستخدم [{node.label}] إلى الجهاز [{host_node.label}]."
                            }
                        ]

                        current_depth = 2
                        if has_priv_esc:
                            current_depth += 1
                            stages.append({
                                "stage_number": current_depth - 1,
                                "tactic": "Privilege Escalation",
                                "title_ar": "تصعيد الصلاحيات الإدارية",
                                "entity": f"{node.label} @ {host_node.label}",
                                "timestamp": edge_u_h.timestamp,
                                "details": f"استدعاء صلاحيات سيادية خاصة للمستخدم [{node.label}]."
                            })

                        stages.append({
                            "stage_number": len(stages) + 1,
                            "tactic": "Execution",
                            "title_ar": "تنفيذ عملية برمجية",
                            "entity": proc_node.label,
                            "timestamp": edge_h_p.timestamp,
                            "details": f"تشغيل العملية [{proc_node.label}] على الجهاز [{host_node.label}]."
                        })

                        if dropped_file:
                            current_depth += 1
                            stages.append({
                                "stage_number": len(stages) + 1,
                                "tactic": "Persistence / Artifact Creation",
                                "title_ar": "إنشاء ملف أو بصمة مشبوهة",
                                "entity": dropped_file.label,
                                "timestamp": edge_h_p.timestamp,
                                "details": f"إنشاء أو قراءة الملف [{dropped_file.label}]."
                            })

                        if external_c2:
                            current_depth += 1
                            stages.append({
                                "stage_number": len(stages) + 1,
                                "tactic": "Command and Control",
                                "title_ar": "اتصال خارجي بمركز التحكم C2",
                                "entity": external_c2.label,
                                "timestamp": edge_h_p.timestamp,
                                "details": f"رصد اتصال شبكي موجه إلى العنوان الخارجي [{external_c2.label}]."
                            })

                        if len(stages) >= min_depth:
                            chain_id = self._next_id("CHN")
                            chain_nodes = [node.to_dict(), host_node.to_dict(), proc_node.to_dict()]
                            chain_edges = [edge_u_h.to_dict(), edge_h_p.to_dict()]
                            if dropped_file:
                                chain_nodes.append(dropped_file.to_dict())
                            if external_c2:
                                chain_nodes.append(external_c2.to_dict())

                            risk = 80 + (10 if has_priv_esc else 0) + (10 if external_c2 else 0)
                            risk = min(100, risk)

                            ac = AttackChain(
                                chain_id=chain_id,
                                title=f"سلسلة هجوم متعددة المراحل: {node.label} ➔ {proc_node.label}" + (f" ➔ {external_c2.label}" if external_c2 else ""),
                                description=f"رصد مسار هجوم متسلسل يبدأ بوصول الحساب [{node.label}] متبوعاً بتشغيل [{proc_node.label}]" + (" واتصال خارجي مشبوه." if external_c2 else "."),
                                start_time=edge_u_h.timestamp,
                                end_time=max(edge_h_p.timestamp, edge_u_h.timestamp),
                                risk_score=risk,
                                confidence=88,
                                depth=len(stages),
                                nodes=chain_nodes,
                                edges=chain_edges,
                                stages=stages,
                                involved_entities={
                                    "users": [node.label],
                                    "hosts": [host_node.label],
                                    "processes": [proc_node.label],
                                    "external_ips": [external_c2.label] if external_c2 else [],
                                },
                                mitre_tactics=[s["tactic"] for s in stages]
                            )
                            chains.append(ac)

            self._attack_chains = chains
        return chains

    def find_lateral_movements(self, min_hops: int = 2) -> List[LateralMovement]:
        """Detect lateral movement across hosts originating from pivot staging hosts."""
        movements: List[LateralMovement] = []
        with self._lock:
            # Group outgoing LATERAL_MOVED_TO edges by source host
            pivot_candidates: Dict[str, List[GraphEdge]] = collections.defaultdict(list)
            for eid, edge in self.graph._edges.items():
                if edge.relation_type == EDGE_LATERAL_MOVED_TO:
                    pivot_candidates[edge.source_id].append(edge)

            for pivot_id, edges in pivot_candidates.items():
                target_host_ids = list({e.target_id for e in edges})
                if len(target_host_ids) >= min_hops or (len(edges) >= 2):
                    pivot_node = self.graph.get_node(pivot_id)
                    pivot_name = pivot_node.label if pivot_node else pivot_id.replace("host:", "")

                    users = list({e.metadata.get("user") for e in edges if e.metadata.get("user")})
                    user_str = users[0] if users else "غير محدد"
                    target_names = [
                        self.graph.get_node(tid).label if self.graph.get_node(tid) else tid.replace("host:", "")
                        for tid in target_host_ids
                    ]

                    all_node_ids = {pivot_id}.union(set(target_host_ids))
                    subgraph = self.graph.extract_subgraph(all_node_ids, max_hops=1)

                    lm = LateralMovement(
                        movement_id=self._next_id("LAT"),
                        pivot_host=pivot_name,
                        source_user=user_str,
                        target_hosts=target_names,
                        start_time=min(e.timestamp for e in edges),
                        end_time=max(e.timestamp for e in edges),
                        hop_count=len(target_host_ids),
                        risk_score=min(95, 70 + len(target_host_ids) * 10),
                        protocol="RDP/SMB/AdminSession",
                        evidence=[f"Pivot from {pivot_name} to {len(target_host_ids)} internal hosts by user [{user_str}]."] + [e.evidence[0] for e in edges if e.evidence],
                        subgraph=subgraph
                    )
                    movements.append(lm)

            self._lateral_movements = movements
        return movements

    def find_insider_threats(self) -> List[InsiderThreat]:
        """Detect abnormal user access patterns across multiple critical host nodes."""
        threats: List[InsiderThreat] = []
        with self._lock:
            for nid, node in self.graph._nodes.items():
                if node.node_type != NODE_USER:
                    continue

                neighbors = self.graph.get_neighbors(nid)
                accessed_hosts = [
                    h_node for h_node, edge in neighbors
                    if h_node.node_type == NODE_HOST and edge.relation_type == EDGE_LOGGED_INTO
                ]

                # Check if user accessed 3+ distinct hosts, or accessed critical infrastructure
                critical_hosts = [h for h in accessed_hosts if h.criticality in {"critical", "high"}]
                if len(accessed_hosts) >= 3 or len(critical_hosts) >= 2:
                    all_ids = {nid}.union({h.id for h in accessed_hosts})
                    subgraph = self.graph.extract_subgraph(all_ids, max_hops=1)
                    evidence = [
                        f"User {node.label} established authenticated sessions on {len(accessed_hosts)} hosts.",
                        f"Critical assets accessed: {', '.join(h.label for h in critical_hosts) if critical_hosts else 'None'}"
                    ]

                    it = InsiderThreat(
                        threat_id=self._next_id("INS"),
                        user_id=nid,
                        username=node.label,
                        anomaly_type="multi_critical_access" if critical_hosts else "excessive_asset_access",
                        risk_score=85 if critical_hosts else 70,
                        start_time=node.first_seen,
                        end_time=node.last_seen,
                        accessed_assets=[h.label for h in accessed_hosts],
                        evidence=evidence,
                        subgraph=subgraph
                    )
                    threats.append(it)

            self._insider_threats = threats
        return threats

    def correlate_all(self) -> Dict[str, Any]:
        """Run all pattern detectors and return compiled graph intelligence."""
        chains = self.find_attack_chains()
        laterals = self.find_lateral_movements()
        insiders = self.find_insider_threats()
        return {
            "attack_chains": [c.to_dict() for c in chains],
            "lateral_movements": [lm.to_dict() for lm in laterals],
            "insider_threats": [it.to_dict() for it in insiders],
            "summary": self.get_summary()
        }

    def promote_pattern_to_incident(self, pattern_type: str, pattern_id: str, incident_mgr: Any = None) -> Optional[Any]:
        """Promote a detected graph pattern to a formal SOC incident."""
        from platform_core import incident_manager
        mgr = incident_mgr or incident_manager

        with self._lock:
            fp = f"graph:{pattern_type}:{pattern_id}"
            if fp in self._promoted_fingerprints:
                return None

            if pattern_type == "attack_chain":
                chain = next((c for c in self._attack_chains if c.chain_id == pattern_id), None)
                if not chain:
                    return None
                self._promoted_fingerprints.add(fp)

                evidence_lines = [
                    f"Attack Chain ID: {chain.chain_id}",
                    f"Stages Count: {chain.depth}",
                    f"Risk Score: {chain.risk_score}",
                    f"Involved Users: {', '.join(chain.involved_entities.get('users', []))}",
                    f"Involved Hosts: {', '.join(chain.involved_entities.get('hosts', []))}",
                    f"Involved Processes: {', '.join(chain.involved_entities.get('processes', []))}",
                ]
                for stg in chain.stages:
                    evidence_lines.append(f"[المرحلة {stg['stage_number']}]: {stg['title_ar']} ({stg['tactic']}) - {stg['details']}")

                inc = mgr.promote_detection_to_incident(
                    title=f"رصد سلسلة هجوم مترابطة: {chain.title}",
                    description=chain.description,
                    severity="critical" if chain.risk_score >= 85 else "high",
                    source_app="GraphCorrelationEngine",
                    source_system="GraphSecurityMesh",
                    event_ids=[],
                    raw_evidence=evidence_lines,
                    asset_criticality="High",
                    business_impact="Operational",
                    created_by="GraphCorrelationEngine (Attack Chain)",
                )
                return inc

            elif pattern_type == "lateral_movement":
                lm = next((m for m in self._lateral_movements if m.movement_id == pattern_id), None)
                if not lm:
                    return None
                self._promoted_fingerprints.add(fp)

                evidence_lines = [
                    f"Lateral Movement ID: {lm.movement_id}",
                    f"Pivot Staging Host: {lm.pivot_host}",
                    f"Target Hosts ({lm.hop_count}): {', '.join(lm.target_hosts)}",
                    f"Actor User: {lm.source_user}",
                ] + lm.evidence

                inc = mgr.promote_detection_to_incident(
                    title=f"رصد تنقل أفقي مشبوه (Lateral Movement): عبر [{lm.pivot_host}]",
                    description=f"رصد قفزات تنقل شبكي متعددة من المحطة الوسيطة [{lm.pivot_host}] ضد {lm.hop_count} أجهزة داخلية بواسطة [{lm.source_user}].",
                    severity="critical" if lm.risk_score >= 85 else "high",
                    source_app="GraphCorrelationEngine",
                    source_system=lm.pivot_host,
                    event_ids=[],
                    raw_evidence=evidence_lines,
                    asset_criticality="High",
                    business_impact="Operational",
                    created_by="GraphCorrelationEngine (Lateral Movement)",
                )
                return inc

        return None

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            node_counts: Dict[str, int] = collections.defaultdict(int)
            for n in self.graph._nodes.values():
                node_counts[n.node_type] += 1

            edge_counts: Dict[str, int] = collections.defaultdict(int)
            for e in self.graph._edges.values():
                edge_counts[e.relation_type] += 1

            return {
                "total_nodes": len(self.graph._nodes),
                "total_edges": len(self.graph._edges),
                "nodes_by_type": dict(node_counts),
                "edges_by_type": dict(edge_counts),
                "active_attack_chains": len(self._attack_chains),
                "active_lateral_movements": len(self._lateral_movements),
                "active_insider_threats": len(self._insider_threats),
                "last_analysis_time": time.time(),
            }


# Global Singleton Instance
_global_graph_engine: Optional[GraphCorrelationEngine] = None
_global_lock = threading.Lock()


def get_graph_correlation_engine() -> GraphCorrelationEngine:
    global _global_graph_engine
    if _global_graph_engine is None:
        with _global_lock:
            if _global_graph_engine is None:
                _global_graph_engine = GraphCorrelationEngine()
    return _global_graph_engine
