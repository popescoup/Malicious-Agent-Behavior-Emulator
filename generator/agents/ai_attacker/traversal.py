"""
MABE AI Attacker — BFS Traversal Agent
========================================

The core of the AI attacker engine. Implements a modified breadth-first search
over the network graph, producing the exhaustive enumeration behavioral
signatures that distinguish AI-driven attacks from human-operated ones.

EMPIRICAL GROUNDING
-------------------
Source: GTG-1002 (November 2025) — "Claude systematically tested authentication
against internal APIs, database systems, container registries, and logging
infrastructure, building comprehensive maps of internal network architecture
and access relationships." → Justifies probe_all_neighbors and the neighbor
priority ordering.

Source: arXiv 2502.04227 (cochise) — "PentestGPT V2 executes coherent
multi-host attack chains using a Memory Subsystem for credential persistence
and a targeted discovery approach for exploration." → Justifies the distinction
between AI traversal (systematic, memory-persistent) and human traversal
(targeted, fewer hops).

BFS ALGORITHM
-------------
At each node, the traversal agent executes in this order:

1. DNS enumeration — emit one dns_query event per newly discovered host
2. Service probing — emit one service_probe event per service on the node
3. Kerberos TGT request — if the node is a domain_controller
4. File access — if the node is a file_server and auth succeeded; rolls
   file_credential_harvest_probability per access event
5. Neighbor enumeration — for each ACL-permitted neighbor reachable under
   current credential privilege, sorted by node type priority:
   a. Auth attempt with first protocol in fallback sequence
   b. On failure: retry up to max_auth_retries, then advance to next
      protocol; if all protocols exhausted, emit backtrack event
   c. On success: apply hallucination check (FIRST); if hallucinated,
      do not enqueue; if real, enqueue and roll credential harvest

PROTOCOL FALLBACK MAPPING
--------------------------
Maps graph node_type values to behavioral_params protocol_fallback_sequences
keys. Structural knowledge — not operator-tunable. Consistent with the
auth_protocols listed per node type in Section 7 of the spec.

    workstation             → windows_host
    domain_controller       → windows_host
    file_server             → windows_host
    logging_infrastructure  → windows_host
    database                → database
    api_endpoint            → api_endpoint
    container_registry      → registry

FAN-OUT COUNT
-------------
Resets to zero each time BFS moves to a new node. Tracks the number of
distinct neighbor nodes probed from the current node in the current visit.
The detection value is per-node: a fan_out_count > 10 at a single node
identifies exhaustive enumeration regardless of session length.

DWELL_MS
--------
Computed as the delta (in milliseconds) between the current event's timestamp
and the arrival timestamp at the current node. Zero on the first event at a
node, growing as the agent works through probes and auth attempts.

SCOPE EXPANSION
---------------
Expansion nodes (if any) are injected into the BFS frontier at session start
by the caller (AIAttackerAgent.__init__.py). The traversal agent treats them
identically to normally discovered nodes except that events at those nodes
carry attack_step=scope_expansion.
"""

from __future__ import annotations

import random
import uuid
from collections import deque
from datetime import datetime, timezone

import networkx as nx

from generator.agents.ai_attacker.foothold import Credential, FootholdResult
from generator.agents.ai_attacker.hallucination import HallucinationModule
from generator.agents.ai_attacker.velocity import VelocityModel
from schema.event import Event, ATTACK_STEP_TTP

# ---------------------------------------------------------------------------
# Protocol fallback mapping
# ---------------------------------------------------------------------------
# Maps node_type → key in behavioral_params.protocol_fallback_sequences.
# Consistent with auth_protocols per node type in Section 7 of the spec.

NODE_TYPE_FALLBACK_CATEGORY: dict[str, str] = {
    "workstation":            "windows_host",
    "domain_controller":      "windows_host",
    "file_server":            "windows_host",
    "logging_infrastructure": "windows_host",
    "database":               "database",
    "api_endpoint":           "api_endpoint",
    "container_registry":     "registry",
}

# Service → destination port (shared with benign_user for consistency)
SERVICE_PORT: dict[str, int] = {
    "ldap":            389,
    "kerberos":        88,
    "dns":             53,
    "mssql":           1433,
    "postgresql":      5432,
    "docker_registry": 5000,
    "helm_registry":   8080,
    "http":            80,
    "https":           443,
    "smb":             445,
    "nfs":             2049,
    "syslog":          514,
    "rdp":             3389,
    "oauth":           443,
    "basic":           80,
    "token":           443,
    "ntlm":            445,
    "sql_auth":        1433,
    "windows_auth":    445,
}

# Auth protocol → Windows logon type integer
AUTH_LOGON_TYPE: dict[str, int] = {
    "kerberos":     3,
    "ntlm":         3,
    "oauth":        3,
    "basic":        3,
    "token":        3,
    "sql_auth":     3,
    "windows_auth": 3,
    "ssh":          10,
}

# Failure reason → Windows hex status code
FAILURE_CODE: dict[str, str] = {
    "auth_failed":        "0xC000006D",
    "access_denied":      "0xC0000022",
    "no_route":           "0xC000005E",
    "host_unreachable":   "0xC0000064",
    "service_unavailable":"0xC000023A",
    "timeout":            "0xC000023A",
    "credential_invalid": "0xC000006D",
}

# Neighbor priority order (index = priority; lower index = higher priority)
# Must match behavioral_params.yaml neighbor_priority_order
DEFAULT_PRIORITY_ORDER: list[str] = [
    "domain_controller",
    "database",
    "container_registry",
    "logging_infrastructure",
    "api_endpoint",
    "file_server",
    "workstation",
]


# ---------------------------------------------------------------------------
# BFSTraversalAgent
# ---------------------------------------------------------------------------

class BFSTraversalAgent:
    """
    Modified BFS traversal agent for the AI attacker.

    Parameters
    ----------
    graph : nx.DiGraph
        The shared network graph.
    params : dict
        The ai_attacker section of behavioral_params.yaml.
    rng : random.Random
        Seeded RNG from simulate.py.
    velocity : VelocityModel
        Shared velocity model — start_session() already called by
        FootholdInitializer before traversal begins.
    hallucination : HallucinationModule
        Shared hallucination module.
    foothold_result : FootholdResult
        Output of FootholdInitializer.initialize() — provides session_id,
        foothold_node, attack_framework_pid, and the initial credential store.
    expansion_nodes : list[str]
        Node IDs pre-injected into the BFS frontier by the scope expansion
        module. Empty list if no scope expansion occurred this session.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        params: dict,
        rng: random.Random,
        velocity: VelocityModel,
        hallucination: HallucinationModule,
        foothold_result: FootholdResult,
        expansion_nodes: list[str],
    ) -> None:
        self._graph = graph
        self._params = params
        self._rng = rng
        self._velocity = velocity
        self._hallucination = hallucination

        # Session identity from foothold
        self._session_id: str = foothold_result.session_id
        self._foothold_node: str = foothold_result.foothold_node
        self._attack_framework_pid: int = foothold_result.attack_framework_pid
        self._attack_framework_image: str = foothold_result.attack_framework_image
        self._username: str = foothold_result.foothold_event.user

        # Credential store — mutable, grows as credentials are harvested
        self._credential_store: list[Credential] = list(
            foothold_result.credential_store
        )

        # BFS state
        self._visited: set[str] = {foothold_result.foothold_node}
        self._frontier: deque[str] = deque([foothold_result.foothold_node])

        # Inject scope expansion nodes into frontier immediately
        for node in expansion_nodes:
            if node not in self._visited:
                self._frontier.append(node)
                self._visited.add(node)

        # Track which nodes are scope expansion nodes for labeling
        self._expansion_nodes: set[str] = set(expansion_nodes)

        # Behavioral params
        self._max_auth_retries: int = int(
            params.get("max_auth_retries", 3)
        )
        self._priority_order: list[str] = params.get(
            "neighbor_priority_order", DEFAULT_PRIORITY_ORDER
        )
        self._fallback_sequences: dict[str, list[str]] = params.get(
            "protocol_fallback_sequences", {}
        )
        self._file_access_per_visit: int = int(
            params.get("file_access_events_per_visit", 3)
        )
        self._file_harvest_prob: float = float(
            params.get("file_credential_harvest_probability", 0.15)
        )

        # Set file harvest probability on the hallucination module
        self._hallucination.set_file_harvest_probability(self._file_harvest_prob)

        # DNS discovery tracking — emit one dns_query per newly seen hostname
        self._dns_resolved: set[str] = set()

        # Accumulated events — appended throughout run()
        self._events: list[Event] = []

        # Sysmon records accumulated during traversal (Event 3, 13, 22)
        self._sysmon_records: list[dict] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> tuple[list[Event], list[dict]]:
        """
        Execute the full BFS traversal and return all generated events.

        Returns
        -------
        tuple[list[Event], list[dict]]
            (canonical_events, sysmon_records)
            canonical_events: all Event objects from the traversal, in
                timestamp order.
            sysmon_records: Sysmon Event 3, 13, and 22 records for the
                EVTX formatter.
        """
        while self._frontier:
            current_node = self._frontier.popleft()
            self._visit_node(current_node)

        return self._events, self._sysmon_records

    @property
    def credential_store(self) -> list[Credential]:
        """Current credential store — readable by AIAttackerAgent for reporting."""
        return list(self._credential_store)

    # ------------------------------------------------------------------
    # Node visitation
    # ------------------------------------------------------------------

    def _visit_node(self, node_id: str) -> None:
        """
        Execute all actions at a single BFS node.

        Order per spec Section 9:
        1. DNS enumeration (if newly discovered)
        2. Service probing
        3. Kerberos TGT request (domain_controller only)
        4. File access (file_server only, requires prior auth success)
        5. Neighbor enumeration and auth attempts
        """
        node_attrs = self._graph.nodes[node_id]
        node_type: str = node_attrs.get("node_type", "workstation")
        is_expansion: bool = node_id in self._expansion_nodes

        # Record arrival time for dwell_ms computation
        arrival_time: datetime = self._velocity.current_time()

        # Record event list length at visit start — used by
        # _update_fan_out_count to identify exactly which events
        # belong to this visit without relying on fan_out heuristics.
        visit_start_index: int = len(self._events)

        # ── Step 1: DNS enumeration ───────────────────────────────────
        if node_id not in self._dns_resolved:
            self._dns_resolved.add(node_id)
            self._emit_dns_event(
                node_id=node_id,
                node_attrs=node_attrs,
                arrival_time=arrival_time,
                is_expansion=is_expansion,
            )
            arrival_time = self._velocity.current_time()

        # ── Step 2: Service probing ───────────────────────────────────
        for service in node_attrs.get("services", []):
            self._emit_service_probe(
                node_id=node_id,
                node_attrs=node_attrs,
                service=service,
                arrival_time=arrival_time,
                is_expansion=is_expansion,
            )

        # ── Step 3: Kerberos TGT request (domain controllers only) ────
        if node_type == "domain_controller":
            self._emit_kerberos_tgt(
                node_id=node_id,
                node_attrs=node_attrs,
                arrival_time=arrival_time,
            )

        # ── Step 4: File access (file servers only) ───────────────────
        # File access requires that the agent has sufficient privilege to
        # reach this node. We check privilege here rather than requiring a
        # separate auth success flag — the BFS only enqueues nodes the agent
        # can reach, so presence in the frontier implies reachability.
        file_auth_succeeded = False
        if node_type == "file_server":
            file_auth_succeeded = self._attempt_auth(
                src_node=self._foothold_node,
                dst_node=node_id,
                node_attrs=node_attrs,
                arrival_time=arrival_time,
                is_expansion=is_expansion,
                is_file_server_auth=True,
            )
            if file_auth_succeeded:
                for _ in range(self._file_access_per_visit):
                    self._emit_file_access(
                        node_id=node_id,
                        node_attrs=node_attrs,
                        arrival_time=arrival_time,
                        is_expansion=is_expansion,
                    )

        # ── Step 5: Neighbor enumeration ─────────────────────────────
        neighbors = self._get_prioritized_neighbors(node_id)
        fan_out_count = 0

        for neighbor_id in neighbors:
            if neighbor_id in self._visited:
                continue

            fan_out_count += 1
            neighbor_attrs = self._graph.nodes[neighbor_id]
            neighbor_is_expansion = neighbor_id in self._expansion_nodes

            auth_succeeded = self._attempt_neighbor_auth(
                src_node=node_id,
                dst_node=neighbor_id,
                src_attrs=node_attrs,
                dst_attrs=neighbor_attrs,
                fan_out_count=fan_out_count,
                arrival_time=arrival_time,
                is_expansion=neighbor_is_expansion,
            )

            if auth_succeeded:
                self._visited.add(neighbor_id)
                self._frontier.append(neighbor_id)

        # Update fan_out_count on all events from this node visit
        self._update_fan_out_count(visit_start_index, fan_out_count)

    # ------------------------------------------------------------------
    # Auth attempt helpers
    # ------------------------------------------------------------------

    def _attempt_neighbor_auth(
        self,
        src_node: str,
        dst_node: str,
        src_attrs: dict,
        dst_attrs: dict,
        fan_out_count: int,
        arrival_time: datetime,
        is_expansion: bool,
    ) -> bool:
        """
        Attempt authentication against a neighbor node using the protocol
        fallback sequence. Returns True if a real (non-hallucinated) success
        was achieved and the node should be enqueued.
        """
        node_type = dst_attrs.get("node_type", "workstation")
        fallback_key = NODE_TYPE_FALLBACK_CATEGORY.get(node_type, "windows_host")
        protocols = self._fallback_sequences.get(fallback_key, ["ntlm"])

        for protocol in protocols:
            for retry in range(self._max_auth_retries):
                event_time = self._velocity.advance()
                dwell = int(
                    (event_time - arrival_time).total_seconds() * 1000
                )

                # Determine auth outcome
                success, failure_reason = self._roll_auth_outcome(
                    dst_node=dst_node,
                    dst_attrs=dst_attrs,
                    protocol=protocol,
                )

                event = self._make_auth_event(
                    event_time=event_time,
                    src_node=src_node,
                    src_attrs=src_attrs,
                    dst_node=dst_node,
                    dst_attrs=dst_attrs,
                    protocol=protocol,
                    success=success,
                    failure_reason=failure_reason,
                    dwell_ms=dwell,
                    fan_out_count=fan_out_count,
                    is_expansion=is_expansion,
                )
                self._events.append(event)
                self._sysmon_records.append(
                    self._make_sysmon_event3(event, dst_attrs)
                )

                if success:
                    # Apply hallucination check (FIRST, per spec ordering)
                    result = self._hallucination.check(
                        node_id=dst_node,
                        node_type=node_type,
                        username=self._username,
                        current_credential_store=self._credential_store,
                    )

                    if result.is_hallucination:
                        # Emit backtrack event
                        self._emit_backtrack(
                            src_node=src_node,
                            src_attrs=src_attrs,
                            dst_node=dst_node,
                            dst_attrs=dst_attrs,
                            arrival_time=arrival_time,
                            fan_out_count=fan_out_count,
                        )
                        return False

                    # Real success — process credential harvest
                    if result.harvested_credential is not None:
                        self._credential_store.append(
                            result.harvested_credential
                        )
                        self._emit_credential_harvest_event(
                            event_time=self._velocity.current_time(),
                            src_node=src_node,
                            src_attrs=src_attrs,
                            dst_node=dst_node,
                            dst_attrs=dst_attrs,
                            credential=result.harvested_credential,
                            dwell_ms=dwell,
                            fan_out_count=fan_out_count,
                            phase="lateral",
                        )

                    return True

            # All retries for this protocol exhausted — try next protocol

        # All protocols exhausted — emit backtrack
        self._emit_backtrack(
            src_node=src_node,
            src_attrs=src_attrs,
            dst_node=dst_node,
            dst_attrs=dst_attrs,
            arrival_time=arrival_time,
            fan_out_count=fan_out_count,
        )
        return False

    def _attempt_auth(
        self,
        src_node: str,
        dst_node: str,
        node_attrs: dict,
        arrival_time: datetime,
        is_expansion: bool,
        is_file_server_auth: bool = False,
    ) -> bool:
        """
        Single auth attempt (no fallback sequence) used for file server
        node-level authentication before file access events are generated.
        Returns True on real success.
        """
        src_attrs = self._graph.nodes[src_node]
        protocols = node_attrs.get("auth_protocols", ["ntlm"])
        protocol = protocols[0]

        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)

        success, failure_reason = self._roll_auth_outcome(
            dst_node=dst_node,
            dst_attrs=node_attrs,
            protocol=protocol,
        )

        event = self._make_auth_event(
            event_time=event_time,
            src_node=src_node,
            src_attrs=src_attrs,
            dst_node=dst_node,
            dst_attrs=node_attrs,
            protocol=protocol,
            success=success,
            failure_reason=failure_reason,
            dwell_ms=dwell,
            fan_out_count=0,
            is_expansion=is_expansion,
        )
        self._events.append(event)
        self._sysmon_records.append(
            self._make_sysmon_event3(event, node_attrs)
        )

        if not success:
            return False

        result = self._hallucination.check(
            node_id=dst_node,
            node_type=node_attrs.get("node_type", "workstation"),
            username=self._username,
            current_credential_store=self._credential_store,
        )
        return not result.is_hallucination

    def _roll_auth_outcome(
        self,
        dst_node: str,
        dst_attrs: dict,
        protocol: str,
    ) -> tuple[bool, str | None]:
        """
        Determine whether an auth attempt succeeds or fails.

        Success probability is influenced by whether the attacker has a
        credential that meets the node's required_privilege. Without
        sufficient privilege, the result is access_denied rather than
        auth_failed — a meaningfully different signal.
        """
        required = dst_attrs.get("required_privilege", "standard_user")
        max_privilege = self._max_credential_privilege()

        from generator.graph_builder import PRIVILEGE_HIERARCHY
        required_level = PRIVILEGE_HIERARCHY.index(required) \
            if required in PRIVILEGE_HIERARCHY else 0
        current_level = PRIVILEGE_HIERARCHY.index(max_privilege) \
            if max_privilege in PRIVILEGE_HIERARCHY else 0

        if current_level < required_level:
            # Insufficient privilege — access_denied
            return False, "access_denied"

        # Sufficient privilege — 60% success base rate (models real-world
        # credential validity rates in lateral movement scenarios)
        if self._rng.random() < 0.60:
            return True, None
        else:
            return False, "auth_failed"

    def _max_credential_privilege(self) -> str:
        """Return the highest privilege level currently in the credential store."""
        from generator.graph_builder import PRIVILEGE_HIERARCHY
        if not self._credential_store:
            return "standard_user"
        levels = [
            PRIVILEGE_HIERARCHY.index(c.privilege)
            for c in self._credential_store
            if c.privilege in PRIVILEGE_HIERARCHY
        ]
        return PRIVILEGE_HIERARCHY[max(levels)] if levels else "standard_user"

    # ------------------------------------------------------------------
    # Neighbor selection
    # ------------------------------------------------------------------

    def _get_prioritized_neighbors(self, node_id: str) -> list[str]:
        """
        Return all ACL-permitted neighbors sorted by node type priority.

        Returns ALL graph successors (ACL-permitted connections) regardless
        of current credential privilege. Privilege determines auth OUTCOME
        (success vs access_denied) inside _attempt_neighbor_auth, not
        whether the attempt is made. The AI attacker probes every reachable
        neighbor — that exhaustive probing is the core behavioral signature.

        Per spec Section 9: "Enumerates all ACL-permitted neighbors reachable
        under the current credential store and privilege levels" — "reachable"
        here means ACL-permitted, not privilege-sufficient.
        """
        all_neighbors = list(self._graph.successors(node_id))

        def priority_key(n: str) -> int:
            nt = self._graph.nodes[n].get("node_type", "workstation")
            try:
                return self._priority_order.index(nt)
            except ValueError:
                return len(self._priority_order)

        return sorted(all_neighbors, key=priority_key)

    # ------------------------------------------------------------------
    # Event emitters
    # ------------------------------------------------------------------

    def _emit_dns_event(
        self,
        node_id: str,
        node_attrs: dict,
        arrival_time: datetime,
        is_expansion: bool,
    ) -> None:
        """Emit a dns_query event for a newly discovered host."""
        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)
        fqdn = node_attrs.get("fqdn", f"{node_id}.corp.internal")
        foothold_attrs = self._graph.nodes[self._foothold_node]

        # dns_query + scope_expansion is not a valid combination per schema.
        # DNS enumeration events always use dns_enumeration regardless of
        # whether the target is a scope expansion node. Scope expansion
        # labeling applies to service_probe and auth events at those nodes.
        attack_step = "dns_enumeration"

        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=self._foothold_node,
            src_ip=foothold_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=node_id,
            dst_ip=node_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT["dns"],
            user=self._username,
            event_type="dns_query",
            protocol="dns",
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=True,
            agent_type="ai_attacker",
            enum_phase="enumeration",
            attack_step=attack_step,
            ttp=ATTACK_STEP_TTP[attack_step],
            is_attack=True,
            dwell_ms=dwell,
            fan_out_count=0,
        )
        self._events.append(event)

        # Sysmon Event 22 (DNS query)
        self._sysmon_records.append({
            "EventID": 22,
            "TimeCreated": _fmt_ts(event_time),
            "host": self._foothold_node,
            "QueryName": fqdn,
            "QueryResults": node_attrs.get("ip_address", "0.0.0.0"),
            "Image": self._attack_framework_image,
            "ProcessId": self._attack_framework_pid,
            "session_id": self._session_id,
        })

    def _emit_service_probe(
        self,
        node_id: str,
        node_attrs: dict,
        service: str,
        arrival_time: datetime,
        is_expansion: bool,
    ) -> None:
        """Emit a service_probe event for one service on the current node."""
        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)
        foothold_attrs = self._graph.nodes[self._foothold_node]

        attack_step = "scope_expansion" if is_expansion else "service_discovery"

        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=self._foothold_node,
            src_ip=foothold_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=node_id,
            dst_ip=node_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT.get(service, 80),
            user=self._username,
            event_type="service_probe",
            protocol=service,
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=True,
            agent_type="ai_attacker",
            enum_phase="enumeration",
            attack_step=attack_step,
            ttp=ATTACK_STEP_TTP[attack_step],
            is_attack=True,
            dwell_ms=dwell,
            fan_out_count=0,
        )
        self._events.append(event)
        self._sysmon_records.append(
            self._make_sysmon_event3(event, node_attrs)
        )

    def _emit_kerberos_tgt(
        self,
        node_id: str,
        node_attrs: dict,
        arrival_time: datetime,
    ) -> None:
        """Emit a kerberos_tgt_request event at a domain controller node."""
        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)
        foothold_attrs = self._graph.nodes[self._foothold_node]

        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=self._foothold_node,
            src_ip=foothold_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=node_id,
            dst_ip=node_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT["kerberos"],
            user=self._username,
            event_type="kerberos_tgt_request",
            protocol="kerberos",
            logon_type=3,
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=True,
            agent_type="ai_attacker",
            enum_phase="enumeration",
            attack_step="auth_test",
            ttp=ATTACK_STEP_TTP["auth_test"],
            is_attack=True,
            dwell_ms=dwell,
            fan_out_count=0,
        )
        self._events.append(event)

    def _emit_file_access(
        self,
        node_id: str,
        node_attrs: dict,
        arrival_time: datetime,
        is_expansion: bool,
    ) -> None:
        """
        Emit a file_access event and independently roll file credential harvest.
        """
        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)
        foothold_attrs = self._graph.nodes[self._foothold_node]

        object_name = f"\\\\{node_id}\\C$"
        attack_step = "scope_expansion" if is_expansion else "service_discovery"

        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=self._foothold_node,
            src_ip=foothold_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=node_id,
            dst_ip=node_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT["smb"],
            user=self._username,
            event_type="file_access",
            protocol="smb",
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            object_name=object_name,
            success=True,
            bytes_in=self._rng.randint(1024, 65536),
            bytes_out=self._rng.randint(512, 8192),
            agent_type="ai_attacker",
            enum_phase="enumeration",
            attack_step=attack_step,
            ttp=ATTACK_STEP_TTP[attack_step],
            is_attack=True,
            dwell_ms=dwell,
            fan_out_count=0,
        )
        self._events.append(event)

        # Independent file credential harvest roll
        harvested = self._hallucination.check_file_harvest(
            node_id=node_id,
            node_type=node_attrs.get("node_type", "file_server"),
            username=self._username,
            current_credential_store=self._credential_store,
        )
        if harvested is not None:
            self._credential_store.append(harvested)
            self._emit_credential_harvest_event(
                event_time=self._velocity.current_time(),
                src_node=self._foothold_node,
                src_attrs=foothold_attrs,
                dst_node=node_id,
                dst_attrs=node_attrs,
                credential=harvested,
                dwell_ms=dwell,
                fan_out_count=0,
                phase="enumeration",
            )

    def _emit_backtrack(
        self,
        src_node: str,
        src_attrs: dict,
        dst_node: str,
        dst_attrs: dict,
        arrival_time: datetime,
        fan_out_count: int,
    ) -> None:
        """Emit a network_connection backtrack event."""
        event_time = self._velocity.advance()
        dwell = int((event_time - arrival_time).total_seconds() * 1000)

        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=445,
            user=self._username,
            event_type="network_connection",
            protocol="smb",
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=False,
            failure_reason="host_unreachable",
            agent_type="ai_attacker",
            enum_phase="lateral",
            attack_step="backtrack",
            ttp=ATTACK_STEP_TTP["backtrack"],
            is_attack=True,
            dwell_ms=dwell,
            fan_out_count=fan_out_count,
        )
        self._events.append(event)
        self._sysmon_records.append(
            self._make_sysmon_event3(event, dst_attrs)
        )

    def _emit_credential_harvest_event(
        self,
        event_time: datetime,
        src_node: str,
        src_attrs: dict,
        dst_node: str,
        dst_attrs: dict,
        credential: Credential,
        dwell_ms: int,
        fan_out_count: int,
        phase: str,
    ) -> None:
        """Emit a canonical credential_harvest auth_attempt event."""
        event = Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=445,
            user=self._username,
            event_type="auth_attempt",
            protocol="ntlm",
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=True,
            credential_id=credential.credential_id,
            agent_type="ai_attacker",
            enum_phase=phase,
            attack_step="credential_harvest",
            ttp=ATTACK_STEP_TTP["credential_harvest"],
            is_attack=True,
            dwell_ms=dwell_ms,
            fan_out_count=fan_out_count,
        )
        self._events.append(event)

    # ------------------------------------------------------------------
    # Auth event factory
    # ------------------------------------------------------------------

    def _make_auth_event(
        self,
        event_time: datetime,
        src_node: str,
        src_attrs: dict,
        dst_node: str,
        dst_attrs: dict,
        protocol: str,
        success: bool,
        failure_reason: str | None,
        dwell_ms: int,
        fan_out_count: int,
        is_expansion: bool,
    ) -> Event:
        """Construct a canonical auth_attempt Event."""
        logon_id = _make_logon_id(self._rng) if success else None
        failure_code = FAILURE_CODE.get(failure_reason) if failure_reason else None

        return Event(
            timestamp=_fmt_ts(event_time),
            session_id=self._session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT.get(protocol, 445),
            user=self._username,
            event_type="auth_attempt",
            protocol=protocol,
            logon_type=AUTH_LOGON_TYPE.get(protocol, 3),
            logon_id=logon_id,
            process_id=self._attack_framework_pid,
            process_name="python.exe",
            success=success,
            failure_reason=failure_reason,
            failure_code=failure_code,
            bytes_in=self._rng.randint(200, 800) if success else 0,
            bytes_out=self._rng.randint(100, 400),
            agent_type="ai_attacker",
            enum_phase="lateral",
            attack_step="auth_test",
            ttp=ATTACK_STEP_TTP["auth_test"],
            is_attack=True,
            dwell_ms=dwell_ms,
            fan_out_count=fan_out_count,
        )

    # ------------------------------------------------------------------
    # Sysmon record factories
    # ------------------------------------------------------------------

    def _make_sysmon_event3(self, event: Event, dst_attrs: dict) -> dict:
        """Construct a Sysmon Event 3 (network connection) record."""
        return {
            "EventID": 3,
            "TimeCreated": event.timestamp,
            "host": self._foothold_node,
            "SourceIp": event.src_ip,
            "SourcePort": event.src_port,
            "DestinationIp": event.dst_ip,
            "DestinationPort": event.dst_port,
            "Protocol": "tcp",
            "Initiated": True,
            "Image": self._attack_framework_image,
            "ProcessId": self._attack_framework_pid,
            "ParentProcessId": 1204,
            "session_id": self._session_id,
        }

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    def _update_fan_out_count(
        self, visit_start_index: int, fan_out_count: int
    ) -> None:
        """
        Backfill fan_out_count on all events generated during this node visit.

        Events are emitted incrementally during _visit_node with fan_out_count=0
        as a placeholder (the final count is not known until all neighbors are
        enumerated). This method updates all events from this visit once the
        final count is known.

        Uses visit_start_index (the length of self._events at the start of
        _visit_node) to identify exactly which events belong to this visit.
        This is precise and does not rely on fan_out_count values as a proxy,
        fixing the heuristic stop-condition bug where the backward scan could
        terminate early if a prior visit's events had non-zero fan_out counts.
        """
        if fan_out_count == 0:
            return
        # Update only events emitted during this visit (index-based slice)
        for event in self._events[visit_start_index:]:
            if event.is_attack:
                object.__setattr__(event, "fan_out_count", fan_out_count)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _fmt_ts(ts: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _make_logon_id(rng: random.Random) -> str:
    """Generate a plausible Windows LUID hex string."""
    return f"0x{rng.randint(0x1000, 0xFFFFFF):X}"