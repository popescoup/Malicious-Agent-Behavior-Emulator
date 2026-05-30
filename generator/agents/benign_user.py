"""
MABE Benign User Agent
======================

Simulates a single normal user account performing routine work activity
against the network graph. Produces low-velocity, purposeful, habitual
traversal across a small consistent set of hosts — the behavioral baseline
against which the AI attacker's signatures are detected.

Behavioral model adapted from LMDG's Sessions Scheduler and Sessions Executor
(arXiv 2508.02942). See Section 2, Source 6 and Section 9 of the spec.

DESIGN
------
BenignUserAgent is initialised once per simulated user with:
  - A role sampled from the role distribution
  - A home workstation node
  - A small set of typical destination nodes drawn from the role's
    typical_destinations list

run_session() accepts a session start datetime and a seeded random.Random
instance from simulate.py, keeping the agent fully stateless with respect
to the calendar and RNG. This guarantees reproducible output when simulate.py
controls the seed.

Each call to run_session() produces one independent session — a list of
Event objects representing one continuous work session for this user.

KEY BEHAVIORAL PROPERTIES
--------------------------
- Low velocity: median 3 minutes between events (vs. 800ms for AI attacker)
- Small, consistent host set: typically 3-5 hosts per session
- High revisit rate: 75% chance of returning to a previously visited host
- Auth success rate: ~98% (2% failure rate models expired/mistyped passwords)
- fan_out_count rarely exceeds 2-3 per session
- No segment exploration: users stay within their role's typical destinations
- Business-hours weighted session timing (handled by simulate.py)
"""

from __future__ import annotations

import math
import random
import uuid
from datetime import datetime, timedelta

import networkx as nx

from schema.event import Event

# ---------------------------------------------------------------------------
# Service → destination port mapping
# ---------------------------------------------------------------------------

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
    "auth_failed":   "0xC000006D",
    "access_denied": "0xC0000022",
    "timeout":       "0xC000023A",
}


# ---------------------------------------------------------------------------
# BenignUserAgent
# ---------------------------------------------------------------------------

class BenignUserAgent:
    """
    Simulates a single normal user account performing routine work activity.

    Parameters
    ----------
    graph : nx.DiGraph
        The shared network graph built by graph_builder.build_graph().
    vocab : dict
        The vocabulary bundle loaded from vocabulary.json.
    params : dict
        The benign_user section of behavioral_params.yaml, loaded and passed
        in by simulate.py.
    rng : random.Random
        Seeded RNG instance provided by simulate.py. All randomness in this
        agent flows through this instance to guarantee reproducibility.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        vocab: dict,
        params: dict,
        rng: random.Random,
    ) -> None:
        self._graph = graph
        self._vocab = vocab
        self._params = params
        self._rng = rng

        # Assign role
        self._role = self._sample_role()

        # Assign username from the role's vocabulary pool
        username_pool = vocab.get("usernames", {}).get(self._role["name"], [])
        if not username_pool:
            raise ValueError(
                f"Vocabulary has no usernames for role '{self._role['name']}'"
            )
        self._username: str = rng.choice(username_pool)

        # Assign home workstation
        workstations = self._nodes_of_type("workstation")
        if not workstations:
            raise ValueError("Graph contains no workstation nodes.")
        self._home_node: str = rng.choice(workstations)

        # Build typical destination set for this user
        self._typical_destinations: list[str] = self._build_typical_destinations()

        # Session history — hosts ever visited across all sessions by this agent
        self._visited_hosts: set[str] = {self._home_node}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run_session(self, session_start: datetime) -> list[Event]:
        """
        Simulate one work session for this user.

        Parameters
        ----------
        session_start : datetime
            Session start time, provided by simulate.py. Expected to fall
            within business hours for realism, but not enforced here.

        Returns
        -------
        list[Event]
            Chronologically ordered list of Event objects for this session.
            All events share a session_id UUID generated at session start.
        """
        session_id = str(uuid.uuid4())
        events: list[Event] = []
        current_time: datetime = session_start

        # Session duration: 1–3 hours, sampled uniformly
        session_duration_s = self._rng.uniform(3600, 28800)
        session_end = session_start + timedelta(seconds=session_duration_s)

        current_node = self._home_node

        while current_time < session_end:
            dst_node = self._sample_destination(current_node)

            # Auth attempt toward destination
            auth_event = self._make_auth_event(
                session_id=session_id,
                timestamp=current_time,
                src_node=current_node,
                dst_node=dst_node,
            )
            events.append(auth_event)

            if auth_event.success:
                self._visited_hosts.add(dst_node)
                # _make_follow_on_events returns (event_list, final_datetime)
                follow_on_events, follow_on_end = self._make_follow_on_events(
                    session_id=session_id,
                    timestamp=current_time,
                    src_node=current_node,
                    dst_node=dst_node,
                )
                events.extend(follow_on_events)
                current_time = follow_on_end
                current_node = dst_node
            # On auth failure, user stays at current node

            # Inter-event delay before next action
            delay_ms = self._sample_delay_ms()
            current_time = _advance_time(current_time, delay_ms)

        return events

    @property
    def username(self) -> str:
        return self._username

    @property
    def role(self) -> str:
        return self._role["name"]

    @property
    def home_node(self) -> str:
        return self._home_node

    # ------------------------------------------------------------------
    # Internal helpers — initialisation
    # ------------------------------------------------------------------

    def _sample_role(self) -> dict:
        """Sample a role from the role distribution using weighted choice."""
        roles = self._params.get("roles", [])
        if not roles:
            raise ValueError("behavioral_params.yaml defines no benign_user roles.")
        weights = [r["weight"] for r in roles]
        return self._rng.choices(roles, weights=weights, k=1)[0]

    def _nodes_of_type(self, node_type: str) -> list[str]:
        """Return all node IDs of the given type from the graph."""
        return [
            n for n, attrs in self._graph.nodes(data=True)
            if attrs.get("node_type") == node_type
        ]

    def _build_typical_destinations(self) -> list[str]:
        """
        Build this user's set of typical destination nodes.

        Draws up to typical_host_count nodes from the node types listed in
        the role's typical_destinations. Excludes the home workstation.
        """
        typical_count: int = self._params.get("typical_host_count", 4)
        dest_types: list[str] = self._role.get("typical_destinations", ["workstation"])

        candidates: list[str] = []
        for node_type in dest_types:
            nodes = self._nodes_of_type(node_type)
            nodes = [n for n in nodes if n != self._home_node]
            candidates.extend(nodes)

        if not candidates:
            return [self._home_node]

        sample_size = min(typical_count, len(candidates))
        return self._rng.sample(candidates, sample_size)

    # ------------------------------------------------------------------
    # Internal helpers — session generation
    # ------------------------------------------------------------------

    def _sample_destination(self, current_node: str) -> str:
        """
        Sample the next destination node.

        Three-way weighted choice:
        - revisit_probability: return to a previously visited host
        - new_host_probability: access a host never visited before
        - remainder: choose from role's typical destinations
        """
        revisit_prob: float = self._params.get("revisit_probability", 0.75)
        new_host_prob: float = self._params.get("new_host_probability", 0.05)

        roll = self._rng.random()

        if roll < revisit_prob and self._visited_hosts:
            candidates = [h for h in self._visited_hosts if h != current_node]
            if candidates:
                return self._rng.choice(candidates)

        if roll < revisit_prob + new_host_prob:
            all_nodes = list(self._graph.nodes())
            unvisited = [n for n in all_nodes
                         if n not in self._visited_hosts and n != current_node]
            if unvisited:
                return self._rng.choice(unvisited)

        if self._typical_destinations:
            candidates = [n for n in self._typical_destinations if n != current_node]
            if candidates:
                return self._rng.choice(candidates)

        # Final fallback
        all_nodes = [n for n in self._graph.nodes() if n != current_node]
        return self._rng.choice(all_nodes) if all_nodes else current_node

    def _sample_delay_ms(self) -> float:
        """
        Sample inter-event delay in milliseconds from a lognormal distribution.

        Parameters: median=180000ms (3 min), sigma=1.2, floor=1000ms.
        """
        median_ms: float = self._params.get("inter_event_ms_median", 180000)
        sigma: float = self._params.get("inter_event_ms_sigma", 1.2)
        mu = math.log(median_ms)
        sample = math.exp(mu + sigma * self._rng.gauss(0, 1))
        return max(sample, 1000.0)

    def _make_auth_event(
        self,
        session_id: str,
        timestamp: datetime,
        src_node: str,
        dst_node: str,
    ) -> Event:
        """Generate an auth_attempt Event from src_node toward dst_node."""
        src_attrs = self._graph.nodes[src_node]
        dst_attrs = self._graph.nodes[dst_node]

        src_protocols = set(src_attrs.get("auth_protocols", []))
        dst_protocols = dst_attrs.get("auth_protocols", ["ntlm"])
        shared = [p for p in dst_protocols if p in src_protocols]
        protocol = shared[0] if shared else dst_protocols[0]

        failure_rate: float = self._params.get("auth_failure_rate", 0.02)
        success = self._rng.random() >= failure_rate

        failure_reason = None
        failure_code = None
        if not success:
            failure_reason = self._rng.choice(["auth_failed", "timeout"])
            failure_code = FAILURE_CODE.get(failure_reason)

        dst_port = _get_dst_port(dst_attrs, protocol)
        logon_type = AUTH_LOGON_TYPE.get(protocol, 3)
        logon_id = _make_logon_id(self._rng) if success else None

        return Event(
            timestamp=_fmt_timestamp(timestamp),
            session_id=session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=dst_port,
            user=self._username,
            event_type="auth_attempt",
            protocol=protocol,
            logon_type=logon_type,
            logon_id=logon_id,
            success=success,
            failure_reason=failure_reason,
            failure_code=failure_code,
            bytes_in=self._rng.randint(200, 800) if success else 0,
            bytes_out=self._rng.randint(100, 400),
            agent_type="benign_user",
            enum_phase="none",
            attack_step="none",
            ttp=None,
            is_attack=False,
            dwell_ms=0,
            fan_out_count=1,
        )

    def _make_follow_on_events(
        self,
        session_id: str,
        timestamp: datetime,
        src_node: str,
        dst_node: str,
    ) -> tuple[list[Event], datetime]:
        """
        Generate follow-on activity events after a successful auth.

        Returns
        -------
        tuple[list[Event], datetime]
            The list of follow-on events and the datetime of the final event.
            Returning the final datetime as a proper datetime object (not a
            formatted string) allows run_session() to advance current_time
            without string parsing.
        """
        dst_attrs = self._graph.nodes[dst_node]
        node_type = dst_attrs.get("node_type", "workstation")
        events: list[Event] = []

        count = self._rng.randint(1, 3)
        current_time: datetime = timestamp

        for _ in range(count):
            delay_ms = self._rng.uniform(5000, 60000)
            current_time = _advance_time(current_time, delay_ms)

            if node_type == "file_server":
                event = self._make_file_access_event(
                    session_id=session_id,
                    timestamp=current_time,
                    src_node=src_node,
                    dst_node=dst_node,
                )
            else:
                event = self._make_service_probe_event(
                    session_id=session_id,
                    timestamp=current_time,
                    src_node=src_node,
                    dst_node=dst_node,
                )
            events.append(event)

        return events, current_time

    def _make_file_access_event(
        self,
        session_id: str,
        timestamp: datetime,
        src_node: str,
        dst_node: str,
    ) -> Event:
        """Generate a file_access Event on a file server node."""
        src_attrs = self._graph.nodes[src_node]
        dst_attrs = self._graph.nodes[dst_node]

        dept_names = self._vocab.get("department_names", ["Shared"])
        dept = self._rng.choice(dept_names)
        object_name = f"\\\\{dst_node}\\{dept}"

        return Event(
            timestamp=_fmt_timestamp(timestamp),
            session_id=session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=SERVICE_PORT["smb"],
            user=self._username,
            event_type="file_access",
            protocol="smb",
            object_name=object_name,
            success=True,
            bytes_in=self._rng.randint(1024, 102400),
            bytes_out=self._rng.randint(512, 10240),
            agent_type="benign_user",
            enum_phase="none",
            attack_step="none",
            ttp=None,
            is_attack=False,
            dwell_ms=0,
            fan_out_count=1,
        )

    def _make_service_probe_event(
        self,
        session_id: str,
        timestamp: datetime,
        src_node: str,
        dst_node: str,
    ) -> Event:
        """Generate a service_probe Event on a non-file-server node."""
        src_attrs = self._graph.nodes[src_node]
        dst_attrs = self._graph.nodes[dst_node]

        services = dst_attrs.get("services", ["http"])
        service = self._rng.choice(services)
        dst_port = SERVICE_PORT.get(service, 80)

        return Event(
            timestamp=_fmt_timestamp(timestamp),
            session_id=session_id,
            src_host=src_node,
            src_ip=src_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=dst_node,
            dst_ip=dst_attrs.get("ip_address", "0.0.0.0"),
            dst_port=dst_port,
            user=self._username,
            event_type="service_probe",
            protocol=service,
            success=True,
            bytes_in=self._rng.randint(256, 4096),
            bytes_out=self._rng.randint(64, 1024),
            agent_type="benign_user",
            enum_phase="none",
            attack_step="none",
            ttp=None,
            is_attack=False,
            dwell_ms=0,
            fan_out_count=1,
        )


# ---------------------------------------------------------------------------
# Module-level utilities
# ---------------------------------------------------------------------------

def _fmt_timestamp(ts: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _advance_time(ts: datetime, delay_ms: float) -> datetime:
    """Return a new datetime advanced by delay_ms milliseconds."""
    return ts + timedelta(milliseconds=delay_ms)


def _get_dst_port(dst_attrs: dict, protocol: str) -> int:
    """Determine destination port from node services, falling back to protocol map."""
    services = dst_attrs.get("services", [])
    for service in services:
        port = SERVICE_PORT.get(service, 0)
        if port > 0:
            return port
    return SERVICE_PORT.get(protocol, 443)


def _make_logon_id(rng: random.Random) -> str:
    """Generate a plausible Windows LUID hex string."""
    return f"0x{rng.randint(0x1000, 0xFFFFFF):X}"