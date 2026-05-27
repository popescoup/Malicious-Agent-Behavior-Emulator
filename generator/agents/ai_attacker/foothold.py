"""
MABE AI Attacker — Foothold Initializer
=========================================

Selects the session's starting node, seeds the credential store with one
standard_user credential, and emits the forensic artifacts that mark the
assumed-breach entry point: a Sysmon Event 1 (attack framework process
created) and two Sysmon Event 7 (image loaded) records, followed by a
single canonical foothold_init Event.

EMPIRICAL GROUNDING
-------------------
Source: GTG-1002 (November 2025) — "The opening stages of reconnaissance
happened outside the target's environment — defenders' first visibility comes
when the attacker is already executing against their infrastructure."
→ Justifies the assumed-breach framing: Phase 1 is asserted, not simulated.
The foothold_init event marks the point at which internal artifacts begin.

Source: GTG-1002 — "Claude Code and MCP tools to execute 80–90% of tactical
operations autonomously." → The attack framework process (python.exe) models
this autonomous execution framework. Motivated further by the Dragos water
utility finding of a 17,000-line Python-based post-compromise framework.

SYSMON ARTIFACTS
----------------
The foothold initializer generates three Sysmon records that will be written
by the EVTX formatter into sysmon_events.json for the session bundle:

  Event 1 (Process Created):
    - attack framework process (python.exe) spawned from a plausible cover
      process (explorer.exe)
    - ProcessId is fixed for the session — all subsequent Sysmon Event 3
      and Event 13 records reference this PID

  Event 7 (Image Loaded) × 2:
    - ws2_32.dll  — Windows Sockets, required for any network activity
    - dnsapi.dll  — DNS resolution
    These are always loaded by any network-capable Python process and are
    forensically plausible without requiring framework-specific knowledge.

These records are attached to the returned FootholdResult and passed through
to the EVTX formatter — they are not canonical Event objects.

SESSION STATE
-------------
v1.0: Every session cold-starts from a single foothold. Session state loading
(resuming from a prior session's credential store and BFS frontier) is a
v2.0 feature. The credential store is seeded with exactly one standard_user
credential at initialisation.
"""

from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime

import networkx as nx

from generator.agents.ai_attacker.velocity import VelocityModel
from schema.event import Event, ATTACK_STEP_TTP

# ---------------------------------------------------------------------------
# Credential store entry
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    """
    A single harvested or seeded credential in the attacker's store.

    Fields
    ------
    credential_id : str
        Unique identifier (e.g. 'cred_001'). Referenced in Event.credential_id.
    username : str
        The account this credential belongs to.
    privilege : str
        One of 'standard_user', 'service_account', 'domain_admin'.
    source_node : str | None
        Node ID where this credential was harvested. None for the seeded
        foothold credential (origin is outside the simulation scope).
    """
    credential_id: str
    username: str
    privilege: str
    source_node: str | None = None


# ---------------------------------------------------------------------------
# Foothold result
# ---------------------------------------------------------------------------

@dataclass
class FootholdResult:
    """
    The complete output of FootholdInitializer.initialize().

    Passed directly to the BFS traversal agent to seed its initial state.

    Fields
    ------
    foothold_node : str
        Node ID of the starting workstation.
    session_id : str
        UUID for this attack session — shared by all events in the session.
    attack_framework_pid : int
        PID of the attack framework process. All Sysmon Event 3 and Event 13
        records in this session reference this PID.
    attack_framework_image : str
        Full image path of the attack framework process (e.g.
        'C:\\Users\\j.harrison\\AppData\\Local\\Temp\\python.exe').
    credential_store : list[Credential]
        Initial credential store containing exactly one standard_user
        credential seeded from the foothold node.
    sysmon_records : list[dict]
        Sysmon Event 1 and Event 7 records for the EVTX formatter. These are
        raw dicts (not canonical Event objects) because Sysmon records have
        a different structure from the canonical schema.
    foothold_event : Event
        The single canonical foothold_init Event marking session start.
    """
    foothold_node: str
    session_id: str
    attack_framework_pid: int
    attack_framework_image: str
    credential_store: list[Credential]
    sysmon_records: list[dict]
    foothold_event: Event


# ---------------------------------------------------------------------------
# FootholdInitializer
# ---------------------------------------------------------------------------

# Attack framework image path template — filled with the foothold username
_FRAMEWORK_IMAGE_TEMPLATE = (
    "C:\\Users\\{username}\\AppData\\Local\\Temp\\python.exe"
)
_PARENT_IMAGE = "C:\\Windows\\explorer.exe"
_PARENT_PID = 1204  # fixed plausible explorer.exe PID

# DLLs loaded at framework initialisation — minimal realistic set
_IMAGE_LOADS = [
    ("ws2_32.dll", "C:\\Windows\\System32\\ws2_32.dll"),
    ("dnsapi.dll", "C:\\Windows\\System32\\dnsapi.dll"),
]


class FootholdInitializer:
    """
    Selects the foothold node and emits session-initialisation artifacts.

    Parameters
    ----------
    graph : nx.DiGraph
        The shared network graph from graph_builder.build_graph().
    vocab : dict
        Vocabulary bundle from vocabulary.json.
    params : dict
        The ai_attacker section of behavioral_params.yaml.
    rng : random.Random
        Seeded RNG from simulate.py. Controls foothold node selection,
        username selection, and PID generation.
    velocity : VelocityModel
        The session's VelocityModel instance. start_session() is called
        here so timestamp accumulation begins at foothold initialisation.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        vocab: dict,
        params: dict,
        rng: random.Random,
        velocity: VelocityModel,
    ) -> None:
        self._graph = graph
        self._vocab = vocab
        self._params = params
        self._rng = rng
        self._velocity = velocity

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def initialize(self, session_start: datetime) -> FootholdResult:
        """
        Initialise the attack session and return the FootholdResult.

        Steps (in order):
        1. Start the velocity model clock at session_start.
        2. Select a random corporate-segment workstation as the foothold.
        3. Select a username from the general_staff or developer pool
           (most likely account type to have a compromised workstation).
        4. Assign a session UUID and attack framework PID.
        5. Seed the credential store with one standard_user credential.
        6. Emit Sysmon Event 1 (process created) and Event 7 × 2 (image loads).
        7. Advance the clock once and emit the canonical foothold_init Event.

        Parameters
        ----------
        session_start : datetime
            Session start time provided by simulate.py.

        Returns
        -------
        FootholdResult
        """
        # Step 1 — start velocity clock
        self._velocity.start_session(session_start)

        # Step 2 — select foothold node (corporate workstation only)
        foothold_node = self._select_foothold_node()
        node_attrs = self._graph.nodes[foothold_node]

        # Step 3 — select username
        username = self._select_username()

        # Step 4 — session identity
        session_id = str(uuid.uuid4())
        attack_framework_pid = self._rng.randint(2000, 8000)
        framework_image = _FRAMEWORK_IMAGE_TEMPLATE.format(username=username)

        # Step 5 — seed credential store
        credential_store = self._seed_credential_store(
            username=username,
            foothold_node=foothold_node,
        )

        # Step 6 — Sysmon artifacts
        sysmon_records = self._make_sysmon_records(
            session_id=session_id,
            session_start=session_start,
            foothold_node=foothold_node,
            username=username,
            attack_framework_pid=attack_framework_pid,
            framework_image=framework_image,
        )

        # Step 7 — advance clock and emit canonical foothold_init Event
        event_time = self._velocity.advance()
        foothold_event = self._make_foothold_event(
            session_id=session_id,
            timestamp=event_time,
            foothold_node=foothold_node,
            node_attrs=node_attrs,
            username=username,
            credential_id=credential_store[0].credential_id,
            attack_framework_pid=attack_framework_pid,
            framework_image=framework_image,
        )

        return FootholdResult(
            foothold_node=foothold_node,
            session_id=session_id,
            attack_framework_pid=attack_framework_pid,
            attack_framework_image=framework_image,
            credential_store=credential_store,
            sysmon_records=sysmon_records,
            foothold_event=foothold_event,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _select_foothold_node(self) -> str:
        """
        Select a random workstation in the corporate segment as the foothold.

        Per the spec: "Selects the starting node (a randomly chosen corporate
        segment workstation)." Only workstations are valid foothold nodes —
        the assumed-breach framing models a compromised end-user machine.
        """
        candidates = [
            n for n, attrs in self._graph.nodes(data=True)
            if attrs.get("node_type") == "workstation"
            and attrs.get("segment") == "corporate"
        ]
        if not candidates:
            raise ValueError(
                "Graph contains no corporate-segment workstation nodes. "
                "Cannot initialise foothold."
            )
        return self._rng.choice(candidates)

    def _select_username(self) -> str:
        """
        Select a username for the compromised account.

        Draws from general_staff (50% weight) and developer (20% weight)
        pools — the most likely account types to have a compromised workstation.
        Admin accounts (10%) are excluded as they are higher-value targets
        that would typically have stricter controls and monitoring.
        Analyst accounts (20%) are also included for coverage.
        """
        usernames = self._vocab.get("usernames", {})
        # Weighted pool: general_staff × 5, developer × 2, analyst × 2
        pool: list[str] = (
            usernames.get("general_staff", []) * 5
            + usernames.get("developer", []) * 2
            + usernames.get("analyst", []) * 2
        )
        if not pool:
            raise ValueError(
                "Vocabulary contains no usernames for foothold account selection."
            )
        return self._rng.choice(pool)

    def _seed_credential_store(
        self,
        username: str,
        foothold_node: str,
    ) -> list[Credential]:
        """
        Seed the credential store with one standard_user credential.

        Per the spec: "seeds the credential store with one credential of type
        windows_auth at privilege level standard_user."

        source_node is None because the foothold credential's origin is
        outside the simulation scope (assumed breach).
        """
        initial_privilege: str = self._params.get(
            "initial_credential_privilege", "standard_user"
        )
        return [
            Credential(
                credential_id="cred_001",
                username=username,
                privilege=initial_privilege,
                source_node=None,
            )
        ]

    def _make_sysmon_records(
        self,
        session_id: str,
        session_start: datetime,
        foothold_node: str,
        username: str,
        attack_framework_pid: int,
        framework_image: str,
    ) -> list[dict]:
        """
        Generate Sysmon Event 1 (process created) and Event 7 × 2 (image loads).

        These are raw dicts for the EVTX formatter, not canonical Event objects.
        Timestamps are derived from session_start with small offsets to place
        them before the first canonical event — they represent the framework
        launching before any network activity begins.
        """
        node_attrs = self._graph.nodes[foothold_node]
        ts_event1 = _fmt_timestamp(session_start)
        ts_event7_ws2 = _fmt_timestamp(
            session_start.replace(
                microsecond=session_start.microsecond + 54000
                if session_start.microsecond + 54000 < 1_000_000
                else 999000
            )
        )
        ts_event7_dns = _fmt_timestamp(
            session_start.replace(
                microsecond=session_start.microsecond + 65000
                if session_start.microsecond + 65000 < 1_000_000
                else 999000
            )
        )

        records: list[dict] = []

        # Sysmon Event 1 — Process Created
        records.append({
            "EventID": 1,
            "TimeCreated": ts_event1,
            "host": foothold_node,
            "Image": framework_image,
            "CommandLine": f'python.exe -c "import socket, subprocess, os; '
                           f'[...]"',
            "ParentImage": _PARENT_IMAGE,
            "ParentProcessId": _PARENT_PID,
            "ProcessId": attack_framework_pid,
            "User": username,
            "session_id": session_id,
        })

        # Sysmon Event 7 — Image Loaded (ws2_32.dll)
        records.append({
            "EventID": 7,
            "TimeCreated": ts_event7_ws2,
            "host": foothold_node,
            "Image": framework_image,
            "ProcessId": attack_framework_pid,
            "ImageLoaded": _IMAGE_LOADS[0][1],
            "Signed": True,
            "Signature": "Microsoft Windows",
            "session_id": session_id,
        })

        # Sysmon Event 7 — Image Loaded (dnsapi.dll)
        records.append({
            "EventID": 7,
            "TimeCreated": ts_event7_dns,
            "host": foothold_node,
            "Image": framework_image,
            "ProcessId": attack_framework_pid,
            "ImageLoaded": _IMAGE_LOADS[1][1],
            "Signed": True,
            "Signature": "Microsoft Windows",
            "session_id": session_id,
        })

        return records

    def _make_foothold_event(
        self,
        session_id: str,
        timestamp: datetime,
        foothold_node: str,
        node_attrs: dict,
        username: str,
        credential_id: str,
        attack_framework_pid: int,
        framework_image: str,
    ) -> Event:
        """
        Emit the single canonical foothold_init Event.

        Represents the assumed-breach entry point — the moment at which
        internal artifacts begin. Labeled:
            attack_step: foothold_init
            ttp:         T1078.002 (Valid Accounts: Domain Accounts)
            enum_phase:  enumeration
        """
        return Event(
            timestamp=_fmt_timestamp(timestamp),
            session_id=session_id,
            src_host=foothold_node,
            src_ip=node_attrs.get("ip_address", "0.0.0.0"),
            src_port=self._rng.randint(49152, 65535),
            dst_host=foothold_node,
            dst_ip=node_attrs.get("ip_address", "0.0.0.0"),
            dst_port=445,  # SMB — workstation self-connection at session start
            user=username,
            event_type="auth_attempt",
            protocol="ntlm",
            logon_type=2,  # interactive logon at the foothold host
            logon_id=_make_logon_id(self._rng),
            process_id=attack_framework_pid,
            process_name="python.exe",
            success=True,
            bytes_in=self._rng.randint(200, 600),
            bytes_out=self._rng.randint(100, 300),
            agent_type="ai_attacker",
            enum_phase="enumeration",
            attack_step="foothold_init",
            ttp=ATTACK_STEP_TTP["foothold_init"],
            is_attack=True,
            dwell_ms=int(self._velocity.next_delay_ms()),
            fan_out_count=0,
        )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _fmt_timestamp(ts: datetime) -> str:
    """Format a datetime as ISO 8601 with millisecond precision and Z suffix."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def _make_logon_id(rng: random.Random) -> str:
    """Generate a plausible Windows LUID hex string."""
    return f"0x{rng.randint(0x1000, 0xFFFFFF):X}"