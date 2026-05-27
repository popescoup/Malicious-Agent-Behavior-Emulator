"""
MABE Canonical Event Schema
===========================
Version: 1.0.0

This module defines the canonical Event dataclass — the immutable internal
contract between the simulation layer (agents, labeler) and all output
formatters (Splunk CIM, EVTX JSON, LANL, Timesketch).

IMMUTABILITY POLICY
-------------------
This schema must not be changed without a version increment in CITATION.cff
and a corresponding migration of all formatter modules. Downstream code must
not add fields to Event instances at runtime — all fields must be declared here.

LITERAL TYPE ENFORCEMENT
-------------------------
Enumerated fields use typing.Literal to enable static type checking (mypy,
pyright). These types are NOT enforced at runtime by @dataclass alone.
Runtime enforcement for the most critical fields is provided by __post_init__.
See the "Allowed values" sections in each field's comment for the full set.

to_dict() BEHAVIOUR
-------------------
By default, to_dict() includes None values for optional fields. Pass
omit_none=True to suppress them — useful for formatters targeting formats
that treat absent fields differently from null fields (e.g. some Splunk CIM
contexts). The validation tool always calls to_dict() with omit_none=False
so that null-field checks are not silently skipped.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional


# ---------------------------------------------------------------------------
# Enumerated type aliases
# ---------------------------------------------------------------------------
# Defined at module level so formatters can import them for their own
# isinstance / membership checks without duplicating the literal sets.

EventType = Literal[
    "auth_attempt",
    "service_probe",
    "network_connection",
    "dns_query",
    "kerberos_tgt_request",
    "kerberos_ticket_request",
    "connection",
    "file_access",
    "registry_access",
]

FailureReason = Literal[
    "auth_failed",
    "access_denied",
    "no_route",
    "host_unreachable",
    "service_unavailable",
    "timeout",
    "credential_invalid",
]

AgentType = Literal[
    "benign_user",
    "ai_attacker",
]

EnumPhase = Literal[
    "enumeration",
    "lateral",
    "none",
]

AttackStep = Literal[
    "foothold_init",
    "service_discovery",
    "auth_test",
    "credential_harvest",
    "scope_expansion",
    "dns_enumeration",
    "backtrack",
    "hallucination_retry",
    "none",
]

# ---------------------------------------------------------------------------
# Valid event_type × attack_step combinations
# ---------------------------------------------------------------------------
# Mirrors the table in Section 6 of the spec. Used by __post_init__ and by
# validation/validate.py. Both consumers import this constant — do not
# duplicate it.
#
# attack_step "none" is always valid for benign events regardless of
# event_type, and is included in every entry for completeness.

VALID_EVENT_ATTACK_COMBINATIONS: dict[str, set[str]] = {
    "auth_attempt":           {"auth_test", "credential_harvest", "foothold_init",
                               "hallucination_retry", "none"},
    "service_probe":          {"service_discovery", "scope_expansion", "none"},
    "network_connection":     {"service_discovery", "scope_expansion", "backtrack", "none"},
    "dns_query":              {"dns_enumeration", "service_discovery", "none"},
    "kerberos_tgt_request":   {"auth_test", "foothold_init", "none"},
    "kerberos_ticket_request":{"auth_test", "credential_harvest", "none"},
    "file_access":            {"credential_harvest", "service_discovery",
                               "scope_expansion", "none"},
    "registry_access":        {"service_discovery", "none"},
    "connection":             {"backtrack", "none"},
}

# ---------------------------------------------------------------------------
# ATT&CK TTP mapping (attack_step → TTP ID)
# ---------------------------------------------------------------------------
# Centralised here so formatters and the labeler share a single source of
# truth. "backtrack" has no direct TTP — None is the correct value.

ATTACK_STEP_TTP: dict[str, Optional[str]] = {
    "foothold_init":      "T1078.002",
    "service_discovery":  "T1046",
    "dns_enumeration":    "T1018",
    "auth_test":          "T1110",
    "credential_harvest": "T1078",
    "scope_expansion":    "T1135",
    "backtrack":          None,
    "hallucination_retry":"T1110",
    "none":               None,
}

# ---------------------------------------------------------------------------
# Canonical Event dataclass
# ---------------------------------------------------------------------------

@dataclass
class Event:
    """
    A single canonical simulation event.

    Required fields have no default. Optional fields default to None.
    All enumerated fields are typed with Literal — use a static type checker
    (mypy / pyright) to catch invalid values at development time.
    __post_init__ provides runtime enforcement for agent_type, enum_phase,
    and event_type × attack_step combinations, which are the most consequential
    for downstream formatter and detection logic.
    """

    # ------------------------------------------------------------------
    # Temporal
    # ------------------------------------------------------------------

    timestamp: str
    """ISO 8601 with millisecond precision. Example: '2025-11-14T09:00:02.312Z'"""

    # ------------------------------------------------------------------
    # Session identity
    # ------------------------------------------------------------------

    session_id: str
    """UUID grouping all events from one agent run."""

    # ------------------------------------------------------------------
    # Network addressing
    # ------------------------------------------------------------------

    src_host: str
    """Source node ID from the network graph. Example: 'WS-042'"""

    src_ip: str
    """Source IP from vocabulary lookup. Example: '10.0.2.47'"""

    src_port: int
    """Ephemeral source port (randomly assigned)."""

    dst_host: str
    """Destination node ID from the network graph. Example: 'DB-02'"""

    dst_ip: str
    """Destination IP from vocabulary lookup. Example: '10.0.3.12'"""

    dst_port: int
    """Destination service port."""

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    user: str
    """Account performing the action. Example: 'j.harrison'"""

    # ------------------------------------------------------------------
    # Event classification
    # ------------------------------------------------------------------

    event_type: EventType
    """
    Class of event.
    Allowed: auth_attempt | service_probe | network_connection | dns_query |
             kerberos_tgt_request | kerberos_ticket_request | connection |
             file_access | registry_access
    """

    protocol: str
    """Network or authentication protocol. Example: 'kerberos', 'mssql'"""

    # ------------------------------------------------------------------
    # Windows logon context (optional)
    # ------------------------------------------------------------------

    logon_type: Optional[int] = None
    """
    Windows logon type integer.
    2 = interactive, 3 = network, 10 = remote interactive.
    Present on auth_attempt, kerberos_tgt_request, kerberos_ticket_request.
    """

    logon_id: Optional[str] = None
    """
    Windows LUID linking a logon session across Security Events 4624/4648/4769.
    Critical for SIFT session reconstruction — must never be None on 4624/4648
    events in the EVTX formatter. Example: '0x3E7'
    """

    # ------------------------------------------------------------------
    # Process context (optional)
    # ------------------------------------------------------------------

    process_id: Optional[int] = None
    """
    PID of the initiating process.
    Must be present on network_connection events (Sysmon Event 3).
    Always references the attack framework PID for ai_attacker events.
    """

    process_name: Optional[str] = None
    """
    Name of the initiating process.
    Must be present on network_connection events (Sysmon Event 3).
    Example: 'python.exe', 'net.exe'
    """

    # ------------------------------------------------------------------
    # Object access (optional)
    # ------------------------------------------------------------------

    object_name: Optional[str] = None
    """
    File, share, or resource accessed.
    Must be present on file_access events.
    Example: '\\\\FS-01\\Finance'
    """

    # ------------------------------------------------------------------
    # Outcome
    # ------------------------------------------------------------------

    success: bool = False
    """Whether the action succeeded."""

    failure_reason: Optional[FailureReason] = None
    """
    Reason for failure when success=False.
    Allowed: auth_failed | access_denied | no_route | host_unreachable |
             service_unavailable | timeout | credential_invalid
    Note: access_denied (valid credentials, insufficient permission) is
    distinct from auth_failed (wrong credentials) — they carry different
    ATT&CK signals (T1078 vs T1110).
    """

    failure_code: Optional[str] = None
    """
    Windows hex status code. Present for Windows auth events only.
    Example: '0xC000006D'
    """

    # ------------------------------------------------------------------
    # Credential tracking (optional)
    # ------------------------------------------------------------------

    credential_id: Optional[str] = None
    """
    Which credential was used — links to the attacker's credential store.
    Example: 'cred_004'
    """

    # ------------------------------------------------------------------
    # Network volume (optional, synthetic approximation)
    # ------------------------------------------------------------------

    bytes_in: Optional[int] = None
    """
    Bytes received — synthetic approximation only.
    Satisfies Splunk CIM Network Traffic data model.
    DO NOT use byte count distributions for behavioral analysis.
    """

    bytes_out: Optional[int] = None
    """
    Bytes sent — synthetic approximation only.
    See bytes_in note.
    """

    # ------------------------------------------------------------------
    # Ground truth and labeling metadata
    # ------------------------------------------------------------------

    agent_type: AgentType = "benign_user"
    """
    Producing agent.
    Allowed: benign_user | ai_attacker
    Runtime-enforced in __post_init__.
    """

    enum_phase: EnumPhase = "none"
    """
    Behavioral phase of the attack.
    Allowed: enumeration | lateral | none
    'none' for all benign_user events.
    Note: scope_expansion events are labeled 'enumeration' and distinguished
    via attack_step='scope_expansion' — enum_phase is a two-value behavioral
    classifier for attack events.
    Runtime-enforced in __post_init__.
    """

    attack_step: AttackStep = "none"
    """
    Specific step within the phase.
    Allowed: foothold_init | service_discovery | auth_test | credential_harvest |
             scope_expansion | dns_enumeration | backtrack | hallucination_retry | none
    'none' for all benign_user events and for attack events where no step applies.
    backtrack: agent reversing after exhausting all protocol options.
    hallucination_retry: agent re-attempting a node it falsely believed it accessed.
    """

    ttp: Optional[str] = None
    """
    MITRE ATT&CK technique ID.
    Derived from attack_step via ATTACK_STEP_TTP mapping.
    None for benign events and for backtrack steps.
    Example: 'T1046', 'T1110', 'T1078.002'
    """

    is_attack: bool = False
    """Ground truth label. True for all ai_attacker events, False for benign_user."""

    # ------------------------------------------------------------------
    # Behavioral metrics
    # ------------------------------------------------------------------

    dwell_ms: int = 0
    """Milliseconds at the current node before this event was generated."""

    fan_out_count: int = 0
    """Number of distinct neighbor nodes probed from the current node so far this session."""

    # ------------------------------------------------------------------
    # Runtime validation
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        """
        Runtime enforcement for the most consequential enumerated fields.

        Covers:
        - agent_type: two-value field; wrong value breaks label consistency
          checks throughout the pipeline.
        - enum_phase: two-value field for attack events; wrong value breaks
          all traversal-pattern detection queries.
        - event_type × attack_step: invalid combinations indicate a bug in
          agent logic and would produce malformed formatter output.

        Does NOT re-check Literal fields that are adequately caught by static
        type checkers (e.g. failure_reason, attack_step individually) — the
        goal is to catch logic bugs, not to duplicate type-checker work.
        """
        # agent_type
        valid_agent_types = {"benign_user", "ai_attacker"}
        if self.agent_type not in valid_agent_types:
            raise ValueError(
                f"Invalid agent_type '{self.agent_type}'. "
                f"Must be one of: {sorted(valid_agent_types)}"
            )

        # enum_phase
        valid_enum_phases = {"enumeration", "lateral", "none"}
        if self.enum_phase not in valid_enum_phases:
            raise ValueError(
                f"Invalid enum_phase '{self.enum_phase}'. "
                f"Must be one of: {sorted(valid_enum_phases)}"
            )

        # event_type × attack_step combination
        if self.event_type in VALID_EVENT_ATTACK_COMBINATIONS:
            valid_steps = VALID_EVENT_ATTACK_COMBINATIONS[self.event_type]
            if self.attack_step not in valid_steps:
                raise ValueError(
                    f"Invalid event_type × attack_step combination: "
                    f"'{self.event_type}' + '{self.attack_step}'. "
                    f"Valid attack_step values for '{self.event_type}': "
                    f"{sorted(valid_steps)}"
                )

        # is_attack / agent_type consistency
        if self.agent_type == "ai_attacker" and not self.is_attack:
            raise ValueError(
                "agent_type='ai_attacker' requires is_attack=True. "
                "All ai_attacker events are attack events."
            )
        if self.agent_type == "benign_user" and self.is_attack:
            raise ValueError(
                "agent_type='benign_user' requires is_attack=False. "
                "Benign user events are never attack events."
            )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self, omit_none: bool = False) -> dict:
        """
        Serialise the event to a plain dictionary.

        Parameters
        ----------
        omit_none : bool
            If False (default), None values are included in the output dict.
            The validation tool always uses omit_none=False so that null-field
            checks are not silently skipped.
            If True, None-valued optional fields are omitted — useful for
            formatters where absent fields behave differently from null fields.

        Returns
        -------
        dict
            All event fields as a flat dictionary. Field names match the
            canonical schema exactly (no CIM or EVTX renaming — that is the
            formatter's responsibility).
        """
        result = {
            "timestamp":      self.timestamp,
            "session_id":     self.session_id,
            "src_host":       self.src_host,
            "src_ip":         self.src_ip,
            "src_port":       self.src_port,
            "dst_host":       self.dst_host,
            "dst_ip":         self.dst_ip,
            "dst_port":       self.dst_port,
            "user":           self.user,
            "event_type":     self.event_type,
            "protocol":       self.protocol,
            "logon_type":     self.logon_type,
            "logon_id":       self.logon_id,
            "process_id":     self.process_id,
            "process_name":   self.process_name,
            "object_name":    self.object_name,
            "success":        self.success,
            "failure_reason": self.failure_reason,
            "failure_code":   self.failure_code,
            "credential_id":  self.credential_id,
            "bytes_in":       self.bytes_in,
            "bytes_out":      self.bytes_out,
            "agent_type":     self.agent_type,
            "enum_phase":     self.enum_phase,
            "attack_step":    self.attack_step,
            "ttp":            self.ttp,
            "is_attack":      self.is_attack,
            "dwell_ms":       self.dwell_ms,
            "fan_out_count":  self.fan_out_count,
        }

        if omit_none:
            return {k: v for k, v in result.items() if v is not None}
        return result