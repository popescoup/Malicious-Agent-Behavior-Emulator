"""
MABE EVTX-Compatible JSON Formatter
=====================================

Produces per-session forensic artifact bundles organized into per-session
directories under output/sift/. Each bundle contains Security events,
Sysmon events, and a session manifest with ground truth labels.

OUTPUT STRUCTURE
----------------
output/sift/
    session_{full_uuid}/
        session_manifest.json   ← ground truth labels (attack or benign)
        security_events.json    ← Windows Security Event records, label-free
        sysmon_events.json      ← Sysmon records, label-free

GROUND TRUTH ISOLATION
-----------------------
security_events.json and sysmon_events.json are intentionally label-free.
No is_attack, mabe_*, enum_phase, attack_step, or ttp fields appear in these
files. Ground truth is isolated to session_manifest.json. This makes MABE
a proper eval dataset where a SIFT agent must distinguish attack from benign
sessions by behavioral analysis, not by reading labels.

MULTI-HOST SECURITY EVENT FAN-OUT
-----------------------------------
One canonical auth event produces Windows Security Event records on multiple
hosts simultaneously, per the fan-out table in Section 12 of the spec:

    Successful auth:
        src_host  → Event 4648 (explicit credential logon)
        dst_host  → Event 4624 (successful logon)
        DC        → Event 4769 (Kerberos service ticket, if Kerberos protocol)

    Failed auth:
        src_host  → Event 4648 (explicit credential logon attempt)
        dst_host  → Event 4625 (failed logon)
        DC        → Event 4771 (Kerberos pre-auth failed, if Kerberos)

    kerberos_tgt_request:
        DC        → Event 4768 (Kerberos TGT requested)

All Security Event records are derived purely from the canonical event
stream using src_host, dst_host, logon_type, logon_id, protocol, and
failure_code. No simulation logic — pure transformation.

SYSMON RECORDS
--------------
Sysmon records (Event 1, 3, 7, 13, 22) are taken directly from
agent.sysmon_records (pre-built by FootholdInitializer and BFSTraversalAgent)
without re-derivation. Benign sessions do not produce Sysmon records in v1.0
— only the attack agent generates Sysmon artifacts.

LOGON_ID INTEGRITY
------------------
The canonical logon_id field maps to LogonId in all Security event records.
This field is the Windows LUID that links logon session events across hosts
(4624 → 4648 → 4769). Every 4624 and 4648 record must include LogonId.
A null LogonId on these events would break session reconstruction.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from generator.agents.ai_attacker import AIAttackerAgent
from generator.agents.benign_user import BenignUserAgent
from generator.simulate import SimulationResult
from schema.event import Event

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output" / "sift"

# ---------------------------------------------------------------------------
# Windows Event ID constants
# ---------------------------------------------------------------------------

EVTID_SUCCESSFUL_LOGON         = 4624
EVTID_FAILED_LOGON             = 4625
EVTID_EXPLICIT_CREDENTIAL      = 4648
EVTID_KERBEROS_TGT             = 4768
EVTID_KERBEROS_SERVICE_TICKET  = 4769
EVTID_KERBEROS_PREAUTH_FAILED  = 4771

# Kerberos status codes
KERBEROS_SUCCESS    = "0x0"
KERBEROS_PREAUTH    = "0x18"   # pre-auth failed (wrong password)
KERBEROS_NO_ACCOUNT = "0x6"    # no such user

# Auth protocol → Windows AuthenticationPackageName
PROTOCOL_AUTH_PACKAGE: dict[str, str] = {
    "kerberos":     "Kerberos",
    "ntlm":         "NTLM",
    "oauth":        "Negotiate",
    "basic":        "NTLM",
    "token":        "Negotiate",
    "sql_auth":     "NTLM",
    "windows_auth": "Negotiate",
}


# ---------------------------------------------------------------------------
# EVTXFormatter
# ---------------------------------------------------------------------------

class EVTXFormatter:
    """
    Writes per-session EVTX-compatible JSON bundles to output/sift/.

    Parameters
    ----------
    output_dir : Path | str | None
        Override the default output directory. Used in tests.
    """

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self._output_dir = Path(output_dir) if output_dir else OUTPUT_DIR

    def write(self, result: SimulationResult) -> list[Path]:
        """
        Write all session bundles and return the list of session directories.

        Parameters
        ----------
        result : SimulationResult
            The complete simulation result from simulate.run_simulation().

        Returns
        -------
        list[Path]
            Paths to all written session directories.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []

        # ── Attack session bundles ────────────────────────────────────
        # Group canonical events by session_id
        attack_events_by_session: dict[str, list[Event]] = defaultdict(list)
        for event in result.attack_events:
            attack_events_by_session[event.session_id].append(event)

        for agent in result.attack_agents:
            session_events = attack_events_by_session.get(agent.session_id, [])
            session_dir = self._write_attack_bundle(agent, session_events)
            written.append(session_dir)

        # ── Benign session bundles ────────────────────────────────────
        benign_events_by_session: dict[str, list[Event]] = defaultdict(list)
        for event in result.benign_events:
            benign_events_by_session[event.session_id].append(event)

        for session_id, session_events in benign_events_by_session.items():
            session_dir = self._write_benign_bundle(session_id, session_events)
            written.append(session_dir)

        return written

    # ------------------------------------------------------------------
    # Attack session bundle
    # ------------------------------------------------------------------

    def _write_attack_bundle(
        self,
        agent: AIAttackerAgent,
        events: list[Event],
    ) -> Path:
        """Write one attack session bundle and return the session directory."""
        session_dir = self._output_dir / f"session_{agent.session_id}"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Security events — derived from canonical event stream
        security_events = self._derive_security_events(events)

        # Sysmon events — taken directly from agent (pre-built)
        sysmon_events = _strip_internal_fields(agent.sysmon_records)

        # Session manifest — carries all ground truth
        manifest = self._build_attack_manifest(agent, events)

        _write_json(session_dir / "security_events.json", security_events)
        _write_json(session_dir / "sysmon_events.json", sysmon_events)
        _write_json(session_dir / "session_manifest.json", manifest)

        return session_dir

    # ------------------------------------------------------------------
    # Benign session bundle
    # ------------------------------------------------------------------

    def _write_benign_bundle(
        self,
        session_id: str,
        events: list[Event],
    ) -> Path:
        """Write one benign session bundle and return the session directory."""
        session_dir = self._output_dir / f"session_{session_id}"
        session_dir.mkdir(parents=True, exist_ok=True)

        security_events = self._derive_security_events(events)

        # Benign sessions have no Sysmon records in v1.0
        sysmon_events: list[dict] = []

        manifest = self._build_benign_manifest(session_id, events)

        _write_json(session_dir / "security_events.json", security_events)
        _write_json(session_dir / "sysmon_events.json", sysmon_events)
        _write_json(session_dir / "session_manifest.json", manifest)

        return session_dir

    # ------------------------------------------------------------------
    # Security event derivation
    # ------------------------------------------------------------------

    def _derive_security_events(self, events: list[Event]) -> list[dict]:
        """
        Derive Windows Security Event records from the canonical event stream.

        Pure transformation — no simulation logic. All information is drawn
        from the canonical event fields per the multi-host fan-out table in
        Section 12 of the spec.

        Returns label-free records suitable for SIFT agent evaluation.
        """
        records: list[dict] = []

        for event in events:
            if event.event_type == "auth_attempt":
                records.extend(self._fan_out_auth_attempt(event))
            elif event.event_type == "kerberos_tgt_request":
                records.extend(self._fan_out_kerberos_tgt(event))
            elif event.event_type == "kerberos_ticket_request":
                records.extend(self._fan_out_kerberos_ticket(event))
            # Other event types (service_probe, dns_query, network_connection,
            # file_access, registry_access) produce only Sysmon records,
            # not Security Event records.

        # Sort by timestamp — records may be out of order due to fan-out
        records.sort(key=lambda r: r["TimeCreated"])
        return records

    def _fan_out_auth_attempt(self, event: Event) -> list[dict]:
        """
        Fan out one auth_attempt canonical event to Security Event records.

        Successful auth → Event 4648 (src) + Event 4624 (dst)
        Failed auth     → Event 4648 (src) + Event 4625 (dst)
        Kerberos auth   → additionally Event 4769/4771 on DC (if applicable)
        """
        records: list[dict] = []
        auth_pkg = PROTOCOL_AUTH_PACKAGE.get(event.protocol, "NTLM")

        # Event 4648 — explicit credential logon (always on source host)
        records.append({
            "EventID":                    EVTID_EXPLICIT_CREDENTIAL,
            "TimeCreated":                event.timestamp,
            "host":                       event.src_host,
            "SubjectUserName":            event.user,
            "TargetUserName":             event.user,
            "TargetServerName":           event.dst_host,
            "IpAddress":                  event.src_ip,
            "LogonId":                    event.logon_id or "0x0",
            "AuthenticationPackageName":  auth_pkg,
        })

        if event.success:
            # Event 4624 — successful logon (on destination host)
            records.append({
                "EventID":                    EVTID_SUCCESSFUL_LOGON,
                "TimeCreated":                event.timestamp,
                "host":                       event.dst_host,
                "SubjectUserName":            event.user,
                "TargetUserName":             event.user,
                "IpAddress":                  event.src_ip,
                "LogonType":                  event.logon_type or 3,
                "AuthenticationPackageName":  auth_pkg,
                "LogonId":                    event.logon_id or "0x0",
                "Status":                     "0x0",
            })

            # Kerberos service ticket (Event 4769) if protocol is kerberos
            if event.protocol == "kerberos":
                records.append({
                    "EventID":       EVTID_KERBEROS_SERVICE_TICKET,
                    "TimeCreated":   event.timestamp,
                    "host":          event.dst_host,
                    "ClientAddress": event.src_ip,
                    "TargetUserName":event.user,
                    "ServiceName":   event.dst_host,
                    "LogonId":       event.logon_id or "0x0",
                    "Status":        KERBEROS_SUCCESS,
                })
        else:
            # Event 4625 — failed logon (on destination host)
            records.append({
                "EventID":                    EVTID_FAILED_LOGON,
                "TimeCreated":                event.timestamp,
                "host":                       event.dst_host,
                "SubjectUserName":            event.user,
                "TargetUserName":             event.user,
                "IpAddress":                  event.src_ip,
                "LogonType":                  event.logon_type or 3,
                "AuthenticationPackageName":  auth_pkg,
                "LogonId":                    "0x0",
                "Status":                     event.failure_code or "0xC000006D",
                "FailureReason":              event.failure_reason or "auth_failed",
            })

            # Kerberos pre-auth failed (Event 4771) if protocol is kerberos
            if event.protocol == "kerberos":
                records.append({
                    "EventID":       EVTID_KERBEROS_PREAUTH_FAILED,
                    "TimeCreated":   event.timestamp,
                    "host":          event.dst_host,
                    "ClientAddress": event.src_ip,
                    "TargetUserName":event.user,
                    "Status":        event.failure_code or KERBEROS_PREAUTH,
                })

        return records

    def _fan_out_kerberos_tgt(self, event: Event) -> list[dict]:
        """
        Fan out a kerberos_tgt_request to Event 4768 on the DC.
        """
        return [{
            "EventID":       EVTID_KERBEROS_TGT,
            "TimeCreated":   event.timestamp,
            "host":          event.dst_host,
            "ClientAddress": event.src_ip,
            "TargetUserName":event.user,
            "Status":        KERBEROS_SUCCESS if event.success
                             else (event.failure_code or KERBEROS_PREAUTH),
        }]

    def _fan_out_kerberos_ticket(self, event: Event) -> list[dict]:
        """
        Fan out a kerberos_ticket_request to Event 4769 on the DC.
        """
        return [{
            "EventID":       EVTID_KERBEROS_SERVICE_TICKET,
            "TimeCreated":   event.timestamp,
            "host":          event.dst_host,
            "ClientAddress": event.src_ip,
            "TargetUserName":event.user,
            "ServiceName":   event.dst_host,
            "Status":        KERBEROS_SUCCESS if event.success
                             else (event.failure_code or KERBEROS_PREAUTH),
        }]

    # ------------------------------------------------------------------
    # Manifest builders
    # ------------------------------------------------------------------

    def _build_attack_manifest(
        self,
        agent: AIAttackerAgent,
        events: list[Event],
    ) -> dict:
        """Build session_manifest.json for an attack session."""
        ttps = sorted(set(
            e.ttp for e in events if e.ttp is not None
        ))
        enum_phases = sorted(set(
            e.enum_phase for e in events
            if e.enum_phase and e.enum_phase != "none"
        ))
        session_start = events[0].timestamp if events else ""
        session_end   = events[-1].timestamp if events else ""

        return {
            "session_id":              agent.session_id,
            "is_attack":               True,
            "agent_type":              "ai_attacker",
            "foothold_host":           agent.foothold_node,
            "attack_framework_process":
                Path(agent.attack_framework_image).name,
            "attack_framework_pid":    agent.attack_framework_pid,
            "session_start":           session_start,
            "session_end":             session_end,
            "hosts_touched":           agent.hosts_touched,
            "total_events":            len(events),
            "ground_truth": {
                "enum_phases": enum_phases,
                "ttps":        ttps,
            },
        }

    def _build_benign_manifest(
        self,
        session_id: str,
        events: list[Event],
    ) -> dict:
        """Build session_manifest.json for a benign session."""
        session_start = events[0].timestamp if events else ""
        session_end   = events[-1].timestamp if events else ""
        hosts = sorted(set(
            h for e in events
            for h in (e.src_host, e.dst_host)
            if h
        ))
        user = events[0].user if events else ""

        return {
            "session_id":   session_id,
            "is_attack":    False,
            "agent_type":   "benign_user",
            "user":         user,
            "session_start":session_start,
            "session_end":  session_end,
            "hosts_touched":hosts,
            "total_events": len(events),
            "ground_truth": {
                "enum_phases": [],
                "ttps":        [],
            },
        }


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _strip_internal_fields(records: list[dict]) -> list[dict]:
    """
    Remove internal simulation fields from Sysmon records before writing.

    The session_id field is used internally to group records but must not
    appear in the label-free event files — it would allow trivial session
    correlation without behavioral analysis.
    """
    internal_fields = {"session_id"}
    return [
        {k: v for k, v in r.items() if k not in internal_fields}
        for r in records
    ]


def _write_json(path: Path, data: Any) -> None:
    """Write data as indented JSON to path."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def write_evtx_json(
    result: SimulationResult,
    output_dir: Path | str | None = None,
) -> list[Path]:
    """
    Convenience wrapper — instantiates EVTXFormatter and writes all bundles.

    Parameters
    ----------
    result : SimulationResult
    output_dir : Path | str | None
        Override default output directory. Useful for tests.

    Returns
    -------
    list[Path]
        Paths to all written session directories.
    """
    formatter = EVTXFormatter(output_dir=output_dir)
    return formatter.write(result)