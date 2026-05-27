"""
MABE Splunk CIM Formatter
==========================

Transforms the labeled canonical event stream into Splunk CIM-compliant
JSON Lines format for ingestion via file monitor input or HTTP Event
Collector replay.

OUTPUT
------
File: output/splunk_stream.json
Format: JSON Lines — one JSON object per line, no enclosing array.
        Splunk's file monitor and HEC both process JSON Lines natively,
        reading one event per line for streaming ingestion.

CIM COMPLIANCE
--------------
Splunk ES correlation searches depend on event tags to route records into
the correct CIM data model accelerator. Without correct tags, the data
model accelerator ignores events entirely and all ES detection searches
produce zero results.

Tag assignment per Section 11 of the spec:

    auth_attempt, kerberos_tgt_request, kerberos_ticket_request
        → tags: ['authentication']
        → sourcetype: mabe:auth

    network_connection, service_probe, connection
        → tags: ['network', 'communicate']
        → sourcetype: mabe:network

    dns_query
        → tags: ['network', 'resolution']
        → sourcetype: mabe:network

    file_access
        → tags: ['network', 'communicate']
        → sourcetype: mabe:network

    registry_access
        → tags: ['network', 'communicate']
        → sourcetype: mabe:network

FIELD MAPPING
-------------
Standard CIM fields use CIM-prescribed names. Non-standard fields use the
mabe_ prefix to avoid collisions with CIM field names. The canonical
event_type field is preserved as mabe_event_type since it does not map
directly to any single CIM field but is needed for downstream queries.

COMPUTED FIELDS
---------------
signature      = attack_step + " " + ttp  (e.g. "auth_test T1110")
signature_id   = ttp                      (e.g. "T1110")
action         = "success" if success else "failure"
tag            = list of tag strings per tag assignment table
sourcetype     = "mabe:auth" or "mabe:network" per event_type
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from schema.event import Event

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
OUTPUT_FILE = OUTPUT_DIR / "splunk_stream.json"

# ---------------------------------------------------------------------------
# Tag and sourcetype assignment
# ---------------------------------------------------------------------------

# event_type → Splunk CIM tags
EVENT_TYPE_TAGS: dict[str, list[str]] = {
    "auth_attempt":            ["authentication"],
    "kerberos_tgt_request":    ["authentication"],
    "kerberos_ticket_request": ["authentication"],
    "network_connection":      ["network", "communicate"],
    "service_probe":           ["network", "communicate"],
    "connection":              ["network", "communicate"],
    "dns_query":               ["network", "resolution"],
    "file_access":             ["network", "communicate"],
    "registry_access":         ["network", "communicate"],
}

# event_type → Splunk sourcetype
EVENT_TYPE_SOURCETYPE: dict[str, str] = {
    "auth_attempt":            "mabe:auth",
    "kerberos_tgt_request":    "mabe:auth",
    "kerberos_ticket_request": "mabe:auth",
    "network_connection":      "mabe:network",
    "service_probe":           "mabe:network",
    "connection":              "mabe:network",
    "dns_query":               "mabe:network",
    "file_access":             "mabe:network",
    "registry_access":         "mabe:network",
}


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------

class SplunkCIMFormatter:
    """
    Writes the labeled event stream to output/splunk_stream.json in
    Splunk CIM JSON Lines format.

    Parameters
    ----------
    output_path : Path | str | None
        Override the default output file path. Used in tests.
    """

    def __init__(self, output_path: Path | str | None = None) -> None:
        self._output_path = Path(output_path) if output_path else OUTPUT_FILE

    def write(self, events: list[Event]) -> Path:
        """
        Transform and write all events to the output file.

        Parameters
        ----------
        events : list[Event]
            Labeled, chronologically sorted event stream from simulate.py.

        Returns
        -------
        Path
            Path to the written output file.
        """
        self._output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self._output_path, "w", encoding="utf-8") as f:
            for event in events:
                record = self._to_cim_record(event)
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        return self._output_path

    # ------------------------------------------------------------------
    # Record transformation
    # ------------------------------------------------------------------

    def _to_cim_record(self, event: Event) -> dict[str, Any]:
        """
        Transform one canonical Event into a Splunk CIM-compliant dict.

        Field mapping follows Section 11 of the spec exactly.
        """
        event_type = event.event_type
        tags = EVENT_TYPE_TAGS.get(event_type, ["network", "communicate"])
        sourcetype = EVENT_TYPE_SOURCETYPE.get(event_type, "mabe:network")

        # Computed fields
        action = "success" if event.success else "failure"
        signature = _compute_signature(event)
        signature_id = event.ttp or ""

        record: dict[str, Any] = {
            # ── Temporal ──────────────────────────────────────────────
            "_time":        event.timestamp,

            # ── Splunk metadata ───────────────────────────────────────
            "sourcetype":   sourcetype,
            "host":         event.src_host,
            "tag":          tags,

            # ── CIM Authentication / Network Traffic ──────────────────
            "src":          event.src_host,
            "dest":         event.dst_host,
            "src_ip":       event.src_ip,
            "dest_ip":      event.dst_ip,
            "src_port":     event.src_port,
            "dest_port":    event.dst_port,
            "user":         event.user,
            "action":       action,
            "app":          event.protocol,

            # ── CIM Authentication ────────────────────────────────────
            "logon_type":   event.logon_type,
            "logon_id":     event.logon_id,
            "reason":       event.failure_reason,
            "status":       event.failure_code,
            "signature":    signature,
            "signature_id": signature_id,

            # ── CIM Network Traffic ───────────────────────────────────
            "bytes_in":     event.bytes_in,
            "bytes_out":    event.bytes_out,

            # ── Custom MABE fields (mabe_ prefix) ─────────────────────
            "mabe_event_type":   event.event_type,
            "mabe_agent_type":   event.agent_type,
            "mabe_is_attack":    event.is_attack,
            "mabe_enum_phase":   event.enum_phase,
            "mabe_attack_step":  event.attack_step,
            "mabe_ttp":          event.ttp,
            "mabe_dwell_ms":     event.dwell_ms,
            "mabe_fan_out_count":event.fan_out_count,
            "mabe_session_id":   event.session_id,
        }

        return record


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _compute_signature(event: Event) -> str:
    """
    Compute the Splunk CIM signature field.

    Format: '<attack_step> <ttp>' for attack events with a known TTP.
    For benign events or events without a TTP, returns the attack_step alone
    or an empty string.
    """
    if event.attack_step and event.attack_step != "none":
        if event.ttp:
            return f"{event.attack_step} {event.ttp}"
        return event.attack_step
    return ""


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def write_splunk_cim(
    events: list[Event],
    output_path: Path | str | None = None,
) -> Path:
    """
    Convenience wrapper — instantiates SplunkCIMFormatter and writes events.

    Parameters
    ----------
    events : list[Event]
        Labeled, chronologically sorted event stream.
    output_path : Path | str | None
        Override default output path. Useful for tests.

    Returns
    -------
    Path
        Path to the written output file.
    """
    formatter = SplunkCIMFormatter(output_path=output_path)
    return formatter.write(events)