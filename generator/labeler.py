"""
MABE Labeling Engine
=====================

Receives the combined event stream from all agents and enriches every event
with validated metadata. In v1.0 the agents already set all label fields
directly — the labeler's role is validation and session registry maintenance
rather than field assignment.

Per the spec (Section 10), the labeler:
  - Maintains a session registry so all events from the same agent run
    share a session_id
  - Validates that label fields are internally consistent
  - Assigns ATT&CK TTPs from the canonical mapping where missing

The session registry is built from the session_id field already present on
every event — agents assign session UUIDs at session start.
"""

from __future__ import annotations

from collections import defaultdict

from schema.event import Event, ATTACK_STEP_TTP


class Labeler:
    """
    Validates and enriches the combined event stream.

    Usage
    -----
        labeler = Labeler()
        labeled_events = labeler.label(all_events)
    """

    def label(self, events: list[Event]) -> list[Event]:
        """
        Validate and enrich all events.

        Parameters
        ----------
        events : list[Event]
            Combined event stream from all agents (benign + attack),
            not yet sorted by timestamp.

        Returns
        -------
        list[Event]
            The same events with any missing TTP fields populated and
            consistency validated. Events are returned in input order —
            timestamp sorting happens in simulate.py.
        """
        self._validate_session_consistency(events)
        self._backfill_ttps(events)
        return events

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_session_consistency(self, events: list[Event]) -> None:
        """
        Verify that all events sharing a session_id have the same agent_type
        and is_attack value.

        Raises ValueError on the first inconsistency found.
        """
        session_agent_types: dict[str, str] = {}
        session_is_attack: dict[str, bool] = {}

        for event in events:
            sid = event.session_id

            if sid not in session_agent_types:
                session_agent_types[sid] = event.agent_type
                session_is_attack[sid] = event.is_attack
            else:
                if session_agent_types[sid] != event.agent_type:
                    raise ValueError(
                        f"Session '{sid}' has mixed agent_type values: "
                        f"'{session_agent_types[sid]}' and '{event.agent_type}'"
                    )
                if session_is_attack[sid] != event.is_attack:
                    raise ValueError(
                        f"Session '{sid}' has mixed is_attack values: "
                        f"{session_is_attack[sid]} and {event.is_attack}"
                    )

    def _backfill_ttps(self, events: list[Event]) -> None:
        """
        Populate ttp field from ATTACK_STEP_TTP mapping where it is None
        and the attack_step has a known TTP.

        Benign events (attack_step='none') correctly have ttp=None — these
        are not backfilled.
        """
        for event in events:
            if event.ttp is None and event.attack_step != "none":
                expected_ttp = ATTACK_STEP_TTP.get(event.attack_step)
                if expected_ttp is not None:
                    object.__setattr__(event, "ttp", expected_ttp)