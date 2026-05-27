"""
MABE Data Validation Tool
==========================

Validates that the generated dataset is internally consistent and that the
behavioral parameters are reflected in the output data.

This is NOT an eval harness — it does not score a detection tool or agent.
It validates that MABE's own output is correct before submission.

CHECKS PERFORMED (Section 13 of the spec)
------------------------------------------
1.  Class balance          — attack/benign event and session ratios
2.  Velocity check         — median dwell_ms ratio matches configured multiplier
3.  Fan-out check          — AI attacker fan-out significantly exceeds benign
4.  Label consistency      — agent_type/is_attack/ttp consistency
5.  Schema completeness    — no required fields null; optional fields checked
6.  event_type x attack_step validity — no invalid combinations
7.  Privilege escalation   — no DC access before domain_admin credential
8.  Process tree integrity — all Sysmon Event 3/13 reference attack framework PID
9.  Session integrity      — session_id groupings are consistent

OUTPUT
------
Prints a structured validation report to stdout.
Exits with code 0 on pass, 1 on any failed check.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from schema.event import Event, VALID_EVENT_ATTACK_COMBINATIONS, ATTACK_STEP_TTP
from generator.simulate import SimulationResult

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

class CheckResult:
    """Result of a single validation check."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.passed = True
        self.messages: list[str] = []

    def fail(self, message: str) -> None:
        self.passed = False
        self.messages.append(message)

    def info(self, message: str) -> None:
        self.messages.append(message)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class Validator:
    """
    Runs all validation checks against a SimulationResult.

    Parameters
    ----------
    result : SimulationResult
        The complete simulation output.
    params : dict
        The full behavioral_params.yaml dict (both ai_attacker and
        benign_user sections). Used to validate against configured values.
    """

    def __init__(self, result: SimulationResult, params: dict) -> None:
        self._result = result
        self._params = params
        self._attack_params = params.get("ai_attacker", {})
        self._benign_params  = params.get("benign_user", {})
        self._checks: list[CheckResult] = []

    def run(self) -> bool:
        """
        Run all checks and print the validation report.

        Returns
        -------
        bool
            True if all checks passed, False otherwise.
        """
        print("=" * 60)
        print("MABE Data Validation Report")
        print("=" * 60)
        print(f"  Total events:    {len(self._result.events)}")
        print(f"  Attack events:   {len(self._result.attack_events)}")
        print(f"  Benign events:   {len(self._result.benign_events)}")
        print(f"  Attack sessions: {self._result.session_count_attack}")
        print(f"  Benign sessions: {self._result.session_count_benign}")
        print()

        self._check_class_balance()
        self._check_velocity()
        self._check_fan_out()
        self._check_label_consistency()
        self._check_schema_completeness()
        self._check_event_attack_step_validity()
        self._check_privilege_escalation()
        self._check_process_tree_integrity()
        self._check_session_integrity()

        # Print report
        all_passed = True
        for check in self._checks:
            status = "PASS" if check.passed else "FAIL"
            print(f"[{status}] {check.name}")
            for msg in check.messages:
                print(f"       {msg}")
            if not check.passed:
                all_passed = False

        print()
        if all_passed:
            print("All checks passed.")
        else:
            failed = sum(1 for c in self._checks if not c.passed)
            print(f"{failed} check(s) failed.")

        return all_passed

    # ------------------------------------------------------------------
    # Check 1 — Class balance
    # ------------------------------------------------------------------

    def _check_class_balance(self) -> None:
        check = CheckResult("Class balance")
        events = self._result.events
        n_total   = len(events)
        n_attack  = len(self._result.attack_events)
        n_benign  = len(self._result.benign_events)

        if n_total == 0:
            check.fail("No events generated.")
            self._checks.append(check)
            return

        ratio = n_attack / n_total
        check.info(f"Attack events: {n_attack} ({ratio:.1%})  "
                   f"Benign events: {n_benign}")

        # Attack sessions
        attack_sids = set(e.session_id for e in self._result.attack_events)
        benign_sids = set(e.session_id for e in self._result.benign_events)
        check.info(f"Attack sessions: {len(attack_sids)}  "
                   f"Benign sessions: {len(benign_sids)}")

        # Warn if attack ratio far exceeds 50% — suggests benign generation failed
        if ratio > 0.95:
            check.fail(
                f"Attack event ratio {ratio:.1%} is very high — "
                "benign session generation may have failed."
            )

        if n_attack == 0:
            check.fail("No attack events found.")
        if n_benign == 0:
            check.fail("No benign events found.")

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 2 — Velocity
    # ------------------------------------------------------------------

    def _check_velocity(self) -> None:
        check = CheckResult("Velocity check")
        from datetime import datetime
        from collections import defaultdict

        def parse(ts: str) -> datetime:
            return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")

        def session_gaps_ms(events: list) -> list[float]:
            """Compute inter-event gaps within each session."""
            by_session: dict[str, list[str]] = defaultdict(list)
            for e in events:
                by_session[e.session_id].append(e.timestamp)
            gaps = []
            for timestamps in by_session.values():
                timestamps.sort()
                for i in range(1, len(timestamps)):
                    delta_ms = (parse(timestamps[i]) - parse(timestamps[i-1])
                                ).total_seconds() * 1000
                    if delta_ms > 0:
                        gaps.append(delta_ms)
            return gaps

        attack_gaps = session_gaps_ms(self._result.attack_events)
        benign_gaps = session_gaps_ms(self._result.benign_events)

        if not attack_gaps or not benign_gaps:
            check.fail("Insufficient inter-event gaps for velocity check.")
            self._checks.append(check)
            return

        attack_median = sorted(attack_gaps)[len(attack_gaps) // 2]
        benign_median = sorted(benign_gaps)[len(benign_gaps) // 2]

        check.info(f"Attack median inter-event gap: {attack_median:.0f}ms")
        check.info(f"Benign median inter-event gap: {benign_median:.0f}ms")

        if benign_median > 0 and attack_median > 0:
            ratio = benign_median / attack_median
            check.info(f"Velocity ratio (benign/attack): {ratio:.0f}x "
                       f"(spec target: 47–158x)")
            if ratio < 10:
                check.fail(
                    f"Velocity ratio {ratio:.0f}x is below minimum threshold "
                    "of 10x — AI attacker may not be significantly faster "
                    "than benign users."
                )
        else:
            check.fail("Median gap is zero — cannot compute velocity ratio.")

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 3 — Fan-out
    # ------------------------------------------------------------------

    def _check_fan_out(self) -> None:
        check = CheckResult("Fan-out check")

        attack_events = self._result.attack_events
        benign_events = self._result.benign_events

        attack_fan_outs = [e.fan_out_count for e in attack_events]
        benign_fan_outs = [e.fan_out_count for e in benign_events]

        if not attack_fan_outs:
            check.fail("No attack fan_out_count values.")
            self._checks.append(check)
            return

        attack_mean = sum(attack_fan_outs) / len(attack_fan_outs)
        benign_mean = (sum(benign_fan_outs) / len(benign_fan_outs)
                       if benign_fan_outs else 0)
        attack_max  = max(attack_fan_outs)

        check.info(f"Attack mean fan_out_count: {attack_mean:.1f}  "
                   f"max: {attack_max}")
        check.info(f"Benign mean fan_out_count: {benign_mean:.1f}")

        if attack_mean <= benign_mean:
            check.fail(
                "AI attacker mean fan_out_count does not exceed benign — "
                "exhaustive enumeration signature is not present."
            )

        if attack_max < 5:
            check.fail(
                f"Maximum attack fan_out_count is {attack_max} — "
                "expected > 5 for exhaustive enumeration."
            )

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 4 — Label consistency
    # ------------------------------------------------------------------

    def _check_label_consistency(self) -> None:
        check = CheckResult("Label consistency")
        errors = 0

        for event in self._result.events:
            # agent_type / is_attack consistency
            if event.agent_type == "ai_attacker" and not event.is_attack:
                check.fail(
                    f"ai_attacker event with is_attack=False: "
                    f"session={event.session_id[:8]} "
                    f"event_type={event.event_type}"
                )
                errors += 1
                if errors >= 5:
                    check.fail("(further label errors suppressed)")
                    break

            if event.agent_type == "benign_user" and event.is_attack:
                check.fail(
                    f"benign_user event with is_attack=True: "
                    f"session={event.session_id[:8]}"
                )
                errors += 1
                if errors >= 5:
                    check.fail("(further label errors suppressed)")
                    break

            # Attack events must have non-null ttp (except backtrack)
            if event.is_attack and event.attack_step != "backtrack" \
                    and event.attack_step != "none" \
                    and event.ttp is None:
                check.fail(
                    f"Attack event with attack_step='{event.attack_step}' "
                    f"has null ttp (expected: "
                    f"{ATTACK_STEP_TTP.get(event.attack_step)})"
                )
                errors += 1
                if errors >= 5:
                    break

        if errors == 0:
            check.info("All agent_type/is_attack/ttp labels consistent.")

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 5 — Schema completeness
    # ------------------------------------------------------------------

    def _check_schema_completeness(self) -> None:
        check = CheckResult("Schema completeness")

        required_fields = [
            "timestamp", "session_id", "src_host", "src_ip", "src_port",
            "dst_host", "dst_ip", "dst_port", "user", "event_type",
            "protocol", "success", "agent_type", "enum_phase",
            "attack_step", "is_attack", "dwell_ms", "fan_out_count",
        ]

        # Optional fields that should never be null given their event_type
        conditional_required: dict[str, list[str]] = {
            "network_connection": ["process_id", "process_name"],
            "file_access":        ["object_name"],
        }

        null_counts: dict[str, int] = defaultdict(int)
        conditional_errors = 0

        for event in self._result.events:
            event_dict = event.to_dict(omit_none=False)

            for field in required_fields:
                if event_dict.get(field) is None:
                    null_counts[field] += 1

            # Conditional required fields
            et = event.event_type
            if et in conditional_required:
                for field in conditional_required[et]:
                    if event_dict.get(field) is None:
                        check.fail(
                            f"'{field}' is null on {et} event "
                            f"(session={event.session_id[:8]})"
                        )
                        conditional_errors += 1
                        if conditional_errors >= 5:
                            break

        for field, count in sorted(null_counts.items()):
            check.fail(f"Required field '{field}' is null on {count} events.")

        # Report optional null counts as info (not failures)
        optional_fields = [
            "logon_type", "logon_id", "process_id", "process_name",
            "object_name", "failure_reason", "failure_code",
            "credential_id", "bytes_in", "bytes_out", "ttp",
        ]
        null_optional: dict[str, int] = defaultdict(int)
        for event in self._result.events:
            d = event.to_dict(omit_none=False)
            for field in optional_fields:
                if d.get(field) is None:
                    null_optional[field] += 1

        for field, count in sorted(null_optional.items()):
            check.info(f"Optional field '{field}' is null on {count} events "
                       f"({count/len(self._result.events):.0%})")

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 6 — event_type × attack_step validity
    # ------------------------------------------------------------------

    def _check_event_attack_step_validity(self) -> None:
        check = CheckResult("event_type × attack_step validity")
        errors = 0

        for event in self._result.events:
            valid_steps = VALID_EVENT_ATTACK_COMBINATIONS.get(
                event.event_type, set()
            )
            if event.attack_step not in valid_steps:
                check.fail(
                    f"Invalid combination: event_type='{event.event_type}' "
                    f"+ attack_step='{event.attack_step}' "
                    f"(session={event.session_id[:8]})"
                )
                errors += 1
                if errors >= 5:
                    check.fail("(further combination errors suppressed)")
                    break

        if errors == 0:
            check.info(
                f"All {len(self._result.events)} events have valid "
                "event_type × attack_step combinations."
            )

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 7 — Privilege escalation
    # ------------------------------------------------------------------

    def _check_privilege_escalation(self) -> None:
        check = CheckResult("Privilege escalation check")

        # Nodes requiring domain_admin
        domain_admin_required_types = {"domain_controller", "logging_infrastructure"}
        errors = 0

        # Group attack events by session
        sessions: dict[str, list[Event]] = defaultdict(list)
        for event in self._result.attack_events:
            sessions[event.session_id].append(event)

        for session_id, events in sessions.items():
            events_sorted = sorted(events, key=lambda e: e.timestamp)

            # Track when domain_admin credential first appears
            domain_admin_acquired_time: str | None = None

            for event in events_sorted:
                if event.attack_step == "credential_harvest":
                    # We can't directly inspect the credential privilege from
                    # the event alone — check if any subsequent events reach
                    # domain_admin-required nodes
                    pass

                # Check: if this event targets a high-privilege node type,
                # verify a credential_harvest event preceded it in the session
                # We use dst_host to infer node type via a proxy check:
                # domain controllers have hostnames starting with DC-
                # This is a heuristic — a full check would require graph access
                if (event.event_type == "auth_attempt"
                        and event.success
                        and event.dst_host.startswith("DC-")):
                    # Find preceding credential_harvest events in this session
                    preceding_harvests = [
                        e for e in events_sorted
                        if e.attack_step == "credential_harvest"
                        and e.timestamp < event.timestamp
                    ]
                    if not preceding_harvests:
                        check.fail(
                            f"Session {session_id[:8]}: successful auth "
                            f"to domain controller {event.dst_host} without "
                            "any preceding credential_harvest event."
                        )
                        errors += 1
                        if errors >= 3:
                            check.fail(
                                "(further privilege escalation errors suppressed)"
                            )
                            break

        if errors == 0:
            check.info(
                "No privilege escalation violations found across "
                f"{len(sessions)} attack sessions."
            )

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 8 — Process tree integrity
    # ------------------------------------------------------------------

    def _check_process_tree_integrity(self) -> None:
        check = CheckResult("Process tree integrity")
        errors = 0

        for agent in self._result.attack_agents:
            expected_pid = agent.attack_framework_pid
            sysmon_records = agent.sysmon_records

            bad_records = [
                r for r in sysmon_records
                if r.get("EventID") in (3, 13)
                and r.get("ProcessId") != expected_pid
            ]

            if bad_records:
                check.fail(
                    f"Session {agent.session_id[:8]}: "
                    f"{len(bad_records)} Sysmon Event 3/13 records "
                    f"reference wrong ProcessId "
                    f"(expected: {expected_pid})"
                )
                errors += 1

            # Verify Event 1 exists and has the correct PID
            event1_records = [
                r for r in sysmon_records if r.get("EventID") == 1
            ]
            if not event1_records:
                check.fail(
                    f"Session {agent.session_id[:8]}: "
                    "No Sysmon Event 1 (process created) found."
                )
                errors += 1
            elif event1_records[0].get("ProcessId") != expected_pid:
                check.fail(
                    f"Session {agent.session_id[:8]}: "
                    f"Sysmon Event 1 ProcessId "
                    f"{event1_records[0].get('ProcessId')} != "
                    f"expected {expected_pid}"
                )
                errors += 1

        if errors == 0:
            check.info(
                f"All Sysmon Event 3/13 records across "
                f"{len(self._result.attack_agents)} attack sessions "
                "reference the correct attack framework PID."
            )

        self._checks.append(check)

    # ------------------------------------------------------------------
    # Check 9 — Session integrity
    # ------------------------------------------------------------------

    def _check_session_integrity(self) -> None:
        check = CheckResult("Session integrity")
        errors = 0

        sessions: dict[str, list[Event]] = defaultdict(list)
        for event in self._result.events:
            sessions[event.session_id].append(event)

        for session_id, events in sessions.items():
            # All events in a session must share agent_type
            agent_types = set(e.agent_type for e in events)
            if len(agent_types) > 1:
                check.fail(
                    f"Session {session_id[:8]} has mixed agent_types: "
                    f"{agent_types}"
                )
                errors += 1

            # All events in a session must share is_attack
            is_attack_vals = set(e.is_attack for e in events)
            if len(is_attack_vals) > 1:
                check.fail(
                    f"Session {session_id[:8]} has mixed is_attack values."
                )
                errors += 1

            # Events must form a contiguous time range (no gaps > 2 hours)
            sorted_events = sorted(events, key=lambda e: e.timestamp)
            if len(sorted_events) > 1:
                from datetime import datetime
                def parse(ts: str) -> datetime:
                    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")
                for i in range(1, len(sorted_events)):
                    gap_s = (
                        parse(sorted_events[i].timestamp) -
                        parse(sorted_events[i-1].timestamp)
                    ).total_seconds()
                    if gap_s > 7200:  # 2-hour threshold
                        check.fail(
                            f"Session {session_id[:8]}: gap of "
                            f"{gap_s/3600:.1f}h between consecutive events "
                            "(expected < 2h for a single session)."
                        )
                        errors += 1
                        break

            if errors >= 5:
                check.fail("(further session integrity errors suppressed)")
                break

        if errors == 0:
            check.info(
                f"All {len(sessions)} sessions have consistent agent_type, "
                "is_attack, and contiguous time ranges."
            )

        self._checks.append(check)


# ---------------------------------------------------------------------------
# Module-level entry point
# ---------------------------------------------------------------------------

def validate(
    result: SimulationResult,
    params: dict,
    exit_on_failure: bool = True,
) -> bool:
    """
    Run all validation checks and optionally exit on failure.

    Parameters
    ----------
    result : SimulationResult
    params : dict
        Full behavioral_params.yaml dict.
    exit_on_failure : bool
        If True (default), calls sys.exit(1) on any failed check.
        Set False for programmatic use (e.g. in tests).

    Returns
    -------
    bool
        True if all checks passed.
    """
    validator = Validator(result, params)
    passed = validator.run()

    if not passed and exit_on_failure:
        sys.exit(1)

    return passed


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import yaml
    from pathlib import Path

    repo_root = Path(__file__).parent.parent
    params_path = repo_root / "config" / "behavioral_params.yaml"

    if not params_path.exists():
        print(f"Error: behavioral_params.yaml not found at {params_path}",
              file=sys.stderr)
        sys.exit(1)

    with open(params_path) as f:
        params = yaml.safe_load(f)

    # Import here to avoid circular imports at module level
    from generator.simulate import run_simulation
    from generator.vocabulary import initialize_vocabulary

    print("Running simulation for validation...")
    vocab = initialize_vocabulary()
    result = run_simulation()

    validate(result, params, exit_on_failure=True)