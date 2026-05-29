"""
MABE — Malicious Agent Behavior Emulator
CLI Entry Point
=================

Usage
-----
    python main.py [options]

Options
-------
    --topology        Path to topology config YAML
                      (default: config/topology_enterprise.yaml)
    --params          Path to behavioral params YAML
                      (default: config/behavioral_params.yaml)
    --sessions-benign Number of benign sessions to generate (default: 150):
    --sessions-attack Number of attack sessions to generate (default: 10)
    --seed            Random seed for reproducibility (default: 42)
    --formats         Comma-separated output formats (default: splunk,evtx)
                      Valid: splunk, evtx, lanl, timesketch
    --date            Simulation date in YYYY-MM-DD format
                      (default: 2025-11-14)
    --skip-vocab      Skip vocabulary generation if vocabulary.json exists
                      (default: true, pass --no-skip-vocab to force regen)
    --validate        Run data validation after generation (default: true)
    --output-dir      Base output directory (default: output/)

Examples
--------
    # Default run — 50 benign, 10 attack, splunk + evtx output
    python main.py

    # Custom session counts with all formats
    python main.py --sessions-benign 100 --sessions-attack 20 --formats splunk,evtx

    # Force vocabulary regeneration
    python main.py --no-skip-vocab

    # Reproducible run with explicit seed
    python main.py --seed 123
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

VALID_FORMATS = {"splunk", "evtx", "lanl", "timesketch"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mabe",
        description="MABE — Malicious Agent Behavior Emulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--topology",
        type=Path,
        default=None,
        help="Path to topology config YAML "
             "(default: config/topology_enterprise.yaml)",
    )
    parser.add_argument(
        "--params",
        type=Path,
        default=None,
        help="Path to behavioral params YAML "
             "(default: config/behavioral_params.yaml)",
    )
    parser.add_argument(
        "--sessions-benign",
        type=int,
        default=50,
        metavar="N",
        help="Number of benign sessions to generate (default: 150)",
    )
    parser.add_argument(
        "--sessions-attack",
        type=int,
        default=10,
        metavar="N",
        help="Number of attack sessions to generate (default: 10)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--formats",
        type=str,
        default="splunk,evtx",
        help="Comma-separated output formats: splunk,evtx,lanl,timesketch "
             "(default: splunk,evtx)",
    )
    parser.add_argument(
        "--date",
        type=str,
        default="2025-11-14",
        metavar="YYYY-MM-DD",
        help="Simulation date (default: 2025-11-14)",
    )
    parser.add_argument(
        "--skip-vocab",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Skip vocabulary generation if vocabulary.json exists "
             "(default: true)",
    )
    parser.add_argument(
        "--validate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run data validation after generation (default: true)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Base output directory (default: output/)",
    )

    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Format validation
# ---------------------------------------------------------------------------

def validate_formats(formats_str: str) -> list[str]:
    """Parse and validate the --formats argument."""
    formats = [f.strip().lower() for f in formats_str.split(",") if f.strip()]
    invalid = set(formats) - VALID_FORMATS
    if invalid:
        print(
            f"Error: Unknown format(s): {', '.join(sorted(invalid))}. "
            f"Valid formats: {', '.join(sorted(VALID_FORMATS))}",
            file=sys.stderr,
        )
        sys.exit(1)
    if not formats:
        print("Error: --formats must specify at least one format.", file=sys.stderr)
        sys.exit(1)
    return formats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Main CLI entry point.

    Returns
    -------
    int
        Exit code: 0 on success, 1 on error.
    """
    args = parse_args(argv)
    formats = validate_formats(args.formats)

    # Warn about stub formatters
    stub_formats = set(formats) & {"lanl", "timesketch"}
    if stub_formats:
        print(
            f"Warning: {', '.join(sorted(stub_formats))} formatter(s) are "
            "stubbed in v1.0 — output files will be empty placeholders.",
        )

    start_time = time.time()

    # ── Step 1: Vocabulary initialisation ────────────────────────────
    print("\n[1/4] Vocabulary initialisation")
    print("-" * 40)
    from generator.vocabulary import initialize_vocabulary
    try:
        vocab = initialize_vocabulary(force=not args.skip_vocab)
    except (EnvironmentError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # ── Step 2: Simulation ────────────────────────────────────────────
    print("\n[2/4] Running simulation")
    print("-" * 40)
    from generator.simulate import run_simulation
    try:
        result = run_simulation(
            topology_path=args.topology,
            params_path=args.params,
            sessions_benign=args.sessions_benign,
            sessions_attack=args.sessions_attack,
            seed=args.seed,
            simulation_date=args.date,
        )
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # ── Step 3: Output formatting ─────────────────────────────────────
    print("\n[3/4] Writing output")
    print("-" * 40)

    output_base = args.output_dir or (Path(__file__).parent / "output")
    written_files: list[Path] = []

    if "splunk" in formats:
        from formatters.splunk_cim import write_splunk_cim
        splunk_path = output_base / "splunk_stream.json"
        out = write_splunk_cim(result.events, output_path=splunk_path)
        written_files.append(out)
        print(f"  Splunk CIM JSON  → {out}")

    if "evtx" in formats:
        from formatters.evtx_json import write_evtx_json
        evtx_dir = output_base / "sift"
        session_dirs = write_evtx_json(result, output_dir=evtx_dir)
        print(f"  EVTX JSON        → {evtx_dir}/ "
              f"({len(session_dirs)} session bundles)")
        written_files.extend(session_dirs)

    if "lanl" in formats:
        _write_lanl_stub(output_base)
        print(f"  LANL CSV/JSON    → {output_base}/lanl/ (stub)")

    if "timesketch" in formats:
        _write_timesketch_stub(output_base)
        print(f"  Timesketch JSONL → {output_base}/timesketch/ (stub)")

    # ── Step 4: Validation ────────────────────────────────────────────
    if args.validate:
        print("\n[4/4] Data validation")
        print("-" * 40)
        import yaml
        params_path = args.params or (
            Path(__file__).parent / "config" / "behavioral_params.yaml"
        )
        with open(params_path) as f:
            params = yaml.safe_load(f)

        from validation.validate import validate
        passed = validate(result, params, exit_on_failure=False)
        if not passed:
            print("\nValidation failed — review the report above.", file=sys.stderr)
            return 1
    else:
        print("\n[4/4] Data validation skipped (--no-validate)")

    # ── Summary ───────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    print(f"\nDone in {elapsed:.1f}s")
    print(f"Total events: {len(result.events)} "
          f"({len(result.attack_events)} attack, "
          f"{len(result.benign_events)} benign)")

    return 0


# ---------------------------------------------------------------------------
# Stub formatters (v1.0 — LANL and Timesketch not yet implemented)
# ---------------------------------------------------------------------------

def _write_lanl_stub(output_base: Path) -> None:
    """Write empty LANL placeholder files."""
    import json
    lanl_dir = output_base / "lanl"
    lanl_dir.mkdir(parents=True, exist_ok=True)
    # network_flows.csv — header only
    (lanl_dir / "network_flows.csv").write_text(
        "Time,Duration,SrcDevice,DstDevice,Protocol,"
        "SrcPort,DstPort,SrcPackets,DstPackets,SrcBytes,DstBytes\n"
    )
    # host_events.json — empty array
    (lanl_dir / "host_events.json").write_text("[]\n")


def _write_timesketch_stub(output_base: Path) -> None:
    """Write empty Timesketch placeholder file."""
    ts_dir = output_base / "timesketch"
    ts_dir.mkdir(parents=True, exist_ok=True)
    (ts_dir / "events.jsonl").write_text("")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())