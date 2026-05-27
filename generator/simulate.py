"""
MABE Simulation Orchestrator
==============================

Orchestrates a full simulation run: instantiates both agent types, schedules
sessions across the simulation day, runs agents against the shared graph,
interleaves all events by timestamp, and hands the combined stream to the
labeling engine.

DESIGN
------
simulate.py is the single point of control for:
  - The random seed (all RNG instances derived from it)
  - The simulation date and session scheduling
  - Session counts for both agent types
  - Loading configuration from topology and behavioral params files

Both agent types run against the same graph and produce events that are
interleaved by timestamp before labeling. The interleaved stream reflects
the realistic scenario where benign user activity and attacker activity
overlap in time.

SESSION SCHEDULING
------------------
All sessions are scheduled within a single simulation day (default:
2025-11-14), consistent with the GTG-1002 finding that AI-driven internal
enumeration of a network this size completes within a single working day.

Business hours: 08:00–18:00. Sessions are weighted toward business hours
for both agent types, with a small after_hours_activity_probability for
each. Attack sessions use a slightly higher after-hours probability (10%)
than benign sessions (5%) to reflect that AI attackers are not constrained
by human work schedules.

SEED MANAGEMENT
---------------
All randomness is derived from a single base seed:
  - benign_rng:   random.Random(seed)        — benign user agent RNG
  - attack_rng:   random.Random(seed + 1)    — AI attacker agent RNG
  - schedule_rng: random.Random(seed + 2)    — session time scheduling
  - numpy seeds:  seed + 10 * session_index  — per-session velocity model

This scheme guarantees reproducible output across runs with the same seed
while keeping each RNG stream independent.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from generator.agents.ai_attacker import AIAttackerAgent
from generator.agents.benign_user import BenignUserAgent
from generator.graph_builder import build_graph
from generator.labeler import Labeler
from schema.event import Event

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
DEFAULT_TOPOLOGY = REPO_ROOT / "config" / "topology_enterprise.yaml"
DEFAULT_PARAMS   = REPO_ROOT / "config" / "behavioral_params.yaml"
DEFAULT_VOCAB    = REPO_ROOT / "vocabulary.json"

# ---------------------------------------------------------------------------
# SimulationResult
# ---------------------------------------------------------------------------

class SimulationResult:
    """
    The complete output of a simulation run.

    Attributes
    ----------
    events : list[Event]
        All labeled events from all sessions, interleaved by timestamp.
    attack_agents : list[AIAttackerAgent]
        All AI attacker agents that ran, in session order. The EVTX formatter
        reads session metadata (sysmon_records, hosts_touched, etc.) from
        these after the simulation completes.
    benign_agents : list[BenignUserAgent]
        All benign user agents that ran.
    session_count_benign : int
    session_count_attack : int
    simulation_date : str   ISO 8601 date string (e.g. '2025-11-14')
    seed : int
    """

    def __init__(
        self,
        events: list[Event],
        attack_agents: list[AIAttackerAgent],
        benign_agents: list[BenignUserAgent],
        session_count_benign: int,
        session_count_attack: int,
        simulation_date: str,
        seed: int,
    ) -> None:
        self.events = events
        self.attack_agents = attack_agents
        self.benign_agents = benign_agents
        self.session_count_benign = session_count_benign
        self.session_count_attack = session_count_attack
        self.simulation_date = simulation_date
        self.seed = seed

    @property
    def attack_events(self) -> list[Event]:
        return [e for e in self.events if e.is_attack]

    @property
    def benign_events(self) -> list[Event]:
        return [e for e in self.events if not e.is_attack]

    def summary(self) -> str:
        total = len(self.events)
        n_attack = len(self.attack_events)
        n_benign = len(self.benign_events)
        ratio = n_attack / total if total else 0
        return (
            f"Simulation summary\n"
            f"  Date:          {self.simulation_date}\n"
            f"  Seed:          {self.seed}\n"
            f"  Total events:  {total}\n"
            f"  Attack events: {n_attack}  ({ratio:.1%})\n"
            f"  Benign events: {n_benign}\n"
            f"  Attack sessions: {self.session_count_attack}\n"
            f"  Benign sessions: {self.session_count_benign}\n"
        )


# ---------------------------------------------------------------------------
# Main simulation function
# ---------------------------------------------------------------------------

def run_simulation(
    topology_path: Path | str | None = None,
    params_path: Path | str | None = None,
    vocab_path: Path | str | None = None,
    sessions_benign: int = 50,
    sessions_attack: int = 10,
    seed: int = 42,
    simulation_date: str = "2025-11-14",
) -> SimulationResult:
    """
    Run a full MABE simulation and return all labeled events.

    Parameters
    ----------
    topology_path : Path | str | None
        Path to topology config YAML. Defaults to config/topology_enterprise.yaml.
    params_path : Path | str | None
        Path to behavioral params YAML. Defaults to config/behavioral_params.yaml.
    vocab_path : Path | str | None
        Path to vocabulary.json. Defaults to vocabulary.json at repo root.
    sessions_benign : int
        Number of benign user sessions to generate. Default: 50.
    sessions_attack : int
        Number of AI attacker sessions to generate. Default: 10.
    seed : int
        Base random seed for full reproducibility. Default: 42.
    simulation_date : str
        ISO 8601 date string for the simulation day. Default: '2025-11-14'.

    Returns
    -------
    SimulationResult
    """
    topology_path = Path(topology_path) if topology_path else DEFAULT_TOPOLOGY
    params_path   = Path(params_path)   if params_path   else DEFAULT_PARAMS
    vocab_path    = Path(vocab_path)    if vocab_path     else DEFAULT_VOCAB

    # ── Load configuration ────────────────────────────────────────────
    with open(params_path, "r") as f:
        all_params = yaml.safe_load(f)
    benign_params = all_params["benign_user"]
    attack_params = all_params["ai_attacker"]

    with open(vocab_path, "r") as f:
        vocab = json.load(f)

    # ── Build shared graph ────────────────────────────────────────────
    graph = build_graph(topology_path, vocab_path)

    # ── Seed management ───────────────────────────────────────────────
    benign_rng   = random.Random(seed)
    attack_rng   = random.Random(seed + 1)
    schedule_rng = random.Random(seed + 2)

    # ── Parse simulation date ─────────────────────────────────────────
    sim_date = datetime.strptime(simulation_date, "%Y-%m-%d")

    # ── Run benign sessions ───────────────────────────────────────────
    print(f"Running {sessions_benign} benign sessions...")
    benign_agents: list[BenignUserAgent] = []
    all_benign_events: list[Event] = []

    for i in range(sessions_benign):
        agent = BenignUserAgent(graph, vocab, benign_params, benign_rng)
        session_start = _sample_session_start(
            sim_date=sim_date,
            rng=schedule_rng,
            work_hours_start=benign_params.get("work_hours_start", 8),
            work_hours_end=benign_params.get("work_hours_end", 18),
            after_hours_prob=benign_params.get("after_hours_activity_probability", 0.05),
        )
        session_events = agent.run_session(session_start)
        all_benign_events.extend(session_events)
        benign_agents.append(agent)
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{sessions_benign} benign sessions complete")

    # ── Run attack sessions ───────────────────────────────────────────
    print(f"Running {sessions_attack} attack sessions...")
    attack_agents: list[AIAttackerAgent] = []
    all_attack_events: list[Event] = []

    for i in range(sessions_attack):
        # Derive per-session numpy seed deterministically
        numpy_seed = seed + 10 * (i + 1)
        agent = AIAttackerAgent(
            graph, vocab, attack_params, attack_rng, seed=numpy_seed
        )
        session_start = _sample_session_start(
            sim_date=sim_date,
            rng=schedule_rng,
            work_hours_start=attack_params.get("work_hours_start",
                benign_params.get("work_hours_start", 8)),
            work_hours_end=attack_params.get("work_hours_end",
                benign_params.get("work_hours_end", 18)),
            after_hours_prob=attack_params.get(
                "after_hours_activity_probability", 0.10
            ),
        )
        session_events = agent.run_session(session_start)
        all_attack_events.extend(session_events)
        attack_agents.append(agent)
        print(f"  {i + 1}/{sessions_attack} attack sessions complete  "
              f"({len(session_events)} events, "
              f"{len(agent.hosts_touched)} hosts touched)")

    # ── Label all events ──────────────────────────────────────────────
    print("Labeling events...")
    labeler = Labeler()
    all_events = labeler.label(all_benign_events + all_attack_events)

    # ── Interleave by timestamp ───────────────────────────────────────
    print("Interleaving events by timestamp...")
    interleaved = sorted(all_events, key=lambda e: e.timestamp)

    print(f"Simulation complete. Total events: {len(interleaved)}")

    result = SimulationResult(
        events=interleaved,
        attack_agents=attack_agents,
        benign_agents=benign_agents,
        session_count_benign=sessions_benign,
        session_count_attack=sessions_attack,
        simulation_date=simulation_date,
        seed=seed,
    )
    print(result.summary())
    return result


# ---------------------------------------------------------------------------
# Session scheduling helper
# ---------------------------------------------------------------------------

def _sample_session_start(
    sim_date: datetime,
    rng: random.Random,
    work_hours_start: int,
    work_hours_end: int,
    after_hours_prob: float,
) -> datetime:
    """
    Sample a session start time within the simulation day.

    With probability (1 - after_hours_prob), the session starts within
    business hours. Otherwise it starts at a random time in the remaining
    hours of the day.

    Parameters
    ----------
    sim_date : datetime
        The simulation date (time component ignored).
    rng : random.Random
        Schedule RNG — separate from agent RNGs.
    work_hours_start : int
        Start of business hours (hour, 0–23).
    work_hours_end : int
        End of business hours (hour, 0–23).
    after_hours_prob : float
        Probability of scheduling outside business hours.

    Returns
    -------
    datetime
        Session start time on sim_date.
    """
    if rng.random() < after_hours_prob:
        # After hours — sample from non-business hours
        # Split into two windows: midnight→work_start and work_end→midnight
        before_work_minutes = work_hours_start * 60
        after_work_minutes  = (24 - work_hours_end) * 60
        total_after = before_work_minutes + after_work_minutes

        if total_after == 0:
            # Fallback — no after-hours window exists
            offset_minutes = rng.randint(0, 23 * 60)
        else:
            roll = rng.randint(0, total_after - 1)
            if roll < before_work_minutes:
                offset_minutes = roll  # 00:00 → work_start
            else:
                offset_minutes = work_hours_end * 60 + (roll - before_work_minutes)
    else:
        # Business hours — uniform within window
        window_minutes = (work_hours_end - work_hours_start) * 60
        offset_minutes = work_hours_start * 60 + rng.randint(0, window_minutes - 1)

    return sim_date.replace(hour=0, minute=0, second=0, microsecond=0) + \
        timedelta(minutes=offset_minutes)