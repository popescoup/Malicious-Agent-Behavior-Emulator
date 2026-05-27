"""
MABE AI Attacker Agent
=======================

Wires the five ai_attacker sub-modules into a single agent interface.
External code imports AIAttackerAgent from this module — the internal
sub-module split is transparent to simulate.py and all other callers.

    from generator.agents.ai_attacker import AIAttackerAgent

SUB-MODULES WIRED
-----------------
    foothold.py          FootholdInitializer  — session init, Sysmon artifacts
    velocity.py          VelocityModel        — lognormal inter-event timing
    hallucination.py     HallucinationModule  — hallucination check + harvest
    scope_expansion.py   ScopeExpansionModule — one-time BFS frontier injection
    traversal.py         BFSTraversalAgent    — BFS traversal, all event emission

INTERFACE
---------
AIAttackerAgent presents the same interface as BenignUserAgent:

    agent = AIAttackerAgent(graph, vocab, params, rng, seed)
    events = agent.run_session(session_start)

run_session() returns a list[Event] — the foothold_event prepended to the
traversal events — plus the session's Sysmon and foothold Sysmon records
stored on the agent for the EVTX formatter to retrieve.

SESSION RESULT
--------------
After run_session() returns, the following are available for the EVTX
formatter and session manifest:

    agent.session_id                str
    agent.foothold_node             str
    agent.attack_framework_pid      int
    agent.attack_framework_image    str
    agent.sysmon_records            list[dict]  — all Sysmon records
    agent.credential_store          list[Credential]
    agent.hosts_touched             list[str]

v1.0: Every session cold-starts from a single foothold. Session continuity
(resuming from a prior session's state) is a v2.0 feature.
"""

from __future__ import annotations

import random
from datetime import datetime

import networkx as nx

from generator.agents.ai_attacker.foothold import (
    Credential,
    FootholdInitializer,
    FootholdResult,
)
from generator.agents.ai_attacker.hallucination import HallucinationModule
from generator.agents.ai_attacker.scope_expansion import ScopeExpansionModule
from generator.agents.ai_attacker.traversal import BFSTraversalAgent
from generator.agents.ai_attacker.velocity import VelocityModel
from schema.event import Event


class AIAttackerAgent:
    """
    AI attacker agent — wires all sub-modules into a single session interface.

    Parameters
    ----------
    graph : nx.DiGraph
        The shared network graph from graph_builder.build_graph().
    vocab : dict
        Vocabulary bundle from vocabulary.json.
    params : dict
        The ai_attacker section of behavioral_params.yaml, loaded and
        passed in by simulate.py.
    rng : random.Random
        Seeded RNG instance from simulate.py. Controls all non-numpy
        randomness: foothold selection, username selection, auth outcomes,
        credential IDs, port numbers.
    seed : int
        Integer seed passed to VelocityModel and HallucinationModule for
        their numpy/internal RNGs. Provided separately from rng so that
        simulate.py can derive it deterministically (e.g. base_seed +
        session_index) without consuming values from the shared rng stream.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        vocab: dict,
        params: dict,
        rng: random.Random,
        seed: int,
    ) -> None:
        self._graph = graph
        self._vocab = vocab
        self._params = params
        self._rng = rng
        self._seed = seed

        # Instantiate sub-modules
        self._velocity = VelocityModel(params, seed=seed)
        self._hallucination = HallucinationModule(params, random.Random(seed + 100))
        self._foothold_init = FootholdInitializer(
            graph, vocab, params, rng, self._velocity
        )
        self._scope_mod = ScopeExpansionModule(graph, params, rng)

        # Session state — populated by run_session()
        self._foothold_result: FootholdResult | None = None
        self._traversal: BFSTraversalAgent | None = None
        self._events: list[Event] = []
        self._sysmon_records: list[dict] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run_session(self, session_start: datetime) -> list[Event]:
        """
        Execute one complete attack session.

        Steps:
        1. Initialise foothold — selects node, seeds credential store,
           starts velocity clock, emits Sysmon Event 1 + 7 records.
        2. Roll scope expansion — optionally injects adjacent-segment
           nodes into the BFS frontier before traversal begins.
        3. Run BFS traversal — exhaustive enumeration of all reachable
           nodes, emitting all canonical events and Sysmon records.
        4. Collect and return all events in timestamp order.

        Parameters
        ----------
        session_start : datetime
            Session start time provided by simulate.py.

        Returns
        -------
        list[Event]
            All canonical events for this session, chronologically ordered.
            Includes the foothold_init event as the first attack event.
        """
        # Step 1 — foothold initialisation
        self._foothold_result = self._foothold_init.initialize(session_start)

        # Step 2 — scope expansion roll
        foothold_segment = self._graph.nodes[
            self._foothold_result.foothold_node
        ]["segment"]
        scope_result = self._scope_mod.roll(foothold_segment)

        # Step 3 — BFS traversal
        self._traversal = BFSTraversalAgent(
            graph=self._graph,
            params=self._params,
            rng=self._rng,
            velocity=self._velocity,
            hallucination=self._hallucination,
            foothold_result=self._foothold_result,
            expansion_nodes=scope_result.expansion_nodes,
        )
        traversal_events, traversal_sysmon = self._traversal.run()

        # Step 4 — assemble full event list
        # foothold_event is prepended — it is the first canonical event
        self._events = (
            [self._foothold_result.foothold_event] + traversal_events
        )

        # Assemble all Sysmon records: foothold artifacts + traversal records
        self._sysmon_records = (
            self._foothold_result.sysmon_records + traversal_sysmon
        )

        return self._events

    # ------------------------------------------------------------------
    # Session metadata (for EVTX formatter and session manifest)
    # ------------------------------------------------------------------

    @property
    def session_id(self) -> str:
        self._assert_session_run()
        return self._foothold_result.session_id

    @property
    def foothold_node(self) -> str:
        self._assert_session_run()
        return self._foothold_result.foothold_node

    @property
    def attack_framework_pid(self) -> int:
        self._assert_session_run()
        return self._foothold_result.attack_framework_pid

    @property
    def attack_framework_image(self) -> str:
        self._assert_session_run()
        return self._foothold_result.attack_framework_image

    @property
    def sysmon_records(self) -> list[dict]:
        """All Sysmon records for this session (foothold + traversal)."""
        self._assert_session_run()
        return list(self._sysmon_records)

    @property
    def credential_store(self) -> list[Credential]:
        """Final credential store after traversal completes."""
        self._assert_session_run()
        return self._traversal.credential_store

    @property
    def hosts_touched(self) -> list[str]:
        """
        Distinct destination hosts that appear in this session's events.
        Used to populate session_manifest.json hosts_touched field.
        """
        self._assert_session_run()
        return sorted(set(
            e.dst_host for e in self._events
            if e.dst_host != self._foothold_result.foothold_node
        ) | {self._foothold_result.foothold_node})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_session_run(self) -> None:
        """Raise RuntimeError if run_session() has not been called."""
        if self._foothold_result is None:
            raise RuntimeError(
                "AIAttackerAgent.run_session() must be called before "
                "accessing session metadata properties."
            )