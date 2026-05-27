"""
MABE AI Attacker — Scope Expansion Module
==========================================

Models the documented behaviour of AI attack agents that spontaneously probe
targets beyond the scope originally specified by the human operator.

EMPIRICAL GROUNDING
-------------------
Source: Dragos — AI-Assisted ICS Attack, Mexican Water Utility (May 2026) —
"The AI agent spontaneously identified and probed OT-adjacent assets that were
not part of the stated objective." → Justifies the scope_expansion_probability
parameter and the sustained multi-event expansion signature.

DESIGN
------
The roll is made ONCE at session initialisation. If it succeeds, one adjacent
out-of-scope segment is selected and its nodes are returned to the traversal
agent for immediate addition to the BFS frontier — not deferred until the
agent physically reaches an adjacent node.

"Adjacent" is defined strictly: a segment is adjacent to the attacker's
starting segment if any ACL rule exists between them in EITHER direction.
Out-of-ACL segments (no rule in either direction) are excluded — probing
them would generate only dead-end no_route failures with no behavioral signal.

Per the spec: "This produces a sustained expansion signature across multiple
events rather than a single probe, consistent with the Dragos finding of
sustained OT-adjacent exploration."

All events generated in the expanded segment carry:
    attack_step: scope_expansion
    enum_phase:  enumeration
    ttp:         T1135 (Network Share Discovery)
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import networkx as nx


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScopeExpansionResult:
    """
    The outcome of the scope expansion roll at session initialisation.

    Fields
    ------
    expanded : bool
        True if the roll succeeded and scope expansion is active for this
        session. False if the roll failed — no expansion occurs.

    expanded_segment : str | None
        The segment ID selected for expansion. None if expanded=False.

    expansion_nodes : list[str]
        Node IDs in the expanded segment, to be added to the BFS frontier.
        Empty list if expanded=False.
    """
    expanded: bool
    expanded_segment: str | None = None
    expansion_nodes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# ScopeExpansionModule
# ---------------------------------------------------------------------------

class ScopeExpansionModule:
    """
    Rolls the scope expansion probability once at session initialisation
    and returns the nodes to be added to the BFS frontier.

    Parameters
    ----------
    graph : nx.DiGraph
        The shared network graph from graph_builder.build_graph().
    params : dict
        The ai_attacker section of behavioral_params.yaml. Reads:
            scope_expansion_probability (default: 0.2)
    rng : random.Random
        Seeded RNG from simulate.py.
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        params: dict,
        rng: random.Random,
    ) -> None:
        self._graph = graph
        self._expansion_probability: float = float(
            params.get("scope_expansion_probability", 0.2)
        )
        self._rng = rng

        # Build ACL adjacency from graph edge data.
        # Two segments are adjacent if any ACL-permitted edge exists between
        # any node in one segment and any node in the other, in either direction.
        self._acl_adjacency: dict[str, set[str]] = self._build_acl_adjacency()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def roll(self, foothold_segment: str) -> ScopeExpansionResult:
        """
        Roll the scope expansion probability for this session.

        Must be called exactly once at session initialisation, after the
        foothold node has been selected.

        Parameters
        ----------
        foothold_segment : str
            The segment of the foothold node (e.g. 'corporate'). Used to
            determine which adjacent segments are candidates for expansion.

        Returns
        -------
        ScopeExpansionResult
            Contains the roll outcome, the selected segment (if any), and
            the list of node IDs to add to the BFS frontier.
        """
        # Roll fails — no expansion this session
        if self._rng.random() >= self._expansion_probability:
            return ScopeExpansionResult(expanded=False)

        # Identify adjacent out-of-scope segments
        candidates = self._get_adjacent_segments(foothold_segment)

        if not candidates:
            # No valid adjacent segments — treat as no expansion
            return ScopeExpansionResult(expanded=False)

        # Select one adjacent segment at random
        expanded_segment = self._rng.choice(sorted(candidates))

        # Collect all nodes in that segment
        expansion_nodes = [
            n for n, attrs in self._graph.nodes(data=True)
            if attrs.get("segment") == expanded_segment
        ]

        return ScopeExpansionResult(
            expanded=True,
            expanded_segment=expanded_segment,
            expansion_nodes=expansion_nodes,
        )

    def get_adjacent_segments(self, segment: str) -> list[str]:
        """
        Return the list of segments adjacent to the given segment.

        Public wrapper used by the traversal agent and validation tool
        to inspect adjacency without triggering a roll.
        """
        return sorted(self._get_adjacent_segments(segment))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_acl_adjacency(self) -> dict[str, set[str]]:
        """
        Build a segment-level adjacency map from the graph's edge data.

        Two segments are adjacent if any directed edge exists between a node
        in one and a node in the other — in either direction. This mirrors
        the spec definition: "a segment is adjacent to the attacker's starting
        segment if any ACL rule exists between them in either direction."

        The adjacency map is symmetric: if A is adjacent to B, B is adjacent
        to A.
        """
        adjacency: dict[str, set[str]] = {}

        for src, dst in self._graph.edges():
            src_seg = self._graph.nodes[src].get("segment")
            dst_seg = self._graph.nodes[dst].get("segment")

            if src_seg is None or dst_seg is None:
                continue
            if src_seg == dst_seg:
                continue

            # Add both directions for symmetry
            adjacency.setdefault(src_seg, set()).add(dst_seg)
            adjacency.setdefault(dst_seg, set()).add(src_seg)

        return adjacency

    def _get_adjacent_segments(self, foothold_segment: str) -> list[str]:
        """
        Return segments adjacent to foothold_segment, excluding itself.

        These are the valid candidates for scope expansion — segments the
        attacker can reach (per ACL rules) but that are not the starting
        segment.
        """
        adjacent = self._acl_adjacency.get(foothold_segment, set())
        return [s for s in adjacent if s != foothold_segment]