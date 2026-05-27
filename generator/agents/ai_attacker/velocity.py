"""
MABE AI Attacker — Velocity Model
===================================

Provides sub-second inter-event timing for the AI attacker agent, modelling
the machine-speed operation documented in the empirical sources.

EMPIRICAL GROUNDING
-------------------
Source: SANS/Lee (December 2025) — "MIT's autonomous agent research
demonstrated privilege escalation and exploit chaining in seconds to minutes
compared to hours for human operators. Horizon3's NodeZero testing achieved
full privilege escalation in about 60 seconds." → 47–158x velocity multiplier.

Source: GTG-1002 (November 2025) — "Peak activity included thousands of
requests, representing sustained request rates of multiple operations per
second." → sub-second inter-event timing sustained over hours.

MABE uses a conservative 47x multiplier (lower bound of the documented range)
applied to the ~3-minute human baseline, yielding a median inter-event delay
of 800ms for the AI attacker.

DISTRIBUTION CHOICE
-------------------
Lognormal is used rather than uniform or normal because:
- It is right-skewed: most events occur in rapid sub-second bursts, with
  occasional longer pauses between attack phases (e.g. after a credential
  harvest, before moving to the next frontier node).
- It matches empirically observed network event timing distributions in
  published intrusion datasets (LMDG, LANL).
- It never produces negative values.

Parameters: median=800ms, sigma=0.6, floor=50ms.
- sigma=0.6 produces a realistic spread: ~68% of events fall between ~450ms
  and ~1400ms, with occasional multi-second pauses.
- floor=50ms prevents timestamp collisions in Windows Event Log format
  (practical resolution ~100ms) and avoids sub-10ms values that cannot be
  meaningfully distinguished in forensic analysis.

NUMPY DEPENDENCY
----------------
Specified explicitly in Section 5 of the spec for this module.
numpy.random.Generator is used (not the legacy numpy.random module) for
reproducibility via a seed passed from simulate.py.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import numpy as np


class VelocityModel:
    """
    Lognormal inter-event timing model for the AI attacker agent.

    Parameters
    ----------
    params : dict
        The ai_attacker section of behavioral_params.yaml. Reads:
            inter_event_ms_median   (default: 800)
            inter_event_ms_sigma    (default: 0.6)
            inter_event_ms_floor_ms (default: 50)
    seed : int
        RNG seed provided by simulate.py. Used to initialise a
        numpy.random.Generator so timing is fully reproducible.
    """

    def __init__(self, params: dict, seed: int) -> None:
        self._median_ms: float = float(
            params.get("inter_event_ms_median", 800)
        )
        self._sigma: float = float(
            params.get("inter_event_ms_sigma", 0.6)
        )
        self._floor_ms: float = float(
            params.get("inter_event_ms_floor_ms", 50)
        )

        # mu for lognormal: ln(median) so that the distribution median
        # equals inter_event_ms_median exactly.
        self._mu: float = float(np.log(self._median_ms))

        # numpy Generator — reproducible, modern API (not legacy np.random)
        self._rng: np.random.Generator = np.random.default_rng(seed)

        # Session timestamp accumulator — set by start_session()
        self._current_time: datetime | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def start_session(self, session_start: datetime) -> None:
        """
        Initialise the timestamp accumulator for a new session.

        Must be called once before next_delay_ms() or advance() are used.
        Resets the accumulator to session_start so successive calls to
        advance() build a contiguous timestamp sequence from the session
        start time.

        Parameters
        ----------
        session_start : datetime
            The datetime at which this attack session begins.
        """
        self._current_time = session_start

    def next_delay_ms(self) -> float:
        """
        Sample the next inter-event delay in milliseconds.

        Samples from lognormal(mu=ln(median), sigma=sigma) and applies
        the configured floor. The floor prevents timestamp collisions and
        ensures all inter-event gaps are forensically distinguishable.

        Returns
        -------
        float
            Delay in milliseconds. Always >= inter_event_ms_floor_ms.
        """
        sample = self._rng.lognormal(mean=self._mu, sigma=self._sigma)
        return max(float(sample), self._floor_ms)

    def advance(self) -> datetime:
        """
        Advance the session clock by one sampled delay and return the new time.

        Combines next_delay_ms() with timestamp accumulation so the traversal
        agent can call advance() once per event to get the event's timestamp
        without managing timing state itself.

        Returns
        -------
        datetime
            The new current time after advancing by one sampled delay.

        Raises
        ------
        RuntimeError
            If start_session() has not been called before advance().
        """
        if self._current_time is None:
            raise RuntimeError(
                "VelocityModel.start_session() must be called before advance()."
            )
        delay_ms = self.next_delay_ms()
        self._current_time = self._current_time + timedelta(milliseconds=delay_ms)
        return self._current_time

    def current_time(self) -> datetime:
        """
        Return the current accumulated session time without advancing it.

        Raises
        ------
        RuntimeError
            If start_session() has not been called.
        """
        if self._current_time is None:
            raise RuntimeError(
                "VelocityModel.start_session() must be called before current_time()."
            )
        return self._current_time

    def dwell_ms(self) -> int:
        """
        Return the last sampled delay as an integer number of milliseconds.

        Convenience wrapper for populating the Event.dwell_ms field.
        Samples a new delay without advancing the clock — intended for
        cases where the traversal agent needs the dwell value before
        calling advance().

        Returns
        -------
        int
            Delay in milliseconds, floored and cast to int.
        """
        return int(self.next_delay_ms())

    # ------------------------------------------------------------------
    # Inspection helpers (used by data validation tool)
    # ------------------------------------------------------------------

    @property
    def median_ms(self) -> float:
        """Configured median inter-event delay in milliseconds."""
        return self._median_ms

    @property
    def sigma(self) -> float:
        """Configured lognormal sigma parameter."""
        return self._sigma

    @property
    def floor_ms(self) -> float:
        """Configured floor in milliseconds."""
        return self._floor_ms