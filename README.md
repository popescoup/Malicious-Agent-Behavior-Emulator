# MABE — Malicious Agent Behavior Emulator

MABE is a parameterizable synthetic dataset generator for AI-driven cyberattacks. It produces labeled event logs that emulate the behavioral signatures of an AI agent conducting internal network enumeration from an assumed breach entry point, contrasted against a realistic background of normal user activity.

## Why MABE Exists

As of May 2026, no public (synthetic or real-world) dataset captures the behavioral characteristics of AI-driven attacks — specifically their velocity, exhaustive network exploration patterns, and non-goal-directed traversal behavior. MABE addresses this gap through synthetic generation from first principles, with every behavioral parameter traceable to a published empirical source.

**Two key behavioral signatures distinguish AI-driven attacks from human-operated ones:**

- **Velocity** — AI agents operate at machine speed (sub-second inter-event intervals). Human operators work at human speed (minutes to hours). The velocity differential is empirically estimated at 47–158x.
- **Traversal pattern** — AI agents enumerate exhaustively (breadth-first, all reachable neighbors). Human operators move purposefully (targeted, fewer hops).

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate vocabulary (one-time, requires ANTHROPIC_API_KEY in .env)
python -m generator.vocabulary

# Run full simulation (50 benign + 10 attack sessions)
python main.py

# Custom run
python main.py --sessions-benign 100 --sessions-attack 20 --seed 123
```

## Output

```
output/
    splunk_stream.json          # Splunk CIM JSON Lines — all sessions interleaved
    sift/
        session_{uuid}/
            session_manifest.json   # Ground truth labels
            security_events.json    # Windows Security Events (label-free)
            sysmon_events.json      # Sysmon records (label-free)
```

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--topology` | `config/topology_enterprise.yaml` | Network topology config |
| `--params` | `config/behavioral_params.yaml` | Agent behavioral parameters |
| `--sessions-benign` | `50` | Number of benign sessions |
| `--sessions-attack` | `10` | Number of attack sessions |
| `--seed` | `42` | Random seed for reproducibility |
| `--formats` | `splunk,evtx` | Output formats (splunk, evtx, lanl, timesketch) |
| `--date` | `2025-11-14` | Simulation date |
| `--no-skip-vocab` | — | Force vocabulary regeneration |
| `--no-validate` | — | Skip post-generation validation |

## Empirical Grounding

Every behavioral parameter is traceable to a published source:

| Source | What it justifies |
|---|---|
| Anthropic GTG-1002 (Nov 2025) | Sub-second velocity, exhaustive enumeration, hallucination rate, credential harvesting |
| SANS/Lee (Dec 2025) | 47–158x velocity multiplier, human baseline timing |
| Dragos water utility (May 2026) | Scope expansion, protocol fallback sequences |
| arXiv 2310.11409 | Dead-end traversal, file-based credential discovery |
| arXiv 2502.04227 | Multi-hop credential chaining, assumed-breach framing |
| arXiv 2508.02942 (LMDG) | Three-engine architecture, benign behavioral model |

## Network Topology

Default enterprise topology: 60 nodes across 4 segments.

| Node type | Count | Segment | Required privilege |
|---|---|---|---|
| workstation | 40 | corporate | standard_user |
| api_endpoint | 6 | corporate | standard_user |
| file_server | 4 | corporate | standard_user |
| database | 4 | data_tier | service_account |
| domain_controller | 2 | infrastructure | domain_admin |
| container_registry | 2 | infrastructure | service_account |
| logging_infrastructure | 2 | infrastructure | service_account |

## Detection Layers

MABE's output is designed to support three detection layers:

1. **Baseline deviation** — is this account accessing systems it has never accessed before?
2. **Traversal pattern** — does the sequence of systems accessed follow an exploratory rather than purposeful pattern? (`fan_out_count`, `enum_phase`)
3. **Velocity** — is the speed of movement consistent with human or machine operation? (`dwell_ms`, inter-event gaps)

## Repository Structure

```
mabe/
├── config/
│   ├── topology_enterprise.yaml    # Default network topology
│   └── behavioral_params.yaml      # Agent parameters (all cited)
├── generator/
│   ├── graph_builder.py            # Topology → NetworkX graph
│   ├── vocabulary.py               # One-time LLM name generation
│   ├── simulate.py                 # Simulation orchestrator
│   ├── labeler.py                  # Event labeling engine
│   └── agents/
│       ├── benign_user.py          # Benign user agent
│       └── ai_attacker/
│           ├── __init__.py         # AIAttackerAgent (wires sub-modules)
│           ├── velocity.py         # Lognormal timing model
│           ├── foothold.py         # Session initialisation
│           ├── hallucination.py    # Hallucination/retry module
│           ├── scope_expansion.py  # Scope expansion module
│           └── traversal.py        # BFS traversal agent
├── schema/
│   └── event.py                    # Canonical event schema (immutable)
├── formatters/
│   ├── splunk_cim.py               # → Splunk CIM JSON Lines
│   ├── evtx_json.py                # → EVTX-compatible JSON (SIFT)
│   ├── lanl.py                     # → LANL CSV/JSON (stub)
│   └── timesketch.py               # → Timesketch JSONL (stub)
├── validation/
│   └── validate.py                 # Dataset validation tool
├── main.py                         # CLI entry point
├── requirements.txt
├── CITATION.cff
└── README.md
```

## Setup

### Prerequisites

- Python 3.11+
- An Anthropic API key (for one-time vocabulary generation only)

### Installation

```bash
pip install -r requirements.txt
```

### Environment

Create `mabe/.env`:

```
ANTHROPIC_API_KEY=your_api_key_here
```

The API key is only used once for vocabulary generation (`generator/vocabulary.py`). All subsequent simulation runs use the cached `vocabulary.json` and make no API calls.

## Validation

After every run, MABE validates its own output:

```
[PASS] Class balance
[PASS] Velocity check          — 53x ratio (target: 47–158x)
[PASS] Fan-out check           — attack mean 9.4x vs benign 1.0x
[PASS] Label consistency
[PASS] Schema completeness
[PASS] event_type × attack_step validity
[PASS] Privilege escalation check
[PASS] Process tree integrity
[PASS] Session integrity
```

Run validation independently:

```bash
python -m validation.validate
```

## Scope

MABE models **internal network enumeration behavior from an assumed foothold**:

- Autonomous exhaustive enumeration (`enum_phase: enumeration`)
- Credential-driven lateral traversal (`enum_phase: lateral`)
- Vulnerability discovery (probe side only)
- Service and database discovery (connection side only)

Out of scope: campaign initialization, exploit delivery, data extraction, exfiltration.

## Contributing

All new behavioral parameters must include an empirical source citation in `behavioral_params.yaml`. New node types must follow the taxonomy schema in Section 7 of the specification. New output formatters must consume the canonical schema without modifying it. Changes to `schema/event.py` require a version increment in `CITATION.cff`.

## Citation

```bibtex
@software{mabe2026,
  author = {Popescu, Luca},
  title  = {MABE: Malicious Agent Behavior Emulator},
  year   = {2026},
  url    = {https://github.com/popescoup/Malicious-Agent-Behavior-Emulator}
}
```

## License

MIT License. See `LICENSE` for details.