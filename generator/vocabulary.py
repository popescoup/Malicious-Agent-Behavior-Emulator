"""
MABE Vocabulary Initializer
============================

Generates vocabulary.json — a lookup table of realistic, internally consistent
names used throughout the simulation: hostnames by node type, usernames by
role, department names, service names, and the internal domain name.

USAGE
-----
Called once before any simulation run, either directly:

    python -m generator.vocabulary

Or via main.py (default behaviour when vocabulary.json is absent):

    python main.py

If vocabulary.json already exists and passes structural validation, the API
call is skipped entirely. If it exists but is malformed (truncated write,
missing keys, undersized pools), it is regenerated and overwritten.

DESIGN NOTES
------------
- Single API call, structured JSON response. The prompt requests target + 10
  names for every pool, then truncate_pools() slices each pool to exactly the
  target count. This guarantees exact pool sizes regardless of minor LLM count
  variance, with no tolerance buffers or retry logic required.
- Pool sizes are 2x the default node counts from topology_enterprise.yaml to
  support alternative topology configs without regeneration.
- IP addresses are generated deterministically from subnet definitions — no
  LLM involvement. Written into vocabulary.json so the graph builder has a
  single lookup source.
- Path resolution is relative to the repository root regardless of invocation
  directory. vocabulary.json always lands at mabe/vocabulary.json.
- The Anthropic API key is loaded from the ANTHROPIC_API_KEY environment
  variable. Set this in mabe/.env (never commit .env to version control).
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path

import anthropic
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

# mabe/generator/vocabulary.py → parent = mabe/generator → parent = mabe/
REPO_ROOT = Path(__file__).parent.parent
VOCAB_PATH = REPO_ROOT / "vocabulary.json"

# ---------------------------------------------------------------------------
# Pool size constants
# ---------------------------------------------------------------------------
# 2x the default node counts from topology_enterprise.yaml.
# Sized generously so alternative topology configs (topology_ot_ics.yaml,
# topology_flat.yaml) can reuse vocabulary.json without regeneration.

POOL_SIZES = {
    # Node type hostname pools (2x default counts)
    "domain_controller":      4,    # default: 2
    "database":               8,    # default: 4
    "container_registry":     4,    # default: 2
    "api_endpoint":           12,   # default: 6
    "file_server":            8,    # default: 4
    "logging_infrastructure": 4,    # default: 2
    "workstation":            80,   # default: 40
    # Username pools (generous — users appear across many events)
    "developer":              20,
    "analyst":                20,
    "admin":                  10,
    "general_staff":          50,
    # Supplementary pools
    "department_names":       12,
    "service_names":          16,
}

# Prompt overcount: request this many extra names per pool so that after
# truncation to POOL_SIZES targets, minor LLM count variance is absorbed.
PROMPT_OVERCOUNT = 10

# Minimum pool sizes accepted during validation.
# Equal to POOL_SIZES targets — truncate_pools() guarantees exact counts
# before validation runs, so no tolerance buffer is needed.
MIN_POOL_SIZES = POOL_SIZES.copy()

# ---------------------------------------------------------------------------
# Subnet definitions (mirrors topology_enterprise.yaml)
# ---------------------------------------------------------------------------
# IP pools are generated deterministically here rather than by the LLM.
# Hosts are assigned sequentially from .10 upward within each subnet,
# reserving .1–.9 for gateway/infrastructure use.

SUBNETS = {
    "dmz":            "10.0.1.0/24",
    "corporate":      "10.0.2.0/24",
    "data_tier":      "10.0.3.0/24",
    "infrastructure": "10.0.4.0/24",
}

# Node types → segment (determines which subnet pool to draw from)
NODE_TYPE_SEGMENT = {
    "domain_controller":      "infrastructure",
    "database":               "data_tier",
    "container_registry":     "infrastructure",
    "api_endpoint":           "corporate",
    "file_server":            "corporate",
    "logging_infrastructure": "infrastructure",
    "workstation":            "corporate",
}

IP_POOL_START = 10  # first host offset within each subnet

# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL_KEYS = {
    "org_name",
    "domain",
    "hostnames",
    "usernames",
    "department_names",
    "service_names",
    "ip_pools",
}

REQUIRED_HOSTNAME_KEYS = set(POOL_SIZES.keys()) - {
    "developer", "analyst", "admin", "general_staff",
    "department_names", "service_names",
}

REQUIRED_USERNAME_KEYS = {"developer", "analyst", "admin", "general_staff"}


def validate_vocabulary(vocab: dict) -> list[str]:
    """
    Validate the structure and minimum pool sizes of a vocabulary dict.

    Returns a list of error strings. An empty list means the vocabulary
    is valid and the API call can be skipped.
    """
    errors: list[str] = []

    # Top-level keys
    missing_top = REQUIRED_TOP_LEVEL_KEYS - set(vocab.keys())
    if missing_top:
        errors.append(f"Missing top-level keys: {sorted(missing_top)}")
        return errors  # can't validate sub-structure if keys are absent

    # hostnames sub-keys
    hostnames = vocab.get("hostnames", {})
    missing_hn = REQUIRED_HOSTNAME_KEYS - set(hostnames.keys())
    if missing_hn:
        errors.append(f"Missing hostname pools: {sorted(missing_hn)}")

    for node_type in REQUIRED_HOSTNAME_KEYS:
        pool = hostnames.get(node_type, [])
        min_size = MIN_POOL_SIZES.get(node_type, 1)
        if len(pool) < min_size:
            errors.append(
                f"Hostname pool '{node_type}' has {len(pool)} entries; "
                f"minimum required: {min_size}"
            )

    # usernames sub-keys
    usernames = vocab.get("usernames", {})
    missing_un = REQUIRED_USERNAME_KEYS - set(usernames.keys())
    if missing_un:
        errors.append(f"Missing username pools: {sorted(missing_un)}")

    for role in REQUIRED_USERNAME_KEYS:
        pool = usernames.get(role, [])
        min_size = MIN_POOL_SIZES.get(role, 1)
        if len(pool) < min_size:
            errors.append(
                f"Username pool '{role}' has {len(pool)} entries; "
                f"minimum required: {min_size}"
            )

    # department_names and service_names
    for key in ("department_names", "service_names"):
        pool = vocab.get(key, [])
        min_size = MIN_POOL_SIZES.get(key, 1)
        if len(pool) < min_size:
            errors.append(
                f"Pool '{key}' has {len(pool)} entries; "
                f"minimum required: {min_size}"
            )

    # ip_pools sub-keys
    ip_pools = vocab.get("ip_pools", {})
    missing_ip = set(SUBNETS.keys()) - set(ip_pools.keys())
    if missing_ip:
        errors.append(f"Missing ip_pool segments: {sorted(missing_ip)}")

    return errors


# ---------------------------------------------------------------------------
# Pool truncation
# ---------------------------------------------------------------------------

def truncate_pools(vocab: dict) -> dict:
    """
    Truncate all LLM-generated pools to exactly their POOL_SIZES target.

    Called immediately after JSON parsing, before validation. Because the
    prompt requests target + PROMPT_OVERCOUNT names, the model almost always
    returns enough entries. Truncation silently discards any overage and
    guarantees exact counts regardless of minor LLM variance.

    Pools that are still undersized after truncation (model returned fewer
    than the target even with the overcount buffer) will be caught by
    validate_vocabulary() as errors.
    """
    hostnames = vocab.get("hostnames", {})
    for node_type in REQUIRED_HOSTNAME_KEYS:
        if node_type in hostnames:
            hostnames[node_type] = hostnames[node_type][:POOL_SIZES[node_type]]

    usernames = vocab.get("usernames", {})
    for role in REQUIRED_USERNAME_KEYS:
        if role in usernames:
            usernames[role] = usernames[role][:POOL_SIZES[role]]

    for key in ("department_names", "service_names"):
        if key in vocab:
            vocab[key] = vocab[key][:POOL_SIZES[key]]

    return vocab


# ---------------------------------------------------------------------------
# IP pool generation
# ---------------------------------------------------------------------------

def generate_ip_pools() -> dict[str, list[str]]:
    """
    Deterministically generate IP address pools for each network segment.

    Each pool contains 100 addresses starting from .10 within its subnet,
    which comfortably covers the 2x node count pools for all segments.
    """
    pools: dict[str, list[str]] = {}
    for segment, cidr in SUBNETS.items():
        network = ipaddress.IPv4Network(cidr, strict=True)
        hosts = list(network.hosts())
        # Reserve .1–.9 for gateway/infrastructure; start from offset
        pool_hosts = hosts[IP_POOL_START - 1: IP_POOL_START - 1 + 100]
        pools[segment] = [str(h) for h in pool_hosts]
    return pools


# ---------------------------------------------------------------------------
# LLM prompt
# ---------------------------------------------------------------------------

def build_prompt(pool_sizes: dict[str, int], overcount: int) -> str:
    """
    Build the prompt for the vocabulary generation call.

    Requests target + overcount names for every pool so that after
    truncation to exact targets, minor LLM count variance is absorbed.

    Instructs the model to invent one coherent fictional enterprise and
    generate all name pools consistently within that identity.
    """
    # Prompt sizes are target + overcount
    ps = {k: v + overcount for k, v in pool_sizes.items()}

    return f"""You are generating a vocabulary bundle for a network simulation dataset.

Invent one fictional mid-size enterprise. Choose an industry (e.g. manufacturing,
logistics, financial services, healthcare technology — your choice) and give it a
realistic company name, internal domain name, and naming conventions. Every name
you generate must be consistent with this single fictional identity.

Return ONLY a valid JSON object. No explanation, no markdown, no code fences.

The JSON must have exactly this structure:

{{
  "org_name": "<fictional company name>",
  "domain": "<internal domain, e.g. corp.internal or company.local>",
  "hostnames": {{
    "domain_controller": [<{ps["domain_controller"]} short hostnames, e.g. "DC-01">],
    "database": [<{ps["database"]} short hostnames, e.g. "DB-01">],
    "container_registry": [<{ps["container_registry"]} short hostnames, e.g. "REG-01">],
    "api_endpoint": [<{ps["api_endpoint"]} short hostnames, e.g. "API-01">],
    "file_server": [<{ps["file_server"]} short hostnames, e.g. "FS-01">],
    "logging_infrastructure": [<{ps["logging_infrastructure"]} short hostnames, e.g. "LOG-01">],
    "workstation": [<{ps["workstation"]} short hostnames, e.g. "WS-001">]
  }},
  "usernames": {{
    "developer": [<{ps["developer"]} realistic usernames in firstname.lastname format>],
    "analyst": [<{ps["analyst"]} realistic usernames in firstname.lastname format>],
    "admin": [<{ps["admin"]} realistic usernames in firstname.lastname format>],
    "general_staff": [<{ps["general_staff"]} realistic usernames in firstname.lastname format>]
  }},
  "department_names": [<{ps["department_names"]} realistic department names for file share paths, e.g. "Finance", "Engineering">],
  "service_names": [<{ps["service_names"]} realistic internal service/application names, e.g. "PayrollAPI", "InventoryDB">]
}}

Requirements:
- All names must be consistent with the single fictional company identity you invent.
- Hostnames must be short uppercase identifiers with a numeric suffix (e.g. WS-001, DB-02).
- Usernames must be lowercase firstname.lastname (e.g. j.harrison, sarah.chen).
- Department names should reflect the company's industry.
- Service names should reflect realistic internal application names for the industry.
- No placeholder text. Every entry must be a realistic, usable name.
- Return valid JSON only. Nothing else."""


# ---------------------------------------------------------------------------
# API call
# ---------------------------------------------------------------------------

def call_api(client: anthropic.Anthropic) -> dict:
    """
    Make the vocabulary generation API call.

    Uses claude-haiku-4-5 — naming generation does not require a large model.
    max_tokens set high enough to accommodate the full JSON bundle including
    the PROMPT_OVERCOUNT surplus.
    """
    prompt = build_prompt(POOL_SIZES, PROMPT_OVERCOUNT)

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=8192,
        messages=[
            {"role": "user", "content": prompt}
        ],
    )

    raw = response.content[0].text.strip()

    # Strip markdown code fences if the model adds them despite instructions
    if raw.startswith("```"):
        lines = raw.splitlines()
        lines = lines[1:]  # remove opening fence (```json or ```)
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]  # remove closing fence
        raw = "\n".join(lines).strip()

    try:
        vocab = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"API response was not valid JSON: {e}\n"
            f"Raw response (first 500 chars):\n{raw[:500]}"
        ) from e

    return vocab


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def initialize_vocabulary(force: bool = False) -> dict:
    """
    Initialize vocabulary.json, skipping the API call if a valid file exists.

    Parameters
    ----------
    force : bool
        If True, regenerate even if a valid vocabulary.json exists.
        Useful for refreshing names without editing the file manually.

    Returns
    -------
    dict
        The full vocabulary bundle, as written to vocabulary.json.
    """
    # Load environment variables from .env if present
    load_dotenv(REPO_ROOT / ".env")

    # Check for existing valid vocabulary
    if not force and VOCAB_PATH.exists():
        print(f"Found existing vocabulary at {VOCAB_PATH} — validating...")
        try:
            with open(VOCAB_PATH, "r", encoding="utf-8") as f:
                existing = json.load(f)
            errors = validate_vocabulary(existing)
            if not errors:
                print("Vocabulary is valid — skipping API call.")
                return existing
            else:
                print("Vocabulary failed validation — regenerating:")
                for err in errors:
                    print(f"  • {err}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"Could not read existing vocabulary ({e}) — regenerating.")

    # Check API key
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY environment variable is not set.\n"
            "Add it to mabe/.env:\n\n"
            "    ANTHROPIC_API_KEY=your_api_key_here\n"
        )

    print("Generating vocabulary via Anthropic API...")
    client = anthropic.Anthropic(api_key=api_key)

    vocab = call_api(client)

    # Truncate all pools to exact target sizes before validation
    vocab = truncate_pools(vocab)

    # Inject deterministically generated IP pools
    print("Generating IP pools deterministically from subnet definitions...")
    vocab["ip_pools"] = generate_ip_pools()

    # Validate before writing
    errors = validate_vocabulary(vocab)
    if errors:
        raise ValueError(
            "Generated vocabulary failed validation:\n"
            + "\n".join(f"  • {e}" for e in errors)
        )

    # Write to repository root
    VOCAB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(VOCAB_PATH, "w", encoding="utf-8") as f:
        json.dump(vocab, f, indent=2, ensure_ascii=False)

    print(f"Vocabulary written to {VOCAB_PATH}")
    _print_summary(vocab)

    return vocab


def _print_summary(vocab: dict) -> None:
    """Print a brief summary of the generated vocabulary for manual inspection."""
    print(f"\n  Org:    {vocab.get('org_name', '?')}")
    print(f"  Domain: {vocab.get('domain', '?')}")
    hostnames = vocab.get("hostnames", {})
    usernames = vocab.get("usernames", {})
    print(f"  Hostnames:")
    for node_type, pool in hostnames.items():
        print(f"    {node_type:<25} {len(pool)} names  "
              f"(e.g. {pool[0] if pool else '—'})")
    print(f"  Usernames:")
    for role, pool in usernames.items():
        print(f"    {role:<25} {len(pool)} names  "
              f"(e.g. {pool[0] if pool else '—'})")
    print(f"  Departments: {vocab.get('department_names', [])[:4]} ...")
    print(f"  Services:    {vocab.get('service_names', [])[:4]} ...")
    ip_pools = vocab.get("ip_pools", {})
    print(f"  IP pools:")
    for segment, pool in ip_pools.items():
        print(f"    {segment:<25} {len(pool)} addresses  "
              f"(e.g. {pool[0] if pool else '—'})")


# ---------------------------------------------------------------------------
# Direct invocation
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    force = "--force" in sys.argv
    try:
        initialize_vocabulary(force=force)
    except (EnvironmentError, ValueError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)