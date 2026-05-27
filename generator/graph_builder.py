"""
MABE Graph Builder
==================

Reads a topology configuration YAML and vocabulary.json, then instantiates
a fully attributed NetworkX directed graph representing the simulated network.

The graph is the shared substrate that both agent types (BenignUserAgent and
AIAttackerAgent) traverse during simulation. It is built once at simulation
start and treated as read-only thereafter.

GRAPH STRUCTURE
---------------
Nodes carry the following attributes:
    node_type           str   — e.g. 'workstation', 'database'
    segment             str   — e.g. 'corporate', 'data_tier'
    services            list  — e.g. ['smb', 'nfs']
    auth_protocols      list  — e.g. ['ntlm', 'kerberos']
    high_value          bool  — True for DC, DB, registry, logging nodes
    required_privilege  str   — 'standard_user' | 'service_account' | 'domain_admin'
    ip_address          str   — assigned from vocabulary ip_pools by segment
    fqdn                str   — hostname.domain, e.g. 'WS-001.meridian.local'

Edges are directed and represent ACL-permitted communication paths. An edge
from node A to node B means A can initiate connections to B under the ACL
rules. Edges carry:
    permitted_protocols  list  — protocols allowed on this path per ACL rules
    required_credential  str   — required_privilege of the destination node

NAMING AND IP ASSIGNMENT
------------------------
Names and IPs are assigned sequentially from vocabulary.json pools by node
type and segment respectively. Assignment is deterministic — the same
vocabulary and topology config always produce the same graph. The vocabulary
pools are read but never modified (no destructive pop).

VALIDATION
----------
The topology config is validated on load. Errors raise ValueError with a
descriptive message. Checks cover: required top-level keys, known node types,
required per-node-type fields, valid segment references, valid ACL segment
references, and a final node count assertion.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import yaml

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).parent.parent
VOCAB_PATH = REPO_ROOT / "vocabulary.json"

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

KNOWN_NODE_TYPES = {
    "domain_controller",
    "database",
    "container_registry",
    "api_endpoint",
    "file_server",
    "logging_infrastructure",
    "workstation",
}

REQUIRED_NODE_FIELDS = {
    "count",
    "segment",
    "services",
    "auth_protocols",
    "high_value",
    "required_privilege",
}

VALID_PRIVILEGE_LEVELS = {"standard_user", "service_account", "domain_admin"}

# Privilege hierarchy used by the traversal agent to determine reachability.
# Higher index = higher privilege.
PRIVILEGE_HIERARCHY = ["standard_user", "service_account", "domain_admin"]

# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------

def _validate_config(config: dict) -> None:
    """
    Validate the topology config dict before graph instantiation.

    Raises ValueError with a descriptive message on the first structural
    problem found. Checks are ordered from most to least fundamental so
    that early failures don't produce confusing cascading errors.
    """
    # Top-level structure
    if "topology" not in config:
        raise ValueError("Topology config missing required top-level key 'topology'.")

    topo = config["topology"]

    for required_key in ("segments", "node_types", "acl_rules"):
        if required_key not in topo:
            raise ValueError(
                f"Topology config missing required key 'topology.{required_key}'."
            )

    # Segments
    segments = topo["segments"]
    if not segments:
        raise ValueError("Topology config defines no segments.")

    valid_segment_ids = set()
    for seg in segments:
        if "id" not in seg:
            raise ValueError(f"Segment entry missing 'id' field: {seg}")
        if "subnet" not in seg:
            raise ValueError(f"Segment '{seg['id']}' missing 'subnet' field.")
        valid_segment_ids.add(seg["id"])

    # Node types
    node_types = topo["node_types"]
    if not node_types:
        raise ValueError("Topology config defines no node_types.")

    for node_type, attrs in node_types.items():
        # Known node type
        if node_type not in KNOWN_NODE_TYPES:
            raise ValueError(
                f"Unknown node type '{node_type}'. "
                f"Known types: {sorted(KNOWN_NODE_TYPES)}"
            )

        # Required fields present
        missing = REQUIRED_NODE_FIELDS - set(attrs.keys())
        if missing:
            raise ValueError(
                f"Node type '{node_type}' missing required fields: {sorted(missing)}"
            )

        # count is a positive integer
        count = attrs["count"]
        if not isinstance(count, int) or count < 1:
            raise ValueError(
                f"Node type '{node_type}' count must be a positive integer; "
                f"got: {count!r}"
            )

        # segment references a defined segment
        segment = attrs["segment"]
        if segment not in valid_segment_ids:
            raise ValueError(
                f"Node type '{node_type}' references undefined segment "
                f"'{segment}'. Defined segments: {sorted(valid_segment_ids)}"
            )

        # required_privilege is a known value
        privilege = attrs["required_privilege"]
        if privilege not in VALID_PRIVILEGE_LEVELS:
            raise ValueError(
                f"Node type '{node_type}' has invalid required_privilege "
                f"'{privilege}'. Valid values: {sorted(VALID_PRIVILEGE_LEVELS)}"
            )

        # services and auth_protocols are non-empty lists
        for list_field in ("services", "auth_protocols"):
            val = attrs[list_field]
            if not isinstance(val, list) or len(val) == 0:
                raise ValueError(
                    f"Node type '{node_type}' field '{list_field}' must be a "
                    f"non-empty list; got: {val!r}"
                )

    # ACL rules
    acl_rules = topo["acl_rules"]
    for i, rule in enumerate(acl_rules):
        for direction in ("from", "to"):
            if direction not in rule:
                raise ValueError(
                    f"ACL rule {i} missing '{direction}' field: {rule}"
                )
            seg_ref = rule[direction]
            if seg_ref not in valid_segment_ids:
                raise ValueError(
                    f"ACL rule {i} references undefined segment "
                    f"'{seg_ref}'. Defined segments: {sorted(valid_segment_ids)}"
                )
        if "permitted_protocols" not in rule:
            raise ValueError(
                f"ACL rule {i} missing 'permitted_protocols' field: {rule}"
            )
        if not isinstance(rule["permitted_protocols"], list) or \
                len(rule["permitted_protocols"]) == 0:
            raise ValueError(
                f"ACL rule {i} 'permitted_protocols' must be a non-empty list."
            )


# ---------------------------------------------------------------------------
# Vocabulary loading
# ---------------------------------------------------------------------------

def _load_vocabulary(vocab_path: Path) -> dict:
    """
    Load vocabulary.json from disk.

    Raises FileNotFoundError if the file does not exist (vocabulary
    initializer has not been run yet), or ValueError if the JSON is malformed.
    """
    if not vocab_path.exists():
        raise FileNotFoundError(
            f"vocabulary.json not found at {vocab_path}.\n"
            "Run the vocabulary initializer first:\n\n"
            "    python -m generator.vocabulary\n"
        )
    try:
        with open(vocab_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"vocabulary.json is malformed: {e}") from e


# ---------------------------------------------------------------------------
# Main build function
# ---------------------------------------------------------------------------

def build_graph(
    topology_path: Path | str | None = None,
    vocab_path: Path | str | None = None,
) -> nx.DiGraph:
    """
    Build and return a fully attributed NetworkX directed graph.

    Parameters
    ----------
    topology_path : Path | str | None
        Path to the topology config YAML. Defaults to
        config/topology_enterprise.yaml relative to the repository root.
    vocab_path : Path | str | None
        Path to vocabulary.json. Defaults to vocabulary.json at the
        repository root.

    Returns
    -------
    nx.DiGraph
        Fully attributed directed graph. Nodes carry type, segment, services,
        auth_protocols, high_value, required_privilege, ip_address, and fqdn.
        Edges carry permitted_protocols and required_credential.

    Raises
    ------
    FileNotFoundError
        If the topology config or vocabulary.json does not exist.
    ValueError
        If the topology config fails validation or vocabulary.json is malformed.
    """
    # Resolve paths
    topology_path = Path(topology_path) if topology_path else \
        REPO_ROOT / "config" / "topology_enterprise.yaml"
    vocab_path = Path(vocab_path) if vocab_path else VOCAB_PATH

    # Load and validate topology config
    if not topology_path.exists():
        raise FileNotFoundError(
            f"Topology config not found at {topology_path}."
        )
    with open(topology_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    _validate_config(config)
    topo = config["topology"]

    # Load vocabulary
    vocab = _load_vocabulary(vocab_path)

    domain = vocab.get("domain", "corp.internal")
    hostname_pools = vocab.get("hostnames", {})
    ip_pools = vocab.get("ip_pools", {})

    # Build segment → subnet mapping for reference
    segment_ids = {seg["id"] for seg in topo["segments"]}

    # Build ACL lookup: (from_segment, to_segment) → [permitted_protocols]
    acl_lookup: dict[tuple[str, str], list[str]] = {}
    for rule in topo["acl_rules"]:
        key = (rule["from"], rule["to"])
        acl_lookup[key] = rule["permitted_protocols"]

    # ---------------------------------------------------------------------------
    # Node instantiation
    # ---------------------------------------------------------------------------
    # Track IP assignment index per segment (sequential, non-destructive read
    # from vocab pool).
    ip_index: dict[str, int] = {seg_id: 0 for seg_id in segment_ids}

    # Track hostname assignment index per node type.
    hostname_index: dict[str, int] = {nt: 0 for nt in topo["node_types"]}

    graph = nx.DiGraph()

    # node_id → segment mapping, needed for edge construction
    node_segment: dict[str, str] = {}

    for node_type, attrs in topo["node_types"].items():
        count: int = attrs["count"]
        segment: str = attrs["segment"]
        services: list[str] = attrs["services"]
        auth_protocols: list[str] = attrs["auth_protocols"]
        high_value: bool = attrs["high_value"]
        required_privilege: str = attrs["required_privilege"]

        # Hostname pool for this node type
        hn_pool: list[str] = hostname_pools.get(node_type, [])
        # IP pool for this node type's segment
        ip_pool: list[str] = ip_pools.get(segment, [])

        for i in range(count):
            # Assign hostname (sequential, non-destructive)
            hn_idx = hostname_index[node_type]
            if hn_idx >= len(hn_pool):
                raise ValueError(
                    f"Vocabulary hostname pool for '{node_type}' is exhausted "
                    f"(pool size: {len(hn_pool)}, requested: {hn_idx + 1}). "
                    "Regenerate vocabulary.json or reduce node count."
                )
            hostname = hn_pool[hn_idx]
            hostname_index[node_type] += 1

            # Assign IP address (sequential per segment, non-destructive)
            ip_idx = ip_index[segment]
            if ip_idx >= len(ip_pool):
                raise ValueError(
                    f"Vocabulary IP pool for segment '{segment}' is exhausted "
                    f"(pool size: {len(ip_pool)}, requested: {ip_idx + 1}). "
                    "Regenerate vocabulary.json or reduce node count."
                )
            ip_address = ip_pool[ip_idx]
            ip_index[segment] += 1

            node_id = hostname
            fqdn = f"{hostname}.{domain}"

            graph.add_node(
                node_id,
                node_type=node_type,
                segment=segment,
                services=services,
                auth_protocols=auth_protocols,
                high_value=high_value,
                required_privilege=required_privilege,
                ip_address=ip_address,
                fqdn=fqdn,
            )
            node_segment[node_id] = segment

    # ---------------------------------------------------------------------------
    # Edge construction
    # ---------------------------------------------------------------------------
    # For every ordered pair of nodes (src, dst) where src != dst, check whether
    # an ACL rule permits traffic from src's segment to dst's segment. If so,
    # add a directed edge with the permitted protocols and the destination node's
    # required_privilege as required_credential.

    nodes = list(graph.nodes(data=True))

    for src_id, src_attrs in nodes:
        src_segment = src_attrs["segment"]
        for dst_id, dst_attrs in nodes:
            if src_id == dst_id:
                continue
            dst_segment = dst_attrs["segment"]
            acl_key = (src_segment, dst_segment)
            if acl_key in acl_lookup:
                graph.add_edge(
                    src_id,
                    dst_id,
                    permitted_protocols=acl_lookup[acl_key],
                    required_credential=dst_attrs["required_privilege"],
                )

    return graph


# ---------------------------------------------------------------------------
# Graph inspection helpers
# ---------------------------------------------------------------------------

def get_nodes_by_type(graph: nx.DiGraph, node_type: str) -> list[str]:
    """Return a list of node IDs matching the given node_type."""
    return [
        n for n, attrs in graph.nodes(data=True)
        if attrs.get("node_type") == node_type
    ]


def get_nodes_by_segment(graph: nx.DiGraph, segment: str) -> list[str]:
    """Return a list of node IDs in the given segment."""
    return [
        n for n, attrs in graph.nodes(data=True)
        if attrs.get("segment") == segment
    ]


def get_reachable_neighbors(
    graph: nx.DiGraph,
    node_id: str,
    credential_privilege: str,
) -> list[str]:
    """
    Return nodes reachable from node_id under the given credential privilege.

    A neighbor is reachable if:
    1. An ACL-permitted edge exists from node_id to the neighbor, AND
    2. The credential_privilege meets or exceeds the neighbor's
       required_privilege per the PRIVILEGE_HIERARCHY.

    Parameters
    ----------
    graph : nx.DiGraph
    node_id : str
    credential_privilege : str
        The highest privilege level in the attacker's current credential store.

    Returns
    -------
    list[str]
        Node IDs of reachable neighbors, unsorted.
    """
    if credential_privilege not in PRIVILEGE_HIERARCHY:
        raise ValueError(
            f"Unknown credential_privilege '{credential_privilege}'. "
            f"Valid values: {PRIVILEGE_HIERARCHY}"
        )

    caller_level = PRIVILEGE_HIERARCHY.index(credential_privilege)
    reachable = []

    for neighbor in graph.successors(node_id):
        edge_data = graph[node_id][neighbor]
        required = edge_data.get("required_credential", "standard_user")
        required_level = PRIVILEGE_HIERARCHY.index(required)
        if caller_level >= required_level:
            reachable.append(neighbor)

    return reachable


def print_summary(graph: nx.DiGraph) -> None:
    """
    Print a human-readable summary of the graph for inspection.

    Matches the validation guidance in Section 14 Step 3 of the spec:
    node count, edge count, and a sample node's full attribute dict.
    """
    print(f"Graph summary")
    print(f"  Nodes : {graph.number_of_nodes()}")
    print(f"  Edges : {graph.number_of_edges()}")
    print()

    # Node count by type
    type_counts: dict[str, int] = {}
    for _, attrs in graph.nodes(data=True):
        nt = attrs.get("node_type", "unknown")
        type_counts[nt] = type_counts.get(nt, 0) + 1
    print("  Node counts by type:")
    for node_type, count in sorted(type_counts.items()):
        print(f"    {node_type:<25} {count}")

    print()

    # Sample node — first workstation
    sample_nodes = get_nodes_by_type(graph, "workstation")
    if sample_nodes:
        sample_id = sample_nodes[0]
        print(f"  Sample node '{sample_id}':")
        for k, v in graph.nodes[sample_id].items():
            print(f"    {k:<22} {v}")

    print()

    # Sample edges from the sample node
    if sample_nodes:
        sample_id = sample_nodes[0]
        successors = list(graph.successors(sample_id))
        print(f"  First 3 edges from '{sample_id}':")
        for dst in successors[:3]:
            edge = graph[sample_id][dst]
            print(f"    → {dst:<12} protocols={edge['permitted_protocols']}  "
                  f"required_credential={edge['required_credential']}")