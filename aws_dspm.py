#!/usr/bin/env python3
"""aws_dspm.py — DSPM (Data Security Posture Management) read-surface.

OverWatch already CLASSIFIES sensitive data agentlessly during a scan — Amazon Macie automated
scores (aws_deepplane.is_crown_jewel) and data-classification tags (is_crown_jewel_by_tags) stamp
crown_jewel + a heterogeneous ``sensitivity`` prop (a Macie int score OR a tag value like
"pci"/"hipaa"/"pii") on datastore nodes, and CAN_READ_DATA edges record who can read them. This
module is the READ-TIME surface over that already-collected signal: it normalizes the mixed
``sensitivity`` into explicit ``data_types`` (PII/PCI/PHI/FINANCIAL/SECRET/AI) + a ``sensitivity_tier``
and computes a crown-jewel data inventory + exposure + a classification coverage gap — all from the
STORED graph, with NO new scan, NO file-content read (that stays gated on the deferred EBS
filesystem parse), and NO aws_correlate edit (the new props are inert to the frozen score).

Pure / stdlib / boto3-free (graph in, dicts out). Reuses aws_correlate.crown_nodes + reachability
READ-ONLY.
"""
from __future__ import annotations

from typing import List, Optional

# map a normalized sensitivity token (tag value / Macie-finding category) -> a data-type label.
_TYPE_MAP = {
    "pii": "PII", "personal": "PII", "gdpr": "PII", "ferpa": "PII", "personal_information": "PII",
    "phi": "PHI", "hipaa": "PHI",
    "pci": "PCI", "pci-dss": "PCI", "pcidss": "PCI", "cardholder": "PCI",
    "financial": "FINANCIAL", "financial_information": "FINANCIAL", "glba": "FINANCIAL", "sox": "FINANCIAL",
    "secret": "SECRET", "credentials": "SECRET",
    "ai-data": "AI", "ai": "AI",
}
_DATA_TYPES_ORDER = ["PCI", "PHI", "PII", "FINANCIAL", "SECRET", "AI"]

# tokens that imply the highest tier when they appear as the sensitivity value.
_HIGH_TOKENS = {"restricted", "critical", "secret", "pci", "phi", "pii", "hipaa", "pci-dss",
                "pcidss", "gdpr", "credentials"}
_MED_TOKENS = {"confidential", "sensitive", "high", "financial", "glba", "sox", "ai-data"}

TIER_RANK = {"restricted": 3, "confidential": 2, "internal": 1, "": 0}


def classify(props: dict) -> dict:
    """Normalize a datastore node's heterogeneous signals into ``{data_types, sensitivity_tier,
    classifier}``. Pure over props already on the node — no new lookup. ``classifier`` records the
    provenance (macie-auto | tag | secret | unclassified) so a Macie-scored-but-untyped store is
    honestly surfaced as a classification gap rather than a false 'no sensitive data'."""
    props = props or {}
    sval = props.get("sensitivity")
    types: List[str] = []
    tier = ""
    classifier = "unclassified"

    if props.get("secret"):
        types.append("SECRET"); tier = "restricted"; classifier = "secret"

    if isinstance(sval, bool):
        sval = None                                   # a stray bool is not a sensitivity signal
    if isinstance(sval, (int, float)):
        # Macie automated score (0-100). >50 is already the crown threshold; band the tier.
        classifier = "macie-auto"
        tier = "restricted" if sval >= 75 else "confidential"
        # a bare score carries no data TYPE — that needs Macie GetFindings (deferred deepening).
    elif isinstance(sval, str) and sval.strip():
        token = sval.strip().lower()
        classifier = "tag" if classifier == "unclassified" else classifier
        t = _TYPE_MAP.get(token)
        if t and t not in types:
            types.append(t)
        if token in _HIGH_TOKENS:
            tier = tier or "restricted"
        elif token in _MED_TOKENS:
            tier = tier or "confidential"
        else:
            tier = tier or "internal"

    # AI-data / DataStore secondary hints
    if props.get("sensitivity") == "ai-data" and "AI" not in types:
        types.append("AI")

    types = [t for t in _DATA_TYPES_ORDER if t in types]     # stable, deduped
    return {"data_types": types, "sensitivity_tier": tier, "classifier": classifier}


def apply_dspm(graph) -> int:
    """Stamp normalized ``data_types`` / ``sensitivity_tier`` / ``classifier`` (MERGE, in place)
    on every crown-jewel / DataStore node. Read-time overlay: the caller rehydrates graph_full,
    applies this, then queries — so graph_full stays pristine and aws_correlate is untouched.
    Makes data_types / sensitivity_tier WQL-queryable. Returns the count enriched."""
    n = 0
    for node in graph.nodes():
        props = node.get("props") or {}
        if not (props.get("crown_jewel") or props.get("DataStore")):
            continue
        c = classify(props)
        graph.add_node(node["id"], node["kind"],
                       data_types=c["data_types"] or None, sensitivity_tier=c["sensitivity_tier"] or None,
                       classifier=c["classifier"])
        n += 1
    return n


def _seg(nid: str) -> str:
    return nid.rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def compute_inventory(graph, account: Optional[str] = None) -> dict:
    """The crown-jewel data inventory over the STORED graph: each sensitive datastore with its
    normalized classification, encryption/public state, reader-role count, and attack-path
    exposure; a per-tier / per-type roll-up; and a CLASSIFICATION-GAP list (crown stores whose
    data type is unknown — Macie-scored-but-untyped or unclassified — the honest 'enable Macie /
    tag it' signal in place of a byte-level content scan). Reuses aws_correlate reachability
    UNCHANGED."""
    import aws_correlate

    crowns = aws_correlate.crown_nodes(graph)                 # prop-based crown ids
    # reader counts: who has a CAN_READ_DATA edge INTO each crown (the data-access map)
    readers: dict = {}
    for e in graph.edges("CAN_READ_DATA"):
        readers[e["dst"]] = readers.get(e["dst"], 0) + 1
    # exposure: crown stores reachable from the internet (forward from InternetSource)
    exposed: set = set()
    if graph.node("internet") is not None:
        exposed = set(graph.reachable("internet", aws_correlate.E_PATH, max_hops=64).keys())

    stores: List[dict] = []
    for nid in crowns:
        nd = graph.node(nid) or {}
        props = nd.get("props") or {}
        c = classify(props)
        is_exposed = nid in exposed
        # a Secrets Manager secret is always KMS-encrypted; an ABSENT encrypted prop is UNKNOWN,
        # not a known-unencrypted risk — only an explicit encrypted==False counts as at-risk (so we
        # never inflate the unencrypted tally / exposure_rank for stores that don't report it).
        enc = props.get("encrypted")
        encrypted = bool(enc) or bool(props.get("secret"))
        known_unencrypted = (enc is False) and not props.get("secret")
        stores.append({
            "node_id": nid, "kind": nd.get("kind", "Unknown"),
            "label": props.get("name") or _seg(nid),
            "data_types": c["data_types"], "sensitivity_tier": c["sensitivity_tier"],
            "classifier": c["classifier"],
            "public": bool(props.get("public")), "encrypted": encrypted,
            "reachable_from_internet": is_exposed,
            "reader_count": readers.get(nid, 0),
            "_unencrypted": known_unencrypted,
            # exposure rank: publicly-reachable & KNOWN-unencrypted is the headline data-at-risk
            "exposure_rank": (2 if props.get("public") or is_exposed else 0)
                             + (1 if known_unencrypted else 0),
        })
    stores.sort(key=lambda s: (-s["exposure_rank"], s["kind"], s["node_id"]))

    by_type: dict = {}
    for s in stores:
        for t in s["data_types"]:
            by_type[t] = by_type.get(t, 0) + 1
    by_tier: dict = {}
    for s in stores:
        tier = s["sensitivity_tier"] or "unclassified"
        by_tier[tier] = by_tier.get(tier, 0) + 1

    gaps = [s for s in stores if not s["data_types"]]        # crown, but data type unknown
    unencrypted = sum(1 for s in stores if s["_unencrypted"])
    for s in stores:
        del s["_unencrypted"]                                 # internal helper — not in the API shape
    return {
        "total": len(stores),
        "exposed": sum(1 for s in stores if s["reachable_from_internet"] or s["public"]),
        "unencrypted": unencrypted,
        "by_type": by_type, "by_tier": by_tier,
        "stores": stores,
        "classification_gaps": gaps,
    }
