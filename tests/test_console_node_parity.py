"""Phase 0 · slice 0.5 — every node kind the product emits can actually be drawn.

`nodeMeta` falls back to `{icon: Circle, label: kind}`, so a missing entry is not an
error anywhere: the graph draws a grey circle labelled with the raw class name and
carries on. That silence is how **34 of 47 kinds** came to have no entry — including
`S3Bucket`, the terminal the flagship attack path ends at and the first node a buyer
looks at, plus the entire DSPM crown-jewel datastore family.

ON THE EXPLICIT LIST BELOW. It is deliberate, and it is the second time this lesson
has been learned in this phase. Node kinds reach the graph through at least four
shapes: a literal in `add_node(id, "Kind")`; a helper call site,
`_dspm_emit(g, arn, "Kind", ...)`; a tuple in a table of describe-calls; and a plain
conditional, `kind = "IAMUser" if ... else "IAMRole"`. No single regex sees all four,
and one loose enough to try (`"kind": "X"`) matches every unrelated dict in the
codebase that happens to have a `kind` field — `choke`, `finding`, `path`, `resource`.
So the universe is written down, and a narrow drift check guards the one shape a regex
CAN read reliably, which is enough to stop the list rotting.
"""
from __future__ import annotations

import glob
import os
import re
import sys

import pytest

from _layout import module_files

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODES_TS = os.path.join(ROOT, "frontend", "src", "lib", "nodes.ts")
QUERYBUILDER_TS = os.path.join(ROOT, "frontend", "src", "lib", "querybuilder.ts")

# `Unknown` is the placeholder add_edge creates for an endpoint not yet resolved; a
# later add_node upgrades it, and it is never meant to be rendered as itself.
PLACEHOLDER = "Unknown"

KNOWN_KINDS = frozenset({
    # entry points and capabilities
    "InternetSource", "AnyPrincipal", "ObservedCidr", "AdminCapability",
    "KubeAdminCapability",
    # identity
    "IAMRole", "IAMUser", "IAMPrincipal", "FederatedPrincipal", "ServicePrincipal",
    "InstanceProfile", "AWSAccount",
    # compute and edge
    "EC2Instance", "LambdaFunction", "ECSTaskDefinition", "ECSFargateTask",
    "ECRImage", "ECRRepository", "LoadBalancer", "ApiGateway",
    "CloudFrontDistribution", "NetworkInterface", "SecurityGroup",
    "DanglingDNSRecord",
    # kubernetes
    "KubePod", "KubeServiceAccount",
    # crown-jewel data terminals (most arrive via _dspm_emit, not add_node)
    "S3Bucket", "RDSInstance", "RDSCluster", "RedshiftCluster", "DynamoDBTable",
    "EFSFileSystem", "FSxFileSystem", "OpenSearchDomain", "MemoryDBCluster",
    "KinesisStream", "TimestreamTable", "Secret", "SecretsManagerSecret", "KMSKey",
    # annotations
    "Vulnerability", "ThreatFinding", "CdrDetection",
    # AI pillar (arrive as a stash `kind` passed through as a variable)
    "SageMakerNotebook", "SageMakerDomain", "BedrockAgent", "AIResource",
    "AgentCoreRuntime", "AgentCoreGateway",
    # Phase 3: a computed flow, not a resource — it annotates the graph the way
    # Vulnerability and ThreatFinding do.
    "ToxicFlow",
    # Phase 3 slice 3.5: a result the OPERATOR produced, annotating the graph.
    "PentestResult",
})


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _add_node_literals():
    """The one emission shape a regex reads reliably: add_node(id, "Kind").

    The glob is NOT recursive, so if these modules ever move into a
    subdirectory it returns no paths, the kind set is empty, and parity against
    the console holds trivially -- a green test asserting nothing.
    """
    paths = module_files()
    kinds = set()
    for path in paths:
        kinds.update(re.findall(r'add_node\([^,]+,\s*"([A-Za-z][A-Za-z0-9_]*)"',
                                _read(path)))
    assert kinds, "no add_node(id, \"Kind\") literals found at all"
    return kinds - {PLACEHOLDER}


def _drawable_kinds():
    body = _read(NODES_TS)
    block = re.search(r"const META[^=]*=\s*\{(.*?)\n\}", body, re.S)
    assert block, "could not find the META map in nodes.ts"
    return set(re.findall(r"^\s{2}([A-Za-z][A-Za-z0-9_]*):\s*\{\s*icon:",
                          block.group(1), re.M))


# ── the parity that matters ─────────────────────────────────────────────────
def test_every_known_kind_can_be_drawn():
    """A kind with no entry renders as an unlabelled grey circle, and nothing
    anywhere reports that it happened."""
    missing = sorted(KNOWN_KINDS - _drawable_kinds())
    assert not missing, (
        f"{len(missing)} node kind(s) have no nodeMeta entry and will draw as a "
        f"generic circle: {missing}. Add an icon, a human label and a tone to "
        f"frontend/src/lib/nodes.ts.")


def test_the_console_draws_nothing_that_is_not_a_real_kind():
    """The other direction: an icon for a kind nothing emits is dead weight that
    makes the map look more complete than it is."""
    stray = sorted(_drawable_kinds() - KNOWN_KINDS)
    assert not stray, f"nodeMeta has entries for kinds nothing emits: {stray}"


def test_the_known_kind_list_has_not_rotted():
    """THE RATCHET, narrow but reliable. A new add_node literal that is not in
    KNOWN_KINDS fails here, so the written-down universe cannot silently fall behind
    the code even though a regex cannot see every emission shape."""
    unlisted = sorted(_add_node_literals() - KNOWN_KINDS)
    assert not unlisted, (
        f"new node kind(s) emitted but absent from KNOWN_KINDS: {unlisted}. Add them "
        f"here and give them a nodeMeta entry.")


# ── the specific regressions this slice was written for ─────────────────────
def test_the_flagship_terminal_is_drawable():
    """S3Bucket had no entry for the whole life of the graph feature, and it is the
    node the flagship attack path terminates at."""
    meta = _drawable_kinds()
    for kind in ("S3Bucket", "EC2Instance", "IAMRole", "AdminCapability",
                 "InternetSource", "LambdaFunction"):
        assert kind in meta, f"{kind} cannot be drawn"


def test_the_ai_kinds_are_drawable_and_distinguishable():
    """A notebook, a Studio domain and an agent fail differently and are remediated
    differently. Drawing them identically hides that from the reader."""
    body = _read(NODES_TS)
    icons = {}
    for kind in ("SageMakerNotebook", "SageMakerDomain", "BedrockAgent"):
        m = re.search(rf"^\s{{2}}{kind}:\s*\{{\s*icon:\s*(\w+)", body, re.M)
        assert m, f"{kind} has no nodeMeta entry"
        icons[kind] = m.group(1)
    assert len(set(icons.values())) == len(icons), (
        f"AI kinds share icons and are indistinguishable on the graph: {icons}")


def test_no_kind_falls_back_to_its_class_name_as_a_label():
    """The fallback label IS the class name. 'SageMakerNotebook' is not a label."""
    body = _read(NODES_TS)
    for kind in sorted(_drawable_kinds()):
        m = re.search(rf"^\s{{2}}{kind}:.*?label:\s*'([^']+)'", body, re.M | re.S)
        assert m, f"{kind} has no label"
        assert m.group(1) != kind, f"{kind}'s label is just its class name"


# ── the query console ───────────────────────────────────────────────────────
def _query_kinds():
    block = re.search(r"QUERY_KINDS\s*=\s*\[(.*?)\]", _read(QUERYBUILDER_TS), re.S)
    assert block, "QUERY_KINDS not found"
    return {k for k in re.findall(r"'([A-Za-z][A-Za-z0-9_]*)'", block.group(1))}


def test_the_query_console_offers_no_filter_that_can_never_match():
    phantom = sorted(_query_kinds() - KNOWN_KINDS)
    assert not phantom, f"Query console offers kinds nothing emits: {phantom}"


def test_the_ai_kinds_are_queryable():
    """'Which AI resources reach crown data' is the question the AI pillar exists to
    answer, and it cannot be asked if the kinds are not offered as a filter."""
    offered = _query_kinds()
    for kind in ("SageMakerNotebook", "SageMakerDomain", "BedrockAgent"):
        assert kind in offered, f"{kind} is not offered in the Query console"


# ── the demo surface ────────────────────────────────────────────────────────
SAMPLE = os.path.join(ROOT, "frontend", "public", "sample")
AI_PREFIXES = ("BDR-", "AGT-", "AISPM-", "AIPATH-")


def _fixture_findings():
    import json
    out = []
    for path in glob.glob(os.path.join(SAMPLE, "account_*_findings.json")):
        with open(path, encoding="utf-8") as fh:
            out.extend(json.load(fh))
    return out


def _fixture_graph_nodes():
    import json
    out = []
    for path in glob.glob(os.path.join(SAMPLE, "account_*_graph.json")):
        with open(path, encoding="utf-8") as fh:
            out.extend(json.load(fh).get("nodes", []))
    return out


def test_the_ai_dashboard_is_not_empty_in_the_demo():
    """52 fixture files carried zero AI check ids, so /ai-security rendered its empty
    state in every screenshot, trial and product tour. The pillar was invisible in
    exactly the first five minutes a buyer sees."""
    ai = [f for f in _fixture_findings()
          if f["check_id"].startswith(AI_PREFIXES)]
    assert len(ai) >= 8, f"only {len(ai)} AI findings across all sample accounts"
    kinds = {f["check_id"].split("-")[0] for f in ai}
    assert {"BDR", "AGT", "AISPM"} <= kinds, (
        f"the demo should exercise Bedrock, agents and the AI-SPM pillar, got {kinds}")


def test_the_demo_shows_a_clean_ai_account_as_well_as_a_failing_one():
    """An estate where every AI finding FAILs teaches a reader that the pillar only
    ever says no. Passes are what make a failure legible."""
    ai = [f for f in _fixture_findings() if f["check_id"].startswith(AI_PREFIXES)]
    assert any(f["status"] == "FAIL" for f in ai)
    assert any(f["status"] == "PASS" for f in ai)


def test_ai_fixtures_carry_the_real_framework_tags_and_remediation():
    """Derived from COMPLIANCE_MAP / REMEDIATION_MAP / FINDING_DETAIL, not written by
    hand -- a hand-written fixture drifts from the product and demos something the
    scanner does not actually emit."""
    from engine import aws_finding_detail
    from engine.aws_live_scanner import COMPLIANCE_MAP, REMEDIATION_MAP
    for f in _fixture_findings():
        if not f["check_id"].startswith(AI_PREFIXES):
            continue
        cid = f["check_id"]
        assert f["compliance"] == COMPLIANCE_MAP.get(cid, {}), f"{cid} tags drifted"
        assert f["remediation_cmd"] == REMEDIATION_MAP.get(cid, ""), f"{cid} cmd drifted"
        assert f["risk"] == aws_finding_detail.FINDING_DETAIL[cid]["risk"], \
            f"{cid} risk prose drifted"


def test_the_graph_fixtures_contain_drawable_ai_nodes():
    nodes = [n for n in _fixture_graph_nodes() if n.get("ai_resource")]
    assert nodes, "no AI nodes in any sample graph"
    drawable = _drawable_kinds()
    for n in nodes:
        assert n["kind"] in drawable, f"{n['kind']} would draw as a grey circle"


def test_no_fixture_stages_an_attack_path_the_engine_cannot_produce():
    """Slice 0.3 established that the AI exposure signal is EGRESS, so the scanner does
    NOT emit internet -[EXPOSED_TO]-> AI node. A fixture containing one would stage a
    path in the demo that no real scan can reproduce -- the worst kind of fixture."""
    import json
    for path in glob.glob(os.path.join(SAMPLE, "account_*_graph.json")):
        with open(path, encoding="utf-8") as fh:
            g = json.load(fh)
        ai_ids = {n["id"] for n in g.get("nodes", []) if n.get("ai_resource")}
        for e in g.get("edges", []):
            assert not (e.get("source") == "internet" and e.get("target") in ai_ids), (
                f"{os.path.basename(path)} stages an inbound internet edge to an AI "
                f"node, which the scanner does not emit")
