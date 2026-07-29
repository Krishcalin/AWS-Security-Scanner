"""aws_dspm — the DSPM read-surface. Covers classify() (tag value -> data_type, Macie score ->
tier-only, secret, unclassified), apply_dspm() stamping WQL-queryable props on datastore nodes
only, compute_inventory() (counts / exposure rank / reader_count / classification gaps), the
service data_inventory + org roll-up + DSPM-GAP display-only finding, the WQL data_types facet,
and that the new props are inert to the byte-frozen aws_correlate score. Pure/offline."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_dspm
import aws_state
import cnapp_connectors as cc
from aws_graph import SecurityGraph
from cnapp_registry import AccountRegistry
from cnapp_service import InMemoryResultStore, PlatformService

ACCT = "111122223333"
PII = "arn:aws:s3:::customers"
PCI = "arn:aws:rds:us-east-1:1:db/payments"
UNK = "arn:aws:s3:::logs"


# ── classify ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("props,types,tier,classifier", [
    ({"sensitivity": "pci"}, ["PCI"], "restricted", "tag"),
    ({"sensitivity": "hipaa"}, ["PHI"], "restricted", "tag"),
    ({"sensitivity": "pii"}, ["PII"], "restricted", "tag"),
    ({"sensitivity": "confidential"}, [], "confidential", "tag"),
    ({"sensitivity": 82}, [], "restricted", "macie-auto"),        # Macie score -> tier, no type
    ({"sensitivity": 60}, [], "confidential", "macie-auto"),
    ({"secret": True}, ["SECRET"], "restricted", "secret"),
    ({"sensitivity": "flagged"}, [], "internal", "tag"),          # untyped -> a classification gap
    ({}, [], "", "unclassified"),
])
def test_classify(props, types, tier, classifier):
    c = aws_dspm.classify(props)
    assert c["data_types"] == types and c["sensitivity_tier"] == tier and c["classifier"] == classifier


def test_classify_ignores_stray_bool_sensitivity():
    assert aws_dspm.classify({"sensitivity": True})["classifier"] == "unclassified"


def test_boolean_pii_phi_tag_keeps_the_data_type():
    # a `phi = true` / `pii = yes` boolean tag must keep the TYPE (from the key), not "flagged" —
    # else DSPM drops the data type and fires a spurious classification gap.
    import aws_deepplane
    assert aws_deepplane.is_crown_jewel_by_tags([{"Key": "phi", "Value": "true"}])["sensitivity"] == "phi"
    assert aws_deepplane.is_crown_jewel_by_tags([{"Key": "PII", "Value": "yes"}])["sensitivity"] == "pii"
    # a generic crown-jewel boolean stays "flagged" (no specific type implied)
    assert aws_deepplane.is_crown_jewel_by_tags([{"Key": "crownjewel", "Value": "true"}])["sensitivity"] == "flagged"
    # and the type survives all the way through classify()
    assert aws_dspm.classify({"sensitivity": "phi"})["data_types"] == ["PHI"]


# ── apply_dspm ──────────────────────────────────────────────────────────────────
def test_apply_dspm_stamps_datastores_only():
    g = SecurityGraph()
    g.add_node(PII, "S3Bucket", crown_jewel=True, sensitivity="pii")
    g.add_node("i-web", "EC2Instance", name="web")               # not a datastore
    n = aws_dspm.apply_dspm(g)
    assert n == 1
    assert (g.node(PII)["props"] or {}).get("data_types") == ["PII"]
    assert "data_types" not in (g.node("i-web")["props"] or {})


# ── compute_inventory ───────────────────────────────────────────────────────────
def _inv_graph():
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node(PII, "S3Bucket", name="customers", crown_jewel=True, sensitivity="pii",
               public=True, encrypted=False)
    g.add_node(PCI, "RDSInstance", name="payments", crown_jewel=True, sensitivity="pci", encrypted=True)
    g.add_node(UNK, "S3Bucket", name="logs", crown_jewel=True, sensitivity=68, encrypted=True)
    g.add_node("r", "IAMRole", name="role")
    g.add_edge("r", PII, "CAN_READ_DATA")
    g.add_edge("r", PCI, "CAN_READ_DATA")
    g.add_edge("internet", PII, "EXPOSED_TO")
    return g


def test_inventory_counts_types_exposure_readers_gaps():
    inv = aws_dspm.compute_inventory(_inv_graph(), ACCT)
    assert inv["total"] == 3 and inv["exposed"] == 1 and inv["unencrypted"] == 1
    assert inv["by_type"] == {"PII": 1, "PCI": 1}
    assert [g["label"] for g in inv["classification_gaps"]] == ["logs"]   # Macie-scored, untyped
    top = inv["stores"][0]
    assert top["label"] == "customers" and top["exposure_rank"] == 3 and top["reader_count"] == 1


def test_inventory_no_internet_node_is_honest():
    g = SecurityGraph()
    g.add_node(PII, "S3Bucket", name="c", crown_jewel=True, sensitivity="pii", public=False, encrypted=True)
    inv = aws_dspm.compute_inventory(g, ACCT)
    assert inv["exposed"] == 0 and inv["stores"][0]["reachable_from_internet"] is False


def test_encryption_absent_is_unknown_not_unencrypted():
    # a Secrets Manager secret is always KMS-encrypted; an ABSENT encrypted prop is UNKNOWN, not a
    # known-unencrypted risk. Only an explicit encrypted==False inflates the tally / exposure_rank.
    g = SecurityGraph()
    g.add_node("secret:s", "Secret", name="db-creds", crown_jewel=True, secret=True)          # no encrypted prop
    g.add_node("ai:a", "SageMakerModel", name="model", crown_jewel=True, sensitivity="ai-data")  # absent
    g.add_node("s3:bad", "S3Bucket", name="raw", crown_jewel=True, sensitivity="pii", encrypted=False)  # explicit
    inv = aws_dspm.compute_inventory(g, ACCT)
    by_id = {s["node_id"]: s for s in inv["stores"]}
    assert by_id["secret:s"]["encrypted"] is True and by_id["secret:s"]["exposure_rank"] == 0
    assert by_id["ai:a"]["exposure_rank"] == 0                # absent -> unknown, not penalized
    assert by_id["s3:bad"]["exposure_rank"] == 1             # explicit False -> at risk
    assert inv["unencrypted"] == 1                            # only the explicit-False store
    assert "_unencrypted" not in inv["stores"][0]            # internal helper stripped


# ── service + WQL + finding ──────────────────────────────────────────────────────
def _svc(graph=None):
    reg = AccountRegistry.open(":memory:")
    results = InMemoryResultStore()
    payload = {"account": ACCT, "results": [], "attack_paths": [], "finding_catalog": []}
    if graph is not None:
        payload["graph_full"] = graph.to_dict()
    results.put(ACCT, payload)
    reg.upsert_account(ACCT, now_epoch=1000, role_arn="r", external_id_ref="ssm://x")
    reg.set_onboarding_status(ACCT, "active", 1000)
    return PlatformService(
        registry=reg, results=results, hub_role_arn="a", cfn_template_url="b",
        secret_writer=lambda a, v: "x", secret_reader=lambda r: "x",
        connectors=cc.ConnectorStore(reg._be), state=aws_state.StateStore(reg._be), clock=lambda: 5000)


def test_service_data_inventory_and_none_without_scan():
    svc = _svc(_inv_graph())
    assert svc.data_inventory(ACCT)["total"] == 3
    assert _svc(graph=None).data_inventory(ACCT) is None


def test_org_data_inventory_rollup():
    org = _svc(_inv_graph()).org_data_inventory()
    assert org["overall"]["total"] == 3 and org["by_type"] == {"PII": 1, "PCI": 1}
    assert org["accounts"][0]["gap_count"] == 1


def test_wql_data_types_facet_is_live():
    svc = _svc(_inv_graph())
    q = {"where": {"pred": "prop", "field": "data_types", "op": "contains", "value": "PII"}}
    assert [n["label"] for n in svc.run_wql(ACCT, q)["nodes"]] == ["customers"]


def test_dspm_gap_finding_display_only():
    svc = _svc(_inv_graph())
    svc.results.put(ACCT, {**(svc.results.get_latest(ACCT)), "posture_score": 80})
    cat = svc.get_finding_catalog(ACCT)
    gap = [f for f in cat if f["check_id"] == "DSPM-GAP"]
    assert len(gap) == 1 and gap[0]["status"] == "WARN" and gap[0]["affected"] == [UNK]
    assert svc.get_account_summary(ACCT)["posture_score"] == 80    # never touches posture


def test_dspm_props_inert_to_frozen_correlate():
    import aws_correlate
    # aws_correlate reads only crown_jewel / public / name off a data node — never data_types/tier
    src = open(aws_correlate.__file__, encoding="utf-8").read()
    for prop in ("data_types", "sensitivity_tier", "classifier"):
        # may appear only in a comment, never in a props.get(...) read
        assert f'props.get(\"{prop}\"' not in src and f"props.get('{prop}'" not in src
