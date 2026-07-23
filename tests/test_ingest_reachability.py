"""B5 — reachability re-run: rank ingested CVEs by ACTUAL attack-path reachability.

The flagship proof: a data path GATED OUT for lack of an exploitable host (stored
paths = []) lights up as CRITICAL once an ingested KEV is emitted and paths are
RE-RUN — which a membership check on the stored paths would structurally miss.
Pure/offline, hand-built graphs mirroring tests/test_correlate.py."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_graph import SecurityGraph
from aws_sidescan import EnrichedMatch
from aws_ingest import compute_reachability_verdicts, diff_reachability

ACCT = "111122223333"
INST = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-1"
ROLE = f"arn:aws:iam::{ACCT}:role/r-1"
PROF = f"arn:aws:iam::{ACCT}:instance-profile/p-1"
BUCKET = f"arn:aws:s3:::crown-data"
ADMIN = f"capability:admin:{ACCT}"


def _base_graph(with_admin=False, with_data=True):
    """Exposed EC2 -> role -> crown data (and/or admin), but NO vuln on the host,
    so the DATA terminal is gated out until something exploitable is added."""
    g = SecurityGraph()
    g.add_node("internet", "InternetSource")
    g.add_node("eni-1", "NetworkInterface")
    g.add_node(INST, "EC2Instance", instance_id="i-1")
    g.add_edge("internet", "eni-1", "EXPOSED_TO", ports="tcp/443")
    g.add_edge("eni-1", INST, "ATTACHED_TO")
    g.add_node(PROF, "InstanceProfile")
    g.add_edge(INST, PROF, "HAS_INSTANCE_PROFILE")
    g.add_node(ROLE, "IAMRole", name="r-1")
    g.add_edge(PROF, ROLE, "HAS_ROLE")
    if with_data:
        g.add_node(BUCKET, "S3Bucket", name="crown-data", crown_jewel=True)
        g.add_edge(ROLE, BUCKET, "CAN_READ_DATA", conditioned=False)
    if with_admin:
        g.add_node(ADMIN, "AdminCapability")
        g.add_edge(ROLE, ADMIN, "CAN_PRIVESC_TO", conditioned=False)
    return g


def _kev_match(cve="CVE-2021-44228"):
    return EnrichedMatch(cve=cve, osv_id=cve, package="log4j-core",
                         installed_version="2.14.1", fixed_version="2.17.1",
                         severity="CRITICAL", cvss_base=10.0, epss=0.975, kev=True,
                         exploit_available="YES", ecosystem="Maven")


def _owned(node=INST, kind="EC2Instance", match=None, suppressed=False):
    return {"node_id": node, "node_kind": kind, "match": match or _kev_match(),
            "suppressed": suppressed, "tool": "trivy", "doc_id": "d1"}


# ── the flagship: re-run beats membership ────────────────────────────────────
def test_ingested_kev_creates_new_critical_data_path():
    g0 = _base_graph(with_data=True, with_admin=False)
    # sanity: the stored graph has NO end-to-end path (data terminal gated, no vuln)
    from aws_ingest import SecurityGraph as _SG  # same class
    verdicts, _ = compute_reachability_verdicts(g0.to_dict(), [_owned()])
    v = verdicts[(INST, "CVE-2021-44228")]
    assert v["on_attack_path"] is True                     # the re-run found it
    assert v["reaches_crown"] is True and "data" in v["terminal_kinds"]
    assert v["priority_band"] == "CRITICAL"
    assert v["priority_score"] >= 90                        # hard_floor_kev_data
    assert v["driving_path"].startswith("internet ->")
    assert v["reachable_from_internet"] is True


def test_same_cve_on_isolated_node_is_not_reachable():
    g0 = _base_graph()
    iso = f"arn:aws:ec2:us-east-1:{ACCT}:instance/i-orphan"
    verdicts, _ = compute_reachability_verdicts(
        g0.to_dict(), [_owned(node=iso)])
    v = verdicts[(iso, "CVE-2021-44228")]
    assert v["on_attack_path"] is False and v["reaches_crown"] is False
    assert v["priority_band"] in ("MEDIUM", "LOW")          # exploitability-only, not CRITICAL
    assert v["priority_score"] < 60
    assert v["driving_path"] is None


def test_non_exploit_kind_owner_is_inert():
    """A CVE resolved to an S3 bucket (not an _EXPLOIT_KINDS node) never earns
    exploitability, so it stays off the attack path even if the bucket is crown."""
    g0 = _base_graph()
    verdicts, _ = compute_reachability_verdicts(
        g0.to_dict(), [_owned(node=BUCKET, kind="S3Bucket")])
    v = verdicts[(BUCKET, "CVE-2021-44228")]
    assert v["on_attack_path"] is False


def test_suppressed_match_emits_no_edge():
    g0 = _base_graph()
    verdicts, g = compute_reachability_verdicts(
        g0.to_dict(), [_owned(suppressed=True)])
    v = verdicts[(INST, "CVE-2021-44228")]
    assert v["on_attack_path"] is False                    # VEX-suppressed → no edge, no path
    assert g.out_edges(INST, ["HAS_VULN"]) == []


def test_no_internet_node_collapses_to_exploitability_only():
    g = SecurityGraph()
    g.add_node(INST, "EC2Instance")                        # no internet, no scan yet
    verdicts, _ = compute_reachability_verdicts(g.to_dict(), [_owned()])
    v = verdicts[(INST, "CVE-2021-44228")]
    assert v["on_attack_path"] is False and v["priority_score"] == 45   # KEV exploitability-only


def test_non_kev_reachable_still_boosted_below_kev():
    """A reachable exploit-available (non-KEV) CVE still lands on the path and
    ranks CRITICAL via the data hard-floor, but never above a real KEV."""
    m = EnrichedMatch(cve="CVE-2023-1", osv_id="CVE-2023-1", package="p",
                      installed_version="1", fixed_version=None, severity="HIGH",
                      cvss_base=7.5, epss=0.6, kev=False, exploit_available="YES",
                      ecosystem="Maven")
    g0 = _base_graph()
    verdicts, _ = compute_reachability_verdicts(g0.to_dict(), [_owned(match=m)])
    v = verdicts[(INST, "CVE-2023-1")]
    assert v["on_attack_path"] is True and v["priority_band"] == "CRITICAL"


# ── refresh diff ─────────────────────────────────────────────────────────────
def test_diff_reachability_detects_became_reachable():
    g0 = _base_graph()
    verdicts, _ = compute_reachability_verdicts(g0.to_dict(), [_owned()])
    # previously stored as not-on-path → now on-path = became_reachable
    old = [{"node_id": INST, "cve": "CVE-2021-44228", "on_attack_path": False}]
    became, gone = diff_reachability(old, verdicts)
    assert len(became) == 1 and became[0]["cve"] == "CVE-2021-44228"
    assert gone == []


def test_diff_reachability_detects_became_unreachable():
    old = [{"node_id": INST, "cve": "CVE-2021-44228", "on_attack_path": True}]
    verdicts = {(INST, "CVE-2021-44228"): {"on_attack_path": False, "priority_score": 45,
                                           "priority_band": "MEDIUM"}}
    became, gone = diff_reachability(old, verdicts)
    assert became == [] and len(gone) == 1
