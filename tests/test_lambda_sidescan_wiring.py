"""LMB-07 — the producer that was missing, and the claim it makes honest.

WHAT THIS IS DEFENDING. `aws_sidescan_lambda` shipped complete: pure extractor,
live fetch seam, its own tests, `LMB-07` named in `emit_node_vuln_edges`' docstring,
and `LambdaFunction` already in `aws_correlate._EXPLOIT_KINDS` so the correlation
engine was waiting for the edges. `docs/OVERWATCH_VULN_ROADMAP.md` ticked LMB-07
complete. Nothing called any of it — the check was registered in none of the four
metadata maps and no code path emitted it, so the ✅ was false and a Lambda
dependency CVE could not be reported by this product at all.

Three of the four side-scan siblings were wired (`aws_sidescan` 9 importers,
`_ebs` 3, `_image` 2); this one had 0. That asymmetry is the whole bug.

THE FOUR WAYS THE WIRING CAN BE WRONG, one test each:

  * IT COSTS SOMETHING UNASKED. The scan downloads deployment packages, so a
    default run must not touch `get_function` at all.
  * IT LANDS SOMEWHERE THE GRAPH CANNOT USE. The finding is the smaller half; the
    `HAS_VULN` edge on a `LambdaFunction` node is what makes a vulnerable
    dependency rank in an attack path. Keyed on the ARN, because the same function
    name exists in every region.
  * IT REPORTS THE SAME IMAGE TWICE. A container-packaged Lambda is the ECR path's
    job; scanning it here would file one artefact under two check ids.
  * IT READS AS CLEAN WHEN IT READ NOTHING. An unreachable artefact, a capped run
    and a missing feed each have to say so — silence is the one output that means
    "no vulnerable dependencies", and it must be earned.
"""
import io
import os
import sys
import zipfile
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_sidescan
from test_live_scanner import make_scanner, MockClientError, MockPaginator


@pytest.fixture(autouse=True)
def _client_error():
    """`ClientError` is imported inside `try: import boto3`, so it does not
    exist in a boto3-less test run and every `except ClientError` in the
    scanner raises NameError instead. The suite's convention is to patch it
    with a stand-in; applied here for the whole module rather than per test."""
    with patch("engine.aws_live_scanner.ClientError", MockClientError,
               create=True):
        yield

_ARN = "arn:aws:lambda:us-east-1:111122223333:function:api"

# lodash 4.17.20 < fixed 4.17.21 -> vulnerable. Same fixture the registry path uses,
# so a CVE that ranks HIGH there ranks HIGH here.
_LODASH_OSV = {"id": "CVE-2024-2", "aliases": ["CVE-2024-2"],
               "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                             "ranges": [{"type": "SEMVER",
                                         "events": [{"introduced": "4.0.0"},
                                                    {"fixed": "4.17.21"}]}]}],
               "severity": [{"type": "CVSS_V3", "score": "7.5"}]}


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, data in files.items():
            zf.writestr(path, data)
    return buf.getvalue()


_VULN_ZIP = _zip({"node_modules/lodash/package.json":
                  b'{"name":"lodash","version":"4.17.20"}'})


def _lambda_client(funcs=None, package_type="Zip", get_function_error=None):
    funcs = funcs if funcs is not None else [
        {"FunctionName": "api", "FunctionArn": _ARN, "Runtime": "nodejs20.x"}]
    lmb = MagicMock()
    lmb.get_paginator.return_value = MockPaginator("Functions", funcs)
    # The LMB-01..06 checks run first; make their reads uninteresting rather than
    # letting MagicMock return values that would be parsed as real config.
    lmb.get_policy.side_effect = MockClientError("ResourceNotFoundException")
    lmb.get_function_code_signing_config.side_effect = MockClientError("denied")
    if get_function_error is not None:
        lmb.get_function.side_effect = get_function_error
    else:
        lmb.get_function.return_value = {
            "Configuration": {"PackageType": package_type, "Layers": []},
            "Code": {"Location": "https://code"}}
    return lmb


def _scanner(lmb, *, on=False, max_fns=20, feed_recs=(_LODASH_OSV,),
             kev=frozenset(), artifact=_VULN_ZIP):
    s = make_scanner(["LAMBDA"])
    s._clients["lambda:us-east-1"] = lmb
    if on:
        s.side_scan_lambda = True
        s.side_scan_lambda_max = max_fns
        s._layer_get = lambda u: artifact
        feed = aws_sidescan.OSVFeed.from_records(list(feed_recs))
        s._vuln_db_bundle = (feed, {}, set(kev), set())
        s._vuln_db_loaded = True
    return s


def _of(s, cid="LMB-07"):
    return [r for r in s.results if r.check_id == cid]


def _has_vuln(s):
    return [e for e in s.graph.to_dict()["edges"] if e["kind"] == "HAS_VULN"]


# ── it costs nothing unasked ────────────────────────────────────────────────
def test_the_artifact_scan_is_off_by_default():
    """A default scan must not download a deployment package. Asserted on the API
    call, not just the absence of findings — a guard that skipped emission but still
    fetched would pass the weaker check while still spending the egress."""
    lmb = _lambda_client()
    s = _scanner(lmb, on=False)
    s._check_lambda()
    assert not [r for r in _of(s) if r.status == "FAIL"]
    lmb.get_function.assert_not_called()


def test_the_flag_turns_it_on():
    """The negative control for the test above: with the flag, the same fixture
    produces the finding, so 'off by default' is a decision and not a broken path."""
    s = _scanner(_lambda_client(), on=True)
    s._check_lambda()
    assert any(r.status == "FAIL" and "CVE-2024-2" in r.message for r in _of(s))


# ── the half that reaches an attack path ────────────────────────────────────
def test_it_lands_a_has_vuln_edge_on_a_lambdafunction_node():
    """The finding is the smaller half. `aws_correlate._EXPLOIT_KINDS` contains
    LambdaFunction, so it is this edge — not the FAIL row — that lets a vulnerable
    dependency rank in an attack path. A different node kind would be invisible to
    correlation while still rendering a finding, which is the quiet failure."""
    s = _scanner(_lambda_client(), on=True)
    s._check_lambda()
    edges = _has_vuln(s)
    assert edges, "no HAS_VULN edge — the CVE cannot reach correlation"
    assert {e["source"] for e in edges} == {_ARN}
    nodes = {n["id"]: n for n in s.graph.to_dict()["nodes"]}
    assert nodes[_ARN]["kind"] == "LambdaFunction"
    assert {e.get("scan_source") for e in edges} == {"lambda-sidescan"}


def test_the_node_is_keyed_on_the_arn_not_the_function_name():
    """The same function name exists in every region and every account. Keying the
    node on the name would merge two unrelated functions into one graph node and
    attribute one's CVEs to the other."""
    s = _scanner(_lambda_client(), on=True)
    s._check_lambda()
    assert all(e["source"].startswith("arn:aws:lambda:") for e in _has_vuln(s))


# ── it must not report one artefact twice ───────────────────────────────────
def test_an_image_packaged_lambda_is_left_to_the_ecr_path():
    """PackageType=Image means the artefact is a container image, which CWPP-05/06
    already own. Reporting it here too would file one image under two check ids and
    double-count it in every total that groups by finding.

    NO LMB-07 ROW AT ALL, not merely no FAIL. Asserting the weaker thing let a
    mutation that deletes this guard survive: without it the flow falls through to
    the `no artifact bytes` branch, which emits a *skipped* INFO on every
    container-packaged function in the account — noise that reads as a coverage gap
    when the truth is that this check does not apply."""
    lmb = _lambda_client(package_type="Image")
    s = _scanner(lmb, on=True)
    s._check_lambda()
    assert _of(s) == [], (
        "an image-packaged Lambda produced an LMB-07 row: %s"
        % [(r.status, r.message) for r in _of(s)])


# ── it must never read as clean when it read nothing ────────────────────────
def test_an_unreachable_artifact_is_an_info_not_silence():
    """Silence is the output that means 'no vulnerable dependencies'. A function
    whose package could not be fetched has to say so, or a denied read renders
    identically to a clean function."""
    lmb = _lambda_client(get_function_error=RuntimeError("AccessDeniedException"))
    s = _scanner(lmb, on=True)
    s._check_lambda()
    infos = [r for r in _of(s) if r.status == "INFO"]
    assert any("skipped" in r.message and "api" in r.message for r in infos), \
        "a denied artifact read produced no INFO — it reads as a clean function"


def test_a_capped_run_says_how_much_it_covered():
    """A cap that is not announced turns a partial scan into an apparent whole one."""
    funcs = [{"FunctionName": "f%d" % i,
              "FunctionArn": "arn:aws:lambda:us-east-1:111122223333:function:f%d" % i}
             for i in range(5)]
    s = _scanner(_lambda_client(funcs=funcs), on=True, max_fns=2)
    s._check_lambda()
    assert any(r.status == "INFO" and "first 2 of 5" in r.message for r in _of(s))
    # and it really did stop at two
    assert len({e["source"] for e in _has_vuln(s)}) == 2


def test_an_uncapped_run_does_not_claim_a_cap():
    """The negative control: the sentence above must not appear on a full run."""
    s = _scanner(_lambda_client(), on=True, max_fns=20)
    s._check_lambda()
    assert not any("of 1 function" in r.message for r in _of(s))


def test_no_vuln_db_is_an_inventory_and_says_so():
    """Without a feed nothing is matched, so 'no findings' would otherwise read as
    'no vulnerable dependencies' — the same sentence the registry path emits."""
    lmb = _lambda_client()
    s = make_scanner(["LAMBDA"])
    s._clients["lambda:us-east-1"] = lmb
    s.side_scan_lambda = True
    s._layer_get = lambda u: _VULN_ZIP
    s._check_lambda()
    assert any(r.status == "INFO" and "CVE match skipped" in r.message for r in _of(s))


# ── severity is the registry path's, deliberately ───────────────────────────
def test_only_high_and_above_are_reported():
    """The registry path's bar, so the same CVE is reported at the same level
    whichever artefact carries it. A LOW dependency CVE on every Lambda in an estate
    would bury the findings that matter."""
    low = dict(_LODASH_OSV, severity=[{"type": "CVSS_V3", "score": "2.0"}])
    s = _scanner(_lambda_client(), on=True, feed_recs=(low,))
    s._check_lambda()
    assert not [r for r in _of(s) if r.status == "FAIL"]


def test_a_kev_dependency_is_reported_and_carried_on_the_edge():
    """LMB-07 is HIGH for every match, unlike the registry path which routes KEV to
    a second CRITICAL id — CWPP-06's remediation is Dockerfile-specific and would be
    wrong advice for a zip. The KEV fact is not lost: it is in the message and on
    the edge, and correlation escalates the PATH, which is where this product acts
    on exploitability."""
    s = _scanner(_lambda_client(), on=True, kev={"CVE-2024-2"})
    s._check_lambda()
    fails = [r for r in _of(s) if r.status == "FAIL"]
    assert fails and all(r.severity == "HIGH" for r in fails)
    assert any("kev=YES" in r.message for r in fails)
    assert any(e.get("kev") for e in _has_vuln(s)), "KEV not carried onto the edge"


# ── the plumbing every other test in this file bypasses ─────────────────────
def _args(**over):
    """A parsed-args stand-in. `_apply_phase6_config` reads eight arguments by
    direct attribute access, so a Namespace carrying only the two under test
    raises AttributeError before reaching them."""
    import argparse

    base = dict(graph_neptune_csv=None, graph_neptune_cypher=None,
                side_scan=False, side_scan_max=20, side_scan_secrets=True,
                side_scan_tag=None, side_scan_targets="exposed", vuln_db=None,
                side_scan_lambda=False, side_scan_lambda_max=20)
    base.update(over)
    return argparse.Namespace(**base)


def test_the_cli_flag_actually_reaches_the_scanner():
    """Every other test here sets `side_scan_lambda` on the scanner directly, so
    none of them would notice if the argparse->scanner assignment were deleted —
    the flag would still parse, --help would still render it, and the scan would
    silently never run. That is the same built-but-not-connected shape LMB-07
    already had once, so it is asserted rather than assumed."""
    from engine import aws_live_scanner as A

    sc = make_scanner(["LAMBDA"])
    assert sc.side_scan_lambda is False, "the default must be off"
    A._apply_phase6_config(sc, _args(side_scan_lambda=True,
                                     side_scan_lambda_max=7))
    assert sc.side_scan_lambda is True
    assert sc.side_scan_lambda_max == 7


def test_the_function_cap_is_clamped_to_a_sane_range():
    """A zero or negative cap would scan nothing while the flag reports itself on,
    and an unbounded one turns an opt-in into an unbounded download of every
    deployment package in the account."""
    from engine import aws_live_scanner as A

    for given, expected in ((0, 1), (-5, 1), (7, 7), (10 ** 6, 500)):
        sc = make_scanner(["LAMBDA"])
        A._apply_phase6_config(sc, _args(side_scan_lambda=True,
                                         side_scan_lambda_max=given))
        assert sc.side_scan_lambda_max == expected, (
            "cap %r became %r, expected %r"
            % (given, sc.side_scan_lambda_max, expected))


# ── the registration the lockstep ratchet requires ──────────────────────────
def test_lmb07_is_registered_in_every_metadata_map():
    """The check existed in a roadmap tick and a docstring and in none of the maps.
    tests/test_check_maps_lockstep.py enforces this for every check; naming it here
    too records that THIS check is why the entries exist."""
    from engine import aws_finding_detail
    from engine.aws_live_scanner import (CHECK_SEVERITY, COMPLIANCE_MAP,
                                         REMEDIATION_MAP)
    assert CHECK_SEVERITY["LMB-07"] == "HIGH"
    assert COMPLIANCE_MAP["LMB-07"]
    assert REMEDIATION_MAP["LMB-07"]
    detail = aws_finding_detail.FINDING_DETAIL["LMB-07"]
    assert detail["risk"] and detail["impact"] and len(detail["steps"]) >= 4
