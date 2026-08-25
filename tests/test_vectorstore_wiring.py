"""Phase 4 · slice 4.2 — the scanner surface for RAG vector stores.

Three things are load-bearing here.

**The two gates stay apart.** `VEC-01` reports that the corpus endpoint is *reachable*;
`VEC-02` reports that it is *readable*; only `VEC-03` claims both, and only when each was
separately established. The OpenSearch Serverless reference is explicit that network
access and data access are different controls, so a scanner that collapses them asserts
a terminal it never proved — the failure `ATT&CK-02` was built to avoid.

**A collection nobody's policy matches is not a private one.** No matching network policy
means reachability could not be established, which is an INFO, not a PASS.

**Only VECTORSEARCH collections are in scope.** A SEARCH or TIMESERIES collection is not
an agent's corpus, and putting AI findings on every log-analytics collection in the
account is how a category gets ignored.
"""
from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_perm_ledger as L
import aws_vectorstore as V
from aws_live_scanner import AWSLiveScanner

ACCT = "123456789012"


def _scanner(client):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = AWSLiveScanner(region="us-east-1", verbose=False, sections=["VECTORSTORE"])
        s.account = ACCT
    s._client = lambda svc, region=None: client
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _aoss(collections=None, net=None, data=None):
    c = MagicMock()
    cols = collections if collections is not None else [
        {"id": "c1", "name": "rag-corpus", "type": "VECTORSEARCH",
         "kmsKeyArn": "arn:aws:kms:us-east-1:123456789012:key/k"}]
    c.list_collections.return_value = {
        "collectionSummaries": [{"id": d["id"], "name": d.get("name")} for d in cols]}
    c.batch_get_collection.return_value = {"collectionDetails": cols}

    def _list(type, **kw):
        pols = net if type == "network" else data
        key = ("securityPolicySummaries" if type != "data"
               else "accessPolicySummaries")
        return {key: [{"name": p["name"]} for p in (pols or [])]}

    def _get_sec(name, type):
        return {"securityPolicyDetail": [p for p in (net or []) if p["name"] == name]}

    def _get_acc(name, type):
        return {"accessPolicyDetail": [p for p in (data or []) if p["name"] == name]}

    c.list_security_policies.side_effect = _list
    c.list_access_policies.side_effect = _list
    c.get_security_policy.side_effect = _get_sec
    c.get_access_policy.side_effect = _get_acc
    return c


def netpol(name="np", public=False, rts=("collection",), targets=("collection/*",)):
    return {"name": name, "type": "network", "policy": json.dumps([{
        "Rules": [{"ResourceType": rt, "Resource": list(targets)} for rt in rts],
        "AllowFromPublic": public}])}


def datapol(name="dp", principals=("arn:aws:iam::123456789012:role/App",)):
    return {"name": name, "type": "data", "policy": json.dumps([{
        "Rules": [{"ResourceType": "collection", "Resource": ["collection/*"]}],
        "Principal": list(principals)}])}


def _run_aoss(client):
    s = _scanner(client)
    s._check_aoss_collections()
    return s


# ── scope ───────────────────────────────────────────────────────────────────
def test_only_vectorsearch_collections_are_assessed():
    """A SEARCH collection is not an agent's corpus. Widening the net puts AI findings
    on every log-analytics collection in the account, which is how operators learn to
    skip the category."""
    s = _run_aoss(_aoss(collections=[
        {"id": "c1", "name": "logs", "type": "SEARCH"},
        {"id": "c2", "name": "metrics", "type": "TIMESERIES"}]))
    assert not _ids(s, "VEC-01") and not _ids(s, "VEC-04")
    info = _ids(s, "VEC-00", "INFO")
    assert info and "were not assessed" in info[0].message


# ── the reach gate ──────────────────────────────────────────────────────────
def test_a_public_collection_raises_vec01():
    s = _run_aoss(_aoss(net=[netpol(public=True)]))
    f = _ids(s, "VEC-01", "FAIL")
    assert len(f) == 1 and "reachable from the public internet" in f[0].message


def test_a_private_collection_passes():
    s = _run_aoss(_aoss(net=[netpol(public=False)]))
    assert _ids(s, "VEC-01", "PASS")


def test_an_ungoverned_collection_is_info_not_pass():
    """No matching policy is not a private one, and a PASS here would be a clean bill
    of health issued because nothing was found."""
    s = _run_aoss(_aoss(net=[netpol(targets=("collection/other",))]))
    assert not _ids(s, "VEC-01", "PASS") and not _ids(s, "VEC-01", "FAIL")
    info = _ids(s, "VEC-00", "INFO")
    assert any("could not be established rather than being private" in r.message
               for r in info)


def test_the_finding_does_not_claim_the_corpus_is_readable():
    """Network access decides reach; the data access policy decides read. Saying
    otherwise asserts a terminal this check never established."""
    s = _run_aoss(_aoss(net=[netpol(public=True)]))
    assert "not who can read it" in _ids(s, "VEC-01", "FAIL")[0].message


# ── the read gate ───────────────────────────────────────────────────────────
def test_a_wildcard_data_policy_raises_vec02():
    s = _run_aoss(_aoss(net=[netpol(public=False)], data=[datapol(principals=("*",))]))
    f = _ids(s, "VEC-02", "FAIL")
    assert len(f) == 1 and "wildcard principal" in f[0].message


def test_a_scoped_data_policy_passes():
    s = _run_aoss(_aoss(net=[netpol(public=False)], data=[datapol()]))
    assert _ids(s, "VEC-02", "PASS")


# ── the composition ─────────────────────────────────────────────────────────
def test_vec03_fires_only_when_both_gates_are_open():
    s = _run_aoss(_aoss(net=[netpol(public=True)], data=[datapol(principals=("*",))]))
    f = _ids(s, "VEC-03", "FAIL")
    assert len(f) == 1
    assert "both gates are open" in f[0].message.lower()
    assert f[0].severity == "CRITICAL"


def test_vec03_stays_silent_when_only_the_network_is_open():
    s = _run_aoss(_aoss(net=[netpol(public=True)], data=[datapol()]))
    assert _ids(s, "VEC-01", "FAIL") and not _ids(s, "VEC-03")


def test_vec03_stays_silent_when_only_the_data_policy_is_broad():
    """An unreachable endpoint is not exploitable, however broad the policy."""
    s = _run_aoss(_aoss(net=[netpol(public=False)], data=[datapol(principals=("*",))]))
    assert _ids(s, "VEC-02", "FAIL") and not _ids(s, "VEC-03")


# ── key custody ─────────────────────────────────────────────────────────────
def test_an_aws_owned_key_raises_vec04():
    s = _run_aoss(_aoss(collections=[
        {"id": "c1", "name": "rag-corpus", "type": "VECTORSEARCH"}]))
    f = _ids(s, "VEC-04", "FAIL")
    assert f and "no key you can disable" in f[0].message


def test_a_customer_key_passes_vec04():
    s = _run_aoss(_aoss())
    assert _ids(s, "VEC-04", "PASS")


# ── s3vectors ───────────────────────────────────────────────────────────────
def _s3v(bucket=None, policy=None, policy_error=None):
    c = MagicMock()
    c.list_vector_buckets.return_value = {
        "vectorBuckets": [{"vectorBucketName": "corpus"}]}
    c.get_vector_bucket.return_value = {"vectorBucket": bucket or {
        "vectorBucketName": "corpus",
        "encryptionConfiguration": {"sseType": "AES256"}}}
    if policy_error:
        c.get_vector_bucket_policy.side_effect = policy_error
    else:
        c.get_vector_bucket_policy.return_value = {"policy": policy}
    return c


def _run_s3v(client):
    s = _scanner(client)
    s._check_s3vectors()
    return s


def test_sse_s3_raises_vec07():
    s = _run_s3v(_s3v())
    f = _ids(s, "VEC-07", "FAIL")
    assert f and "AES256" in f[0].message


def test_a_customer_key_passes_vec07():
    s = _run_s3v(_s3v(bucket={"vectorBucketName": "corpus",
                              "encryptionConfiguration": {
                                  "sseType": "aws:kms",
                                  "kmsKeyArn": "arn:aws:kms:us-east-1:1:key/k"}}))
    assert _ids(s, "VEC-07", "PASS")


def test_a_public_bucket_policy_raises_vec05():
    pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "s3vectors:GetVectors"}]})
    s = _run_s3v(_s3v(policy=pol))
    assert _ids(s, "VEC-05", "FAIL")


def test_a_cross_account_grant_raises_vec06_not_vec05():
    """A named external account is frequently a partner integration. Collapsing it into
    'public' would put a HIGH on a working design."""
    pol = json.dumps({"Statement": [{
        "Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "s3vectors:GetVectors"}]})
    s = _run_s3v(_s3v(policy=pol))
    assert _ids(s, "VEC-06", "FAIL") and not _ids(s, "VEC-05")


def test_no_bucket_policy_raises_nothing():
    s = _run_s3v(_s3v(policy=None))
    assert not _ids(s, "VEC-05") and not _ids(s, "VEC-06")


# ── refused reads never become clean answers ────────────────────────────────
def test_a_denied_collection_read_is_a_coverage_note():
    c = _aoss()
    c.batch_get_collection.side_effect = Exception("AccessDeniedException")
    s = _scanner(c)
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_aoss_collections()
    assert "VEC-01" in s._coverage.not_evaluated
    assert not _ids(s, "VEC-01", "PASS")
    assert any("no phantom pass" in r.message for r in _ids(s, "VEC-00"))


def test_a_denied_bucket_policy_read_is_a_coverage_note():
    s = _scanner(_s3v(policy_error=Exception("AccessDeniedException")))
    with patch.object(s, "_is_access_denied", return_value=True):
        s._check_s3vectors()
    for cid in ("VEC-05", "VEC-06"):
        assert cid in s._coverage.not_evaluated
    assert not _ids(s, "VEC-05", "PASS")


def test_an_sdk_without_the_service_costs_the_checks_not_the_scan():
    s = _scanner(MagicMock(spec=[]))
    s._check_aoss_collections()          # must not raise
    s._check_s3vectors()
    assert not _ids(s, "VEC-01")


# ── the declined data plane ─────────────────────────────────────────────────
def test_every_finding_says_contents_were_not_read():
    """A vector-store finding silent on contents reads as 'contents checked, contents
    clean' — a phantom pass produced by omission."""
    s = _run_aoss(_aoss(net=[netpol(public=True)], data=[datapol(principals=("*",))]))
    for cid in ("VEC-01", "VEC-02", "VEC-03"):
        f = _ids(s, cid, "FAIL")
        assert f, cid
        assert "does NOT read the stored vectors" in f[0].message, cid


def test_the_ledger_never_asks_for_the_data_plane():
    """D8. Asking for GetVectors would be asking for the customer's corpus."""
    actions = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    for banned in ("s3vectors:GetVectors", "s3vectors:ListVectors",
                   "s3vectors:QueryVectors"):
        assert banned not in actions, banned


def test_every_vector_check_is_in_the_ledger():
    import aws_live_scanner as A
    vec = {c for c in A.CHECK_SEVERITY if c.startswith("VEC-")}
    assert vec <= set(L.REQUIREMENTS), vec - set(L.REQUIREMENTS)
