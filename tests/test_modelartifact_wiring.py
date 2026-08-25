"""Phase 4 · slice 4.6 — the scanner surface for model artifacts.

The config half is always on and the artifact read is not. That split is the whole shape
of the slice, and most of what is defended here.

**The crossing stays out of the always-on ask.** `MART-04` needs `s3:GetObject`, and the
permission ledger's own guard rejected the first attempt to put it in the additive policy
— that policy is what an operator approves once and forgets, and a content read has no
business in it. It lives in `deploy/cnapp-scanner-role.yaml` as its own named policy
instead, following the precedent FLOW-00 set.

**Off unless asked.** Without `--scan-model-artifacts` nothing fetches an object, and a
test crosses the CLI seam rather than only setting the attribute — the gap that left
`--pentest-results` dead code through all of slice 3.5.

**An unreadable answer is never a clean one.** A bucket policy that could not be read, an
object that could not be fetched, a stream that would not parse: each is reported as what
it is.
"""
from __future__ import annotations

import io
import os
import pickle
import sys
import zipfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_live_scanner as A
import aws_modelartifact as MA
import aws_perm_ledger as L

ACCT = "123456789012"


class _Evil:
    def __reduce__(self):
        return (open, ("SHOULD_NEVER_EXIST.txt", "w"))


def _scanner(*, scan=False, s3=None):
    with patch("aws_live_scanner.HAS_BOTO3", True):
        s = A.AWSLiveScanner(region="us-east-1", verbose=False, sections=["SAGEMAKER"])
        s.account = ACCT
    s._client = lambda svc, region=None: (s3 or MagicMock())
    s._scan_model_artifacts = scan
    return s


def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _container(uri="s3://artifacts/model.tar.gz", etag=None, legacy=False):
    if legacy:
        return {"Image": "img", "ModelDataUrl": uri}
    src = {"S3Uri": uri}
    if etag:
        src["ETag"] = etag
    return {"Image": "img", "ModelDataSource": {"S3DataSource": src}}


# ── who can replace the artifact ────────────────────────────────────────────
def test_an_externally_writable_artifact_bucket_is_critical():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value="public"):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container(etag="e")})
    f = _ids(s, "MART-01", "FAIL")
    assert len(f) == 1 and f[0].severity == "CRITICAL"
    assert "remote code execution" in f[0].message


def test_an_internal_bucket_raises_no_write_finding():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container(etag="e")})
    assert not _ids(s, "MART-01", "FAIL")


def test_an_unreadable_bucket_policy_is_a_note_not_a_pass():
    """None means unreadable. Treating it as 'not writable' would manufacture safety
    out of a permissions error — the same trap _bucket_write_scope documents."""
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container(etag="e")})
    assert any("could not be established rather than being nobody" in r.message
               for r in _ids(s, "MART-00"))


# ── pinning ─────────────────────────────────────────────────────────────────
def test_an_unpinned_artifact_is_reported():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container()})
    f = _ids(s, "MART-02", "FAIL")
    assert f and "whatever sits at that URI at deploy time" in f[0].message


def test_a_pinned_artifact_raises_nothing():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container(etag="abc")})
    assert not _ids(s, "MART-02")


def test_the_legacy_url_is_always_unpinned():
    """ModelDataUrl has no ETag field, so it cannot be pinned at all."""
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", {"PrimaryContainer": _container(legacy=True)})
    assert _ids(s, "MART-02", "FAIL")


def test_every_container_in_a_pipeline_is_assessed():
    """A multi-container model loads several artifacts and each one executes."""
    s = _scanner()
    detail = {"PrimaryContainer": _container("s3://a/one.tar.gz"),
              "Containers": [_container("s3://a/two.tar.gz")]}
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts("m1", detail)
    assert len(_ids(s, "MART-02", "FAIL")) == 2


# ── format ──────────────────────────────────────────────────────────────────
def test_safetensors_passes_the_format_check():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/w.safetensors", etag="e")})
    assert _ids(s, "MART-05", "PASS")
    assert not _ids(s, "MART-05", "FAIL")


def test_a_pickle_suffix_fails_the_format_check():
    s = _scanner()
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/model.pt", etag="e")})
    f = _ids(s, "MART-05", "FAIL")
    assert f and "safetensors is the direct replacement" in f[0].message


# ── the opt-in crossing ─────────────────────────────────────────────────────
def _s3_with(body: bytes):
    c = MagicMock()
    c.get_object.return_value = {"Body": io.BytesIO(body)}
    return c


def test_nothing_is_fetched_without_the_flag():
    """The crossing is off unless asked. This is the property the whole opt-in shape
    exists to guarantee."""
    s3 = _s3_with(pickle.dumps(_Evil()))
    s = _scanner(scan=False, s3=s3)
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/model.pkl", etag="e")})
    s3.get_object.assert_not_called()
    assert not _ids(s, "MART-04")


def test_a_malicious_artifact_is_found_with_the_flag(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        s = _scanner(scan=True, s3=_s3_with(pickle.dumps(_Evil())))
        with patch.object(s, "_bucket_write_scope", return_value=None):
            s._emit_model_artifacts(
                "m1", {"PrimaryContainer": _container("s3://a/model.pkl", etag="e")})
        f = _ids(s, "MART-04", "FAIL")
        assert f and "_io.open" in f[0].message
        assert "Do NOT load it to investigate" in f[0].message
        # And the scanner did not execute it while finding it.
        assert not os.path.exists("SHOULD_NEVER_EXIST.txt")
    finally:
        os.chdir(cwd)


def test_an_ordinary_model_raises_no_malicious_finding():
    """Almost every real checkpoint contains REDUCE. Flagging them all is how a scanner
    gets switched off."""
    import collections
    s = _scanner(scan=True,
                 s3=_s3_with(pickle.dumps(collections.OrderedDict([("w", [1.0])]))))
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/model.pkl", etag="e")})
    assert not _ids(s, "MART-04", "FAIL")


def test_a_denied_object_read_is_reported_as_not_scanned():
    """An artifact that could not be fetched is not a clean one."""
    s3 = MagicMock()
    s3.get_object.side_effect = Exception("AccessDeniedException")
    s = _scanner(scan=True, s3=s3)
    with patch.object(s, "_bucket_write_scope", return_value=None), \
            patch.object(s, "_is_access_denied", return_value=True):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/model.pkl", etag="e")})
    assert "MART-04" in s._coverage.not_evaluated
    assert any("not a clean one" in r.message for r in _ids(s, "MART-00"))


def test_a_prefix_reference_is_not_scanned_and_says_so():
    """S3Prefix names many objects; listing them would be a second permission this
    slice did not ask for."""
    s3 = MagicMock()
    s = _scanner(scan=True, s3=s3)
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/models/", etag="e")})
    s3.get_object.assert_not_called()
    assert any("names a prefix rather than an object" in r.message
               for r in _ids(s, "MART-00"))


def test_the_read_is_ranged_and_bounded():
    """An opt-in data crossing that reads whole multi-gigabyte checkpoints becomes an
    egress bill."""
    s3 = _s3_with(pickle.dumps({"a": 1}))
    s = _scanner(scan=True, s3=s3)
    with patch.object(s, "_bucket_write_scope", return_value=None):
        s._emit_model_artifacts(
            "m1", {"PrimaryContainer": _container("s3://a/model.pkl", etag="e")})
    kwargs = s3.get_object.call_args.kwargs
    assert kwargs["Range"].startswith("bytes=0-")
    assert int(kwargs["Range"].split("-")[1]) < MA.MAX_SCAN_BYTES


# ── the CLI seam ────────────────────────────────────────────────────────────
def _args(**over):
    ns = dict(scan_model_artifacts=False, ai_owners="", pentest_results=None,
              tool_patterns=None, side_scan=False, side_scan_targets=None,
              side_scan_tag=None, side_scan_max=10, side_scan_secrets=False,
              side_scan_images=False, side_scan_images_max=1, ecr_scan_max_images=20,
              vuln_db=None, vuln_db_pubkey=None, flow_logs=False)
    ns.update(over)
    return SimpleNamespace(**ns)


def test_the_flag_reaches_the_scanner():
    """Crossing the seam, not just setting the attribute — the gap that left
    --pentest-results dead code through all of slice 3.5."""
    s = _scanner()
    A._apply_phase6_config(s, _args(scan_model_artifacts=True))
    assert s._scan_model_artifacts is True


def test_the_default_is_off():
    s = _scanner(scan=True)
    A._apply_phase6_config(s, _args())
    assert s._scan_model_artifacts is False


# ── the charter ─────────────────────────────────────────────────────────────
def test_the_always_on_policy_never_asks_for_object_reads():
    """The ledger guard rejected the first attempt to put MART-04 in the additive
    policy, and it was right: that policy is what an operator approves once and
    forgets."""
    actions = {r.action for reqs in L.REQUIREMENTS.values() for r in reqs}
    assert "s3:GetObject" not in actions


def test_the_config_half_is_in_the_ledger():
    for cid in ("MART-01", "MART-02", "MART-03", "MART-05"):
        assert cid in L.REQUIREMENTS, cid


def test_the_opt_in_policy_is_documented_in_the_deploy_template():
    """A crossing that ships without the policy an operator must attach is a feature
    nobody can turn on."""
    import pathlib
    text = pathlib.Path("deploy/cnapp-scanner-role.yaml").read_text(encoding="utf-8")
    assert "CnappModelArtifactRead" in text
    assert "--scan-model-artifacts" in text
    assert "s3:GetObject" in text
