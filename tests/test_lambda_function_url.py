"""LMB-08 / LMB-09 — Lambda function URLs.

A function URL is a SECOND front door onto a function, separate from the resource
policy LMB-01 reads: a dedicated public HTTPS endpoint that can be anonymous
(AuthType NONE) while the policy looks unremarkable, and that sits in front of none
of the API Gateway machinery teams assume protects their HTTP surface. LMB-08 is
that endpoint being unauthenticated; LMB-09 is its CORS allowing any origin to read
the responses.

Offline: MagicMock lambda client, no AWS credentials.

REGRESSION THIS FILE PINS. The first cut of the scan caught the "function has no
URL" case with `except ClientError`, and `ClientError` is only bound when boto3
imported — so on the COMMON path (most functions have no URL and answer
ResourceNotFoundException) it raised NameError and took the whole LAMBDA section
down with it. Nothing caught that, because no test had ever driven this code.
"""
import json
import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_live_scanner import make_scanner, MockClientError, MockPaginator


def _status(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def _msgs(s, cid):
    return " ".join(r.message for r in s.results if r.check_id == cid)


def _scanner(url_by_fn, extra_funcs=(), error_by_fn=None):
    """url_by_fn maps FunctionName -> the GetFunctionUrlConfig response.

    A function in `extra_funcs` has no URL and answers ResourceNotFoundException,
    which is what the real API does and is the overwhelmingly common case.
    """
    names = list(url_by_fn) + list(extra_funcs)
    s = make_scanner(sections=["LAMBDA"])
    lmb = MagicMock()
    lmb.get_paginator.side_effect = lambda n: MockPaginator(
        "Functions", [{"FunctionName": n} for n in names])
    lmb.get_policy.return_value = {"Policy": json.dumps({"Statement": []})}
    lmb.get_function_concurrency.return_value = {"ReservedConcurrentExecutions": 5}
    lmb.get_function_code_signing_config.return_value = {"CodeSigningConfigArn": None}

    def _url(FunctionName):
        if error_by_fn and FunctionName in error_by_fn:
            raise error_by_fn[FunctionName]
        if FunctionName not in url_by_fn:
            raise MockClientError("ResourceNotFoundException", "no url config")
        return url_by_fn[FunctionName]

    lmb.get_function_url_config.side_effect = _url
    s._clients["lambda:us-east-1"] = lmb
    return s


# ── LMB-08: is the endpoint anonymous? ────────────────────────────────────────
def test_lmb08_authtype_none_fails():
    s = _scanner({"public-fn": {"AuthType": "NONE"}})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-08")
    assert "public-fn" in _msgs(s, "LMB-08")


def test_lmb08_iam_auth_passes():
    s = _scanner({"signed-fn": {"AuthType": "AWS_IAM"}})
    s._check_lambda()
    assert "PASS" in _status(s, "LMB-08")
    assert "FAIL" not in _status(s, "LMB-08")


def test_lmb08_only_the_url_bearing_function_is_reported():
    """A function with no URL is not a finding either way — a per-function PASS for
    the (many) functions without one would bury the (few) that have one."""
    s = _scanner({"public-fn": {"AuthType": "NONE"}},
                 extra_funcs=["plain-1", "plain-2", "plain-3"])
    s._check_lambda()
    resources = {r.resource for r in s.results if r.check_id == "LMB-08"}
    assert resources == {"public-fn"}


def test_lmb08_no_urls_anywhere_is_a_single_info_not_silence():
    s = _scanner({}, extra_funcs=["plain-1", "plain-2"])
    s._check_lambda()
    lmb08 = [r for r in s.results if r.check_id == "LMB-08"]
    assert len(lmb08) == 1 and lmb08[0].status == "INFO"


def test_lmb08_missing_url_config_does_not_crash_the_section():
    """THE REGRESSION. ResourceNotFoundException is the normal answer for most
    functions; catching it via an unbound `ClientError` raised NameError and killed
    every later check in the section."""
    s = _scanner({}, extra_funcs=["plain-1"])
    s._check_lambda()                       # must not raise
    assert any(r.check_id == "LMB-06" for r in s.results)   # section ran to the end


def test_lmb08_denied_read_warns_rather_than_reading_clean():
    """A denied read is not the same as a safe config."""
    s = _scanner({}, extra_funcs=["opaque-fn"],
                 error_by_fn={"opaque-fn": MockClientError("AccessDeniedException")})
    s._check_lambda()
    assert "WARN" in _status(s, "LMB-08")
    assert "PASS" not in _status(s, "LMB-08")


def test_lmb08_unexpected_error_shape_is_undetermined_not_clean():
    s = _scanner({}, extra_funcs=["odd-fn"],
                 error_by_fn={"odd-fn": RuntimeError("connection reset")})
    s._check_lambda()
    assert "WARN" in _status(s, "LMB-08")


def test_lmb08_blank_authtype_is_undetermined_not_pass():
    s = _scanner({"weird-fn": {"AuthType": ""}})
    s._check_lambda()
    assert "PASS" not in _status(s, "LMB-08")
    assert "WARN" in _status(s, "LMB-08")


def test_lmb08_unknown_authtype_still_fails():
    """Anything that is not AWS_IAM leaves the endpoint unauthenticated by AWS, so a
    future/unrecognised value must not fall through as clean."""
    s = _scanner({"odd-auth": {"AuthType": "SOMETHING_NEW"}})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-08")


# ── LMB-09: can any site read the responses? ──────────────────────────────────
def test_lmb09_wildcard_origin_fails():
    s = _scanner({"open-cors": {"AuthType": "AWS_IAM",
                                "Cors": {"AllowOrigins": ["*"]}}})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-09")


def test_lmb09_wildcard_with_credentials_says_so_in_the_finding():
    """Severity is per check and cannot vary per finding, so the materially worse
    case has to be legible in the message itself."""
    s = _scanner({"worst": {"AuthType": "NONE",
                            "Cors": {"AllowOrigins": ["*"], "AllowCredentials": True}}})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-09")
    assert "AllowCredentials" in _msgs(s, "LMB-09")


def test_lmb09_wildcard_without_credentials_does_not_claim_credentials():
    s = _scanner({"plainer": {"AuthType": "AWS_IAM",
                              "Cors": {"AllowOrigins": ["*"], "AllowCredentials": False}}})
    s._check_lambda()
    assert "FAIL" in _status(s, "LMB-09")
    assert "AllowCredentials" not in _msgs(s, "LMB-09")


def test_lmb09_explicit_origins_pass():
    s = _scanner({"scoped": {"AuthType": "AWS_IAM",
                             "Cors": {"AllowOrigins": ["https://a.internal",
                                                       "https://b.internal"]}}})
    s._check_lambda()
    assert "PASS" in _status(s, "LMB-09")
    assert "FAIL" not in _status(s, "LMB-09")


def test_lmb09_absent_cors_block_is_silent():
    """No CORS at all means no browser cross-origin access to report on — neither a
    pass nor a failure."""
    s = _scanner({"nocors": {"AuthType": "AWS_IAM"}})
    s._check_lambda()
    assert not [r for r in s.results if r.check_id == "LMB-09"]


def test_lmb09_empty_origin_list_is_silent():
    s = _scanner({"emptycors": {"AuthType": "AWS_IAM", "Cors": {"AllowOrigins": []}}})
    s._check_lambda()
    assert not [r for r in s.results if r.check_id == "LMB-09"]


def test_both_checks_report_on_the_same_function_independently():
    """The two are separate weaknesses: an IAM-authenticated URL can still have a
    wildcard CORS, and an anonymous one can have a tight CORS."""
    s = _scanner({"anon-tight": {"AuthType": "NONE",
                                 "Cors": {"AllowOrigins": ["https://a.internal"]}},
                  "iam-open": {"AuthType": "AWS_IAM",
                               "Cors": {"AllowOrigins": ["*"]}}})
    s._check_lambda()
    fails = {(r.check_id, r.resource) for r in s.results if r.status == "FAIL"}
    assert ("LMB-08", "anon-tight") in fails
    assert ("LMB-09", "iam-open") in fails
    assert ("LMB-08", "iam-open") not in fails
    assert ("LMB-09", "anon-tight") not in fails


# ── catalogue wiring ──────────────────────────────────────────────────────────
def test_maps_lockstep():
    from engine import aws_live_scanner as A
    from engine import aws_finding_detail as D
    for cid in ("LMB-08", "LMB-09"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert cid in A.REMEDIATION_MAP and cid in D.FINDING_DETAIL
        assert "aws " in A.REMEDIATION_MAP[cid].lower()


def test_cited_against_the_compute_benchmark_not_foundations():
    """These are the first checks tagged to the Compute Services Benchmark, whose
    control numbers are its own — citing them as plain "CIS" would point a reader at
    an unrelated Foundations control."""
    from engine import aws_live_scanner as A
    for cid in ("LMB-08", "LMB-09"):
        assert "CIS-COMPUTE" in A.COMPLIANCE_MAP[cid]
        assert "CIS" not in A.COMPLIANCE_MAP[cid]
