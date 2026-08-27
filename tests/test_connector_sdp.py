"""ManageEngine ServiceDesk Plus: auto-created tickets (OW2-CC-020/022/023).

WHY THIS CONNECTOR NEEDED ITS OWN TESTS RATHER THAN THE SHARED ONES
--------------------------------------------------------------------
Every other connector speaks JSON and reports failure with an HTTP status. SDP v3
does neither, and both differences fail SILENTLY:

  1. The body is FORM-ENCODED, with the whole JSON inside one `input_data` field.
     Sending a JSON body returns 200 and creates nothing.
  2. A logical failure arrives INSIDE an HTTP 200, as
     `response_status.status_code != 2000`. Trusting the HTTP status alone records
     every rejected ticket as delivered.

Either mistake produces a connector that looks healthy in the delivery ledger
while no tickets exist — which is precisely the "compiles and does not work"
outcome D13 warns about when a vendor contract is taken on trust. So the two
tests that matter here are `test_the_body_is_form_encoded_not_json` and
`test_a_logical_failure_inside_http_200_is_not_success`.

DEPLOYMENT DEFAULTS TO ON-PREMISE
---------------------------------
Cloud uses `Authorization: Zoho-oauthtoken` and nests the portal in the path;
on-premise uses a bare `authtoken` header and does not. CON-01 puts this
deployment self-hosted inside India, so on-premise is the default — and
`deployment` is an explicit config key rather than something inferred from the
URL, because guessing wrong fails at delivery time instead of at configuration
time.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cnapp_connectors as C  # noqa: E402

NOW = 1_700_000_000


def conn(**cfg):
    base = {"base_url": "https://sdp.internal.example"}
    base.update(cfg)
    return C.Connector(connector_id="c1", type="sdp", name="SDP",
                       config=base, enabled=True, secret_ref="ssm://k")


def finding(**kw):
    base = dict(check_id="S3-01", section="S3", severity="CRITICAL", status="FAIL",
                compliance={"CIS": "2.1.5"}, remediation_cmd="aws s3api put-...",
                risk="The bucket is public.", impact="Anyone can read it.",
                steps=["Enable Block Public Access", "Re-scan"],
                affected=["arn:aws:s3:::a", "arn:aws:s3:::b"], count=2, distinct=2,
                account="111111111111", on_attack_path=True)
    base.update(kw)
    return C.EnrichedFinding(**base)


def body_of(req) -> dict:
    """The decoded input_data JSON from a form-encoded request."""
    parsed = urllib.parse.parse_qs(req.raw_body.decode("utf-8"))
    return json.loads(parsed["input_data"][0])


# ── the two that fail silently if wrong ─────────────────────────────────────

def test_the_body_is_form_encoded_not_json():
    """A JSON body returns 200 and creates nothing."""
    req = C.request_for(conn(), C.render_sdp(conn(), finding()), "tok", now_epoch=NOW)
    assert req.json_body is None, "SDP must not use the shared JSON path"
    assert req.raw_body is not None
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    parsed = urllib.parse.parse_qs(req.raw_body.decode("utf-8"))
    assert list(parsed) == ["input_data"], "the whole payload lives in one field"
    assert "request" in json.loads(parsed["input_data"][0])


def test_a_logical_failure_inside_http_200_is_not_success():
    """SDP reports rejection with HTTP 200 + status_code != 2000."""
    resp = C.HttpResp(200, json.dumps({
        "response_status": {"status_code": 4001, "status": "failed",
                            "messages": [{"message": "requester is not valid"}]}}))
    out = C.interpret_response(conn(), resp)
    assert out.ok is False
    assert "requester is not valid" in out.error
    assert "SDP 4001" in out.error


def test_a_real_success_is_recognised_and_carries_the_ticket_id():
    resp = C.HttpResp(200, json.dumps({
        "response_status": {"status_code": 2000, "status": "success"},
        "request": {"id": "80512"}}))
    out = C.interpret_response(conn(), resp)
    assert out.ok is True
    assert out.external_ref == "80512"
    assert "woID=80512" in out.detail, "the ledger links back to the ticket"


def test_a_status_wrapped_in_a_list_is_still_read():
    """Some SDP builds return response_status as a single-element list."""
    resp = C.HttpResp(200, json.dumps({
        "response_status": [{"status_code": 2000, "status": "success"}],
        "request": {"id": "9"}}))
    assert C.interpret_response(conn(), resp).ok is True


def test_an_http_error_is_still_a_failure():
    assert C.interpret_response(conn(), C.HttpResp(401, "nope")).ok is False


def test_an_unparseable_body_fails_rather_than_defaulting_to_success():
    assert C.interpret_response(conn(), C.HttpResp(200, "<html>")).ok is False


# ── auth and endpoint shape ────────────────────────────────────────────────

def test_on_premise_is_the_default_and_uses_a_bare_authtoken_header():
    req = C.request_for(conn(), {"request": {}}, "SECRET", now_epoch=NOW)
    assert req.headers["authtoken"] == "SECRET"
    assert "Authorization" not in req.headers
    assert req.url == "https://sdp.internal.example/api/v3/requests"


def test_cloud_uses_the_zoho_oauth_header_and_the_portal_path():
    c = conn(deployment="cloud", portal="acme")
    req = C.request_for(c, {"request": {}}, "TOK", now_epoch=NOW)
    assert req.headers["Authorization"] == "Zoho-oauthtoken TOK"
    assert "authtoken" not in req.headers
    assert req.url == "https://sdp.internal.example/app/acme/api/v3/requests"


def test_a_fully_specified_endpoint_is_used_verbatim():
    """Instances behind a reverse proxy match neither default shape."""
    c = conn(base_url="https://proxy/x/api/v3/requests")
    assert C.request_for(c, {"request": {}}, "t").url == "https://proxy/x/api/v3/requests"


def test_the_vendor_accept_header_is_always_sent():
    """Without it SDP may answer with an older schema."""
    req = C.request_for(conn(), {"request": {}}, "t")
    assert req.headers["Accept"] == "application/vnd.manageengine.sdp.v3+json"


def test_the_secret_never_appears_in_the_body():
    req = C.request_for(conn(), C.render_sdp(conn(), finding()), "SUPERSECRET",
                        now_epoch=NOW)
    assert b"SUPERSECRET" not in req.raw_body


# ── the OW2-CC-022 payload ─────────────────────────────────────────────────

def test_the_ticket_carries_the_structured_payload():
    r = C.render_sdp(conn(), finding(), hub_base="https://ow.example")["request"]
    d = r["description"]
    assert "S3-01" in r["subject"] and "CRITICAL" in r["subject"]
    assert "The bucket is public." in d
    assert "Anyone can read it." in d
    assert "1. Enable Block Public Access" in d
    assert "aws s3api put-" in d
    assert "arn:aws:s3:::a" in d
    assert "111111111111" in d
    assert "CIS 2.1.5" in d
    assert "On attack path: yes" in d


def test_the_ticket_deep_links_back_to_the_finding():
    r = C.render_sdp(conn(), finding(), hub_base="https://ow.example")["request"]
    assert "https://ow.example/findings/S3-01?account=111111111111" in r["description"]


def test_no_hub_base_means_no_broken_link():
    r = C.render_sdp(conn(), finding())["request"]
    assert "Open in OverWatch" not in r["description"]


def test_the_due_date_mirrors_the_sla_policy():
    r = C.render_sdp(conn(), finding(severity="CRITICAL"), now_epoch=NOW)["request"]
    # 15 days for CRITICAL (OW2-AR-031), in epoch MILLISECONDS as a string.
    assert r["due_by_time"]["value"] == str((NOW + 15 * 86400) * 1000)


def test_a_severity_with_no_sla_gets_no_invented_due_date():
    r = C.render_sdp(conn(), finding(severity="INFO"), now_epoch=NOW)["request"]
    assert "due_by_time" not in r


def test_the_affected_list_declares_what_it_did_not_show():
    f = finding(affected=["arn:%d" % i for i in range(40)], count=40, distinct=40)
    d = C.render_sdp(conn(), f)["request"]["description"]
    assert "AFFECTED (40 distinct)" in d
    assert "and 20 more" in d, "the cap declares itself, as everywhere else"


def test_instance_specific_lookups_are_omitted_unless_configured():
    """A default SDP install has no 'Cloud Security' group; sending one would be
    rejected for naming something that does not exist."""
    plain = C.render_sdp(conn(), finding())["request"]
    for k in ("group", "category", "technician", "requester"):
        assert k not in plain
    rich = C.render_sdp(conn(group="Cloud Security", category="Security"),
                        finding())["request"]
    assert rich["group"] == {"name": "Cloud Security"}
    assert rich["category"] == {"name": "Security"}


def test_priority_maps_from_severity_and_is_overridable():
    assert C.render_sdp(conn(), finding(severity="CRITICAL"))["request"]["priority"] \
        == {"name": "High"}
    assert C.render_sdp(conn(), finding(severity="LOW"))["request"]["priority"] \
        == {"name": "Low"}
    assert C.render_sdp(conn(priority="P1"), finding())["request"]["priority"] \
        == {"name": "P1"}


def test_the_subject_is_bounded():
    f = finding(section="x" * 500)
    assert len(C.render_sdp(conn(), f)["request"]["subject"]) <= 250


def test_a_template_overrides_the_subject():
    r = C.render_sdp(conn(), finding(), template="SEC $check_id on $account")["request"]
    assert r["subject"] == "SEC S3-01 on 111111111111"


def test_the_description_is_plain_text_not_markup():
    """SDP renders HTML only when configured for it; a ticket full of unrendered
    markup is worse than one that is plain."""
    d = C.render_sdp(conn(), finding())["request"]["description"]
    assert "<p>" not in d and "**" not in d


# ── registration ───────────────────────────────────────────────────────────

def test_sdp_is_a_known_connector_type_with_a_renderer():
    assert "sdp" in C._CONNECTOR_TYPES
    assert C.RENDERERS["sdp"] is C.render_sdp


def test_the_shared_render_entry_point_routes_sdp():
    out = C.render(conn(), finding(), event_id="e", now_epoch=NOW,
                   hub_base="https://ow.example")
    assert "request" in out and "subject" in out["request"]
