"""Phase 3 · slice 3.1 — toxic flow.

This is the flagship, and the flagship is where an overclaim costs the most. The whole
programme has been correcting one failure mode: a finding whose sentence is stronger than
the evidence behind it. AIPATH-01 shipped that for two slices at one check's worth of
surface; toxic flow would ship it at the size of the product's headline feature.

So the tests that matter are the ones about what it refuses to say:

* an ASSUMED entry is never described as an observed one, and the sentence leads with
  "IF" rather than burying the premise;
* a PROVEN entry names the specific data source that proves it, so the claim can be
  checked;
* an unreadable bucket policy leaves a source ASSUMED — an unreadable policy is not an
  open one;
* attenuation is bounded, so a guardrail can never zero a flow out. A tool that let a
  control erase a path would teach operators the control is a boundary, which is the
  belief AIGRD-01 exists to correct;
* an agent that reaches nothing produces no flow, however reachable it is.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_toxicflow as T

CROWN = "arn:aws:s3:::prod-pii"
PRIVESC = "iam:PassRole on an unscoped (*) resource"


def ds(dstype, *, name="src", dsid="ds1", bucket="arn:aws:s3:::kb-corpus"):
    cfg = {"type": dstype}
    if dstype == "S3":
        cfg["s3Configuration"] = {"bucketArn": bucket}
    return {"dataSourceId": dsid, "name": name, "dataSourceConfiguration": cfg}


# ── the entry gate ──────────────────────────────────────────────────────────
def test_a_web_crawler_is_a_proven_untrusted_path():
    """"The configuration of web URLs to crawl" — content nobody in the account
    authored. That is configuration, not an assumption about configuration."""
    a = T.source_is_untrusted(ds("WEB"))
    assert a["untrusted"] is True and a["class"] == T.PROVEN
    assert "outside the account" in a["why"]


def test_an_externally_writable_s3_source_is_proven():
    a = T.source_is_untrusted(ds("S3"), bucket_write_scope="public")
    assert a["untrusted"] is True and a["class"] == T.PROVEN
    assert "kb-corpus" in a["why"] and "WRITE" in a["why"]


def test_a_cross_account_writable_s3_source_is_proven():
    a = T.source_is_untrusted(ds("S3"), bucket_write_scope="cross_account")
    assert a["class"] == T.PROVEN


def test_an_org_writable_bucket_is_not_treated_as_external():
    """An organisation is inside the trust boundary here. Treating a sibling account as
    an attacker would fire on the normal shape of a multi-account estate, and a finding
    that fires on everyone is one nobody reads."""
    a = T.source_is_untrusted(ds("S3"), bucket_write_scope="org")
    assert a["untrusted"] is False and a["class"] == T.ASSUMED


def test_an_unreadable_bucket_policy_leaves_the_source_assumed():
    """An unreadable policy is not an open one. Defaulting the other way would
    manufacture the flagship's strongest finding out of a permissions error."""
    a = T.source_is_untrusted(ds("S3"), bucket_write_scope=None)
    assert a["class"] == T.ASSUMED


def test_multi_author_connectors_are_assumed_but_noted():
    """Confluence and SharePoint are inside the organisation and writable by many more
    people than operate the agent. Real, weaker than the open web, and not proven."""
    for t in ("CONFLUENCE", "SHAREPOINT", "SALESFORCE"):
        a = T.source_is_untrusted(ds(t))
        assert a["untrusted"] is False, t
        assert a["class"] == T.ASSUMED, t
        assert "many authors" in a["why"], t


def test_the_surface_is_proven_if_any_single_source_is():
    s = T.injection_surface([ds("S3", dsid="a"), ds("WEB", name="crawl", dsid="b")])
    assert s["entry_class"] == T.PROVEN
    assert s["proven"][0]["name"] == "crawl"


def test_an_agent_with_no_knowledge_base_is_assumed():
    s = T.injection_surface([])
    assert s["entry_class"] == T.ASSUMED and s["proven"] == []


# ── attenuation is bounded ──────────────────────────────────────────────────
def test_no_controls_means_no_reduction():
    assert T.attenuation()["factor"] == 1.0


def test_a_blocking_guardrail_reduces_the_flow():
    a = T.attenuation(guardrail_blocks=True)
    assert a["factor"] < 1.0
    assert "blocks prompt attacks" in a["applied"][0]


def test_a_mandatory_guardrail_reduces_it_further():
    loose = T.attenuation(guardrail_blocks=True)["factor"]
    tight = T.attenuation(guardrail_blocks=True, guardrail_mandatory=True)["factor"]
    assert tight < loose


def test_mandatory_alone_does_nothing_without_blocking():
    """Enforcing a guardrail that does not block is enforcing nothing — exactly the
    AIGRD-02 case, arriving here as arithmetic."""
    assert T.attenuation(guardrail_mandatory=True)["factor"] == 1.0


def test_full_confirmation_reduces_more_than_partial():
    full = T.attenuation(confirmation_gated=3, confirmation_total=3)["factor"]
    part = T.attenuation(confirmation_gated=1, confirmation_total=3)["factor"]
    assert full < part < 1.0


def test_every_control_together_still_leaves_a_flow():
    """The load-bearing test of the whole attenuation model. A guardrail raises the cost
    of an injection; it does not make one impossible — AWS's own reference records that
    guardrail input tags bypass the input check. A flow that disappeared behind a
    guardrail would teach operators the guardrail is a boundary."""
    a = T.attenuation(guardrail_blocks=True, guardrail_mandatory=True,
                      confirmation_gated=5, confirmation_total=5)
    assert a["factor"] > 0
    assert len(a["applied"]) == 3, "every control should be named in the explanation"
    # At today's weights the product is ~0.225 and the floor does not bind. That is
    # fine — the floor is a guard against a future weight edit, not the normal outcome —
    # but it means this test must not assert `floored`, because doing so would pass only
    # by accident and would break the moment somebody tuned a weight upward.
    assert a["floored"] is False


def test_the_floor_binds_when_the_weights_would_go_below_it(monkeypatch):
    """Tests the floor MECHANISM directly, since today's weights never reach it. Without
    this the floor is untested code that looks tested."""
    monkeypatch.setattr(T, "_ATTEN_FULL_CONFIRMATION", 0.01)
    a = T.attenuation(guardrail_blocks=True, confirmation_gated=1,
                      confirmation_total=1)
    assert a["factor"] == T._ATTEN_FLOOR
    assert a["floored"] is True


# ── the flow ────────────────────────────────────────────────────────────────
def test_an_agent_that_reaches_nothing_has_no_flow():
    """An injection that arrives somewhere harmless is not a finding. Reporting one is
    how a flagship computation becomes noise."""
    assert T.compute_flow(agent_name="bot",
                          entry=T.injection_surface([ds("WEB")])) is None


def test_a_proven_entry_to_crown_data_scores_higher_than_an_assumed_one():
    proven = T.compute_flow(agent_name="bot", crown=CROWN,
                            entry=T.injection_surface([ds("WEB")]))
    assumed = T.compute_flow(agent_name="bot", crown=CROWN,
                             entry=T.injection_surface([ds("S3")]))
    assert proven["score"] > assumed["score"]
    assert proven["entry_class"] == T.PROVEN
    assert assumed["entry_class"] == T.ASSUMED


def test_admin_outranks_crown_data():
    """Same reason aws_correlate does it: reaching admin is reaching everything,
    including the data."""
    admin = T.compute_flow(agent_name="b", privesc=PRIVESC)
    data = T.compute_flow(agent_name="b", crown=CROWN)
    assert admin["score"] > data["score"]


def test_a_capability_alone_is_a_flow_even_with_a_scoped_role():
    """A shell converts an instruction into an effect without touching the execution
    role at all, so 'the role is scoped' is not an answer to it."""
    f = T.compute_flow(agent_name="b", capabilities=["ANTHROPIC.Bash"],
                       capability_severity="CRITICAL")
    assert f is not None
    assert "direct execution" in f["terminals"][0]


def test_attenuation_lowers_the_score_without_removing_the_flow():
    bare = T.compute_flow(agent_name="b", crown=CROWN,
                          entry=T.injection_surface([ds("WEB")]))
    tight = T.compute_flow(agent_name="b", crown=CROWN,
                           entry=T.injection_surface([ds("WEB")]),
                           atten=T.attenuation(guardrail_blocks=True,
                                               guardrail_mandatory=True,
                                               confirmation_gated=2,
                                               confirmation_total=2))
    assert 0 < tight["score"] < bare["score"]


# ── what it refuses to say ──────────────────────────────────────────────────
def test_an_assumed_flow_leads_with_the_premise():
    """A reader who stops after the first clause must not come away believing an
    injection was observed. This is the AIPATH-01 lesson applied to the sentence that
    will appear on the product's headline screen."""
    f = T.compute_flow(agent_name="bot", crown=CROWN,
                       entry=T.injection_surface([ds("S3")]))
    s = T.describe(f)
    assert s.startswith("IF an injection reaches")
    assert "assumed" in s


def test_a_proven_flow_names_the_source_that_proves_it():
    """A claim a reader cannot check is a claim they have to take on trust, and this one
    is too strong to be taken on trust."""
    f = T.compute_flow(agent_name="bot", crown=CROWN,
                       entry=T.injection_surface([ds("WEB", name="public-docs")]))
    s = T.describe(f)
    assert "public-docs" in s
    assert not s.startswith("IF")


def test_the_description_never_asserts_an_incident():
    for entry in (T.injection_surface([ds("WEB")]), T.injection_surface([ds("S3")])):
        s = T.describe(T.compute_flow(agent_name="b", privesc=PRIVESC, crown=CROWN,
                                      entry=entry)).lower()
        for banned in ("was compromised", "has been", "attacker gained", "exfiltrated",
                       "breach", "incident"):
            assert banned not in s, f"{banned!r} asserts an occurrence"


def test_the_description_says_when_nothing_stands_in_the_way():
    f = T.compute_flow(agent_name="b", crown=CROWN)
    assert "Nothing stands between the instruction and the act" in T.describe(f)


def test_the_module_reads_no_prompt_content():
    """Decision D2 in force at the flagship. The whole point of computing capability is
    that it needs no prompt text, and a regex over conversation content here would
    quietly reverse a decision taken deliberately."""
    import inspect
    src = inspect.getsource(T).lower()
    for word in ("prompt_text", "completion", "inputtext", "conversation", "messages"):
        assert f'"{word}"' not in src and f"'{word}'" not in src


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    bad = re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests|urllib)\b",
                     inspect.getsource(T), re.M)
    assert not bad, f"pure computation imports I/O: {bad}"


@pytest.mark.parametrize("bad", [None, {}, {"dataSourceConfiguration": None},
                                 "nope", {"dataSourceConfiguration": {"type": None}}])
def test_nothing_raises_on_malformed_sources(bad):
    T.source_is_untrusted(bad)
    T.injection_surface([bad])


def test_compute_flow_never_raises_on_missing_inputs():
    assert T.compute_flow(agent_name="") is None
    T.describe(None)
