"""Phase 4 · slice 4.3 — where the prompts land, and who saw the call.

Two gaps this closes, and both are gaps in advice OverWatch already gives.

`BDR-01` tells operators to turn model invocation logging on and names the destination.
It never asks whether that destination is safe — and with `textDataDeliveryEnabled` true
that bucket receives every prompt and every completion in the account. Turning logging on
**creates a crown jewel**; this is the second half of BDR-01's own advice, not an
argument against it.

`LOG-08` asks whether a trail records data events *at all*. An account passes it while no
trail anywhere records `AWS::Bedrock::Model`, which means no record of who invoked which
model — the first question an incident responder asks, and the one `AITHR-01` needs to
detect LLMjacking.

Three readings that had to be verified rather than assumed, each pinned below: the four
delivery switches are independent; `largeDataDeliveryS3Config` is a *third* destination;
and Bedrock data events require **advanced** selectors, so a trail full of S3 data events
carries no AI coverage at all.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ailog as AL


def cfg(text=True, image=False, embedding=False, video=False,
        s3=None, cw=None, large=None):
    c = {"textDataDeliveryEnabled": text, "imageDataDeliveryEnabled": image,
         "embeddingDataDeliveryEnabled": embedding, "videoDataDeliveryEnabled": video}
    if s3:
        c["s3Config"] = {"bucketName": s3, "keyPrefix": "bedrock/"}
    if cw or large:
        c["cloudWatchConfig"] = {"logGroupName": cw or "/aws/bedrock",
                                 "roleArn": "arn:aws:iam::1:role/r"}
        if large:
            c["cloudWatchConfig"]["largeDataDeliveryS3Config"] = {"bucketName": large}
    return c


def trail(name="t1", types=()):
    return {"name": name, "selectors": {"AdvancedEventSelectors": [
        {"Name": "ai", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": list(types)}]}]}}


# ── the delivery switches ───────────────────────────────────────────────────
def test_the_four_switches_are_independent():
    """Read off the service model. A config can log text and not images, and the
    sensitivity of the destination follows whichever are on."""
    assert AL.DELIVERY_SWITCHES == (
        "textDataDeliveryEnabled", "imageDataDeliveryEnabled",
        "embeddingDataDeliveryEnabled", "videoDataDeliveryEnabled")


def test_text_delivery_makes_the_destination_a_prompt_store():
    p = AL.delivery_posture(cfg(text=True))
    assert p["carries_content"] is True
    assert p["modalities"] == ["text"]


def test_embeddings_alone_do_not_make_it_a_prompt_store():
    """An embedding is derived rather than the user's own words. It is still sensitive,
    but this slice's finding is about the destination holding prompts and completions,
    and stretching that to cover a metrics-shaped config would dilute it."""
    p = AL.delivery_posture(cfg(text=False, embedding=True))
    assert p["carries_content"] is False
    assert p["delivering"] == ["embeddingDataDeliveryEnabled"]


def test_everything_off_carries_nothing():
    p = AL.delivery_posture(cfg(text=False))
    assert p["carries_content"] is False and p["delivering"] == []


def test_an_absent_config_is_not_enabled():
    assert AL.delivery_posture({})["enabled"] is False
    assert AL.delivery_posture(None)["enabled"] is False


# ── the three destinations ──────────────────────────────────────────────────
def test_the_s3_and_cloudwatch_sinks_are_both_found():
    sinks = AL.log_destinations(cfg(s3="prompt-logs", cw="/aws/bedrock/inv"))
    kinds = {s["kind"]: s["name"] for s in sinks}
    assert kinds == {"s3": "prompt-logs", "cloudwatch": "/aws/bedrock/inv"}


def test_the_large_payload_overflow_bucket_is_a_third_destination():
    """The one operators forget. It receives the LARGEST payloads — pasted documents and
    long transcripts — which is what makes forgetting it the expensive case."""
    sinks = AL.log_destinations(cfg(cw="/aws/bedrock", large="overflow-bucket"))
    names = [s["name"] for s in sinks]
    assert "overflow-bucket" in names
    over = next(s for s in sinks if s["name"] == "overflow-bucket")
    assert over["kind"] == "s3" and over["role"] == "large-payload overflow"


def test_all_three_destinations_are_reported_together():
    sinks = AL.log_destinations(cfg(s3="a", cw="/g", large="b"))
    assert sorted(s["name"] for s in sinks) == ["/g", "a", "b"]


def test_no_destination_is_an_empty_list_not_an_error():
    assert AL.log_destinations(cfg(text=True)) == []
    assert AL.log_destinations(None) == []


def test_the_description_names_the_modality_and_the_sink():
    line = AL.describe_delivery(AL.delivery_posture(cfg(text=True, image=True)),
                                AL.log_destinations(cfg(s3="prompt-logs")))
    assert "text and image" in line and "prompt-logs" in line
    assert "prompts users send" in line


def test_the_description_is_empty_when_nothing_sensitive_is_written():
    assert AL.describe_delivery(AL.delivery_posture(cfg(text=False)), []) == ""


# ── data event coverage ─────────────────────────────────────────────────────
def test_model_invocation_coverage_is_detected():
    cov = AL.trail_ai_data_events([trail(types=["AWS::Bedrock::Model"])])
    assert cov["model_invocations"] is True and cov["any"] is True


def test_no_ai_types_reads_as_no_coverage():
    cov = AL.trail_ai_data_events([trail(types=["AWS::S3::Object"])])
    assert cov["any"] is False and cov["model_invocations"] is False


def test_basic_event_selectors_are_not_ai_coverage():
    """Basic selectors accept only DynamoDB, Lambda and S3 object types, so a trail
    configured that way cannot carry Bedrock activity however many data events it logs.
    Counting them would let S3 data events masquerade as AI coverage."""
    t = {"name": "t1", "selectors": {"EventSelectors": [
        {"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::x/"]}]}]}}
    assert AL.trail_ai_data_events([t])["any"] is False


def test_coverage_is_a_union_across_trails():
    """Any one trail satisfies coverage. An account with a dedicated Bedrock trail and a
    broad management trail is correctly configured, and evaluating trails independently
    would report the management trail as a gap."""
    cov = AL.trail_ai_data_events([
        trail("mgmt", types=["AWS::S3::Object"]),
        trail("ai", types=["AWS::Bedrock::Model"])])
    assert cov["model_invocations"] is True
    assert cov["by_trail"] == {"ai": ["AWS::Bedrock::Model"]}


def test_missing_types_are_named_rather_than_counted():
    cov = AL.trail_ai_data_events([trail(types=["AWS::Bedrock::Model"])])
    assert "AWS::Bedrock::Model" not in cov["bedrock_missing"]
    assert "AWS::Bedrock::KnowledgeBase" in cov["bedrock_missing"]


def test_agentcore_gaps_are_tracked_apart_from_bedrock():
    """An account can run one estate and not the other, and reporting a gap in a service
    the customer does not use is noise."""
    cov = AL.trail_ai_data_events([trail(types=["AWS::Bedrock::Model"])])
    assert set(cov["agentcore_missing"]) == set(AL.AGENTCORE_DATA_TYPES)


def test_the_resource_type_strings_are_the_documented_ones():
    """Taken verbatim from the CloudTrail reference; a typo here means a check that
    silently never matches, which reads exactly like a check that always passes."""
    assert AL.MODEL_DATA_TYPE == "AWS::Bedrock::Model"
    for t in AL.BEDROCK_DATA_TYPES:
        assert t.startswith("AWS::Bedrock::")
    for t in AL.AGENTCORE_DATA_TYPES:
        assert t.startswith("AWS::BedrockAgentCore::")


def test_no_trails_reads_as_no_coverage():
    assert AL.trail_ai_data_events([])["any"] is False
    assert AL.trail_ai_data_events(None)["any"] is False


# ── the line this slice does not cross ──────────────────────────────────────
def test_the_module_reads_configuration_not_logs():
    """The whole reason the destination matters is that it holds prompts. A scanner that
    read them to check them would be the second copy of the problem — D2 and D8."""
    import ast
    import inspect
    tree = ast.parse(inspect.getsource(AL))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            b = node.body
            if (b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant)
                    and isinstance(b[0].value.value, str)):
                b.pop(0)
    code = ast.unparse(tree).lower()
    for banned in ("get_log_events", "filter_log_events", "start_query",
                   "get_object", "getlogevents", "getobject"):
        assert banned not in code, f"{banned} appears in executable code"


def test_the_refusal_is_stated_for_the_reader():
    assert "never the logs" in AL.CONTENTS_NOT_READ


def test_the_module_makes_no_aws_calls():
    import inspect
    import re
    assert not re.findall(r"^\s*(?:import|from)\s+(boto3|botocore|requests)\b",
                          inspect.getsource(AL), re.M)


@pytest.mark.parametrize("bad", [None, {}, "nope", 7, [],
                                 {"cloudWatchConfig": "x"}, {"s3Config": 5}])
def test_nothing_raises_on_malformed_input(bad):
    AL.delivery_posture(bad if isinstance(bad, dict) else None)
    AL.log_destinations(bad if isinstance(bad, dict) else None)
    AL.trail_ai_data_events(bad if isinstance(bad, list) else None)
    AL.describe_delivery(bad if isinstance(bad, dict) else None, None)
