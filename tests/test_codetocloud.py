"""Unit tests for aws_codetocloud — pure IaC index + tiered T1..T5 matcher.
String/JSON fixtures only (no boto3, no yaml needed)."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_codetocloud as CC

TF = '''
resource "aws_s3_bucket" "logs" {
  bucket = "acme-logs-prod"
  tags = {
    Name      = "acme-logs"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role" "app" {
  name = "app-role"
}

resource "aws_s3_bucket" "data" {
  bucket = "acme-data-prod"
}
'''

CFN = {
    "Resources": {
        "MyBucket": {"Type": "AWS::S3::Bucket",
                     "Properties": {"BucketName": "cfn-bucket-1",
                                    "Tags": [{"Key": "env", "Value": "prod"}]}},
        "MyRole": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": "cfn-role"}},
    }
}


def _index():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "main.tf"), "w", encoding="utf-8") as f:
            f.write(TF)
        with open(os.path.join(d, "stack.json"), "w", encoding="utf-8") as f:
            json.dump(CFN, f)
        return CC.build_iac_index(d)


# ── parsing ──────────────────────────────────────────────────────────────────
def test_tf_block_extraction():
    res = CC._scan_tf_blocks(TF, "main.tf")
    by_name = {r.logical_id: r for r in res}
    assert set(by_name) == {"logs", "app", "data"}
    assert by_name["logs"].resource_type == "aws_s3_bucket"
    assert by_name["logs"].physical_name == "acme-logs-prod"
    assert by_name["logs"].tags.get("Name") == "acme-logs"
    assert by_name["logs"].tags.get("ManagedBy") == "terraform"
    assert by_name["app"].physical_name == "app-role"
    assert by_name["logs"].line == 2                 # anchor line


def test_cfn_structural_parse():
    res = CC._scan_cfn(CFN, "stack.json")
    by = {r.logical_id: r for r in res}
    assert by["MyBucket"].resource_type == "AWS::S3::Bucket"
    assert by["MyBucket"].physical_name == "cfn-bucket-1"
    assert by["MyBucket"].tags.get("env") == "prod"
    assert by["MyRole"].physical_name == "cfn-role"


def test_build_index_walks_both():
    idx = _index()
    types = {r.resource_type for r in idx.resources}
    assert "aws_s3_bucket" in types and "AWS::S3::Bucket" in types
    assert len(idx.resources) == 5                   # 3 tf + 2 cfn


# ── matcher tiers ────────────────────────────────────────────────────────────
def test_t1_exact_physical_name():
    idx = _index()
    m = CC.match_to_iac("acme-logs-prod", "S3Bucket", {}, idx)
    assert m is not None and m.confidence == "high"
    assert m.iac_resource.logical_id == "logs" and m.file.endswith("main.tf")


def test_t1_from_arn():
    idx = _index()
    m = CC.match_to_iac("arn:aws:s3:::acme-data-prod", "S3Bucket", {}, idx)
    assert m.confidence == "high" and m.iac_resource.logical_id == "data"


def test_t2_distinctive_tag_matches():
    # a genuinely distinctive custom tag (unique across the index) -> HIGH
    idx = CC.build_iac_index([])
    idx.resources = CC._scan_tf_blocks(
        'resource "aws_s3_bucket" "b" { bucket = "b" tags = { AppId = "svc-7f3a" } }', "f.tf")
    m = CC.match_to_iac("some-bucket", "S3Bucket", {"AppId": "svc-7f3a"}, idx)
    assert m is not None and m.confidence == "high" and "T2" in m.evidence


# ── regression (adversarial rank 2): a non-identifying tag must NOT match ─────
def test_t2_non_identifying_tag_no_match():
    idx = CC.build_iac_index([])
    idx.resources = (
        CC._scan_tf_blocks('resource "aws_s3_bucket" "alpha" { bucket="alpha" tags={ Environment="production" } }', "a.tf")
        + CC._scan_tf_blocks('resource "aws_s3_bucket" "beta" { bucket="beta" tags={ Environment="dev" } }', "b.tf"))
    # Environment=production is unique here but non-identifying -> no wrong-code match
    assert CC.match_to_iac("gamma-bucket", "S3Bucket", {"Environment": "production"}, idx) is None
    # aws: namespace tags are also ignored
    assert CC.match_to_iac("gamma", "S3Bucket", {"aws:cloudformation:stack-name": "s"}, idx) is None


def test_t3_cfn_logical_id():
    idx = _index()
    m = CC.match_to_iac("cfn-bucket-1-xyz", "S3Bucket",
                        {"aws:cloudformation:logical-id": "MyBucket"}, idx)
    assert m is not None and m.evidence.startswith("T3") and m.confidence == "medium"


def test_t5_type_only_single():
    # only one iam_role in the index -> LOW type-only match
    idx = CC.build_iac_index([])
    idx.resources = CC._scan_tf_blocks('resource "aws_dynamodb_table" "t" { name = "x" }', "f.tf")
    m = CC.match_to_iac("prod-table-unknown-name", "DynamoDB", {}, idx)
    assert m is not None and m.confidence == "low" and "T5" in m.evidence


def test_no_guess_when_ambiguous():
    idx = _index()
    # two aws_s3_bucket with no name/tag match and >1 candidate -> None (never guess)
    m = CC.match_to_iac("totally-unrelated-bucket-name", "S3Bucket", {}, idx)
    assert m is None


def test_matcher_closure_and_to_dict():
    idx = _index()
    match = idx.matcher()("app-role", "IAMRole", {})
    assert match.confidence == "high"
    d = match.to_dict()
    assert d["logical_id"] == "app" and d["confidence"] == "high" and "line" in d


def test_deterministic():
    idx = _index()
    a = CC.match_to_iac("acme-logs-prod", "S3Bucket", {}, idx).to_dict()
    b = CC.match_to_iac("acme-logs-prod", "S3Bucket", {}, idx).to_dict()
    assert a == b


# ── regression (adversarial rank 1): empty/unknown type must not match all ───
def test_empty_or_unknown_type_returns_none():
    idx = CC.build_iac_index([])
    idx.resources = CC._scan_tf_blocks('resource "aws_iam_role" "admin" { name = "admin-role" }', "f.tf")
    assert idx._candidates("") == [] and idx._candidates("SQSQueue") == []
    # a random S3 name with empty type must NOT anchor to the lone iam_role
    assert CC.match_to_iac("some-random-s3-bucket", "", {}, idx) is None
    # cross-type: an IAMRole-named string must not match with empty type
    idx2 = CC.build_iac_index([])
    idx2.resources = (CC._scan_tf_blocks('resource "aws_iam_role" "r" { name = "shared-name" }', "a.tf")
                      + CC._scan_tf_blocks('resource "aws_s3_bucket" "b" { bucket = "other" }', "b.tf"))
    assert CC.match_to_iac("shared-name", "", {}, idx2) is None


# ── regression (adversarial rank 3): brace-in-string must not bleed blocks ────
def test_balanced_string_aware_no_block_bleed():
    tf = ('resource "aws_s3_bucket" "alpha" { bucket = "alpha-bucket"\n'
          '  description = "a brace { here" }\n'
          'resource "aws_s3_bucket" "beta" { bucket = "beta-bucket" tags = { CostCenter = "9999" } }\n')
    res = {r.logical_id: r for r in CC._scan_tf_blocks(tf, "f.tf")}
    # alpha's tags must be empty (beta's CostCenter must NOT bleed into alpha)
    assert res["alpha"].tags == {}
    assert res["beta"].tags.get("CostCenter") == "9999"
    assert res["alpha"].physical_name == "alpha-bucket"


def test_no_cross_type_name_bleed():
    tf = ('resource "aws_iam_role" "r" { name = "role-thing"\n'
          '  assume_role_policy = "has a { brace" }\n'
          'resource "aws_s3_bucket" "b" { bucket = "shared-name" }\n')
    res = {r.logical_id: r for r in CC._scan_tf_blocks(tf, "f.tf")}
    assert res["r"].physical_name == "role-thing"     # not "shared-name"
    assert res["b"].physical_name == "shared-name"


# ── regression (adversarial rank 4): ${...} in tags must not truncate ────────
def test_tf_tags_interpolation_not_truncated():
    r = CC._scan_tf_blocks(
        'resource "aws_s3_bucket" "a" { bucket = "bucket-a" '
        'tags = { Env = "${var.env}" Team = "core" } }', "f.tf")[0]
    assert r.tags.get("Env") == "${var.env}" and r.tags.get("Team") == "core"


def test_tf_tags_nested_map_no_phantom():
    r = CC._scan_tf_blocks(
        'resource "aws_s3_bucket" "a" { bucket = "b" '
        'tags = { Meta = { team = "x" } Owner = "real-owner" } }', "f.tf")[0]
    assert "team" not in r.tags and r.tags.get("Owner") == "real-owner"


def test_parse_error_file_skipped():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.json"), "w", encoding="utf-8") as f:
            f.write("{ not valid json ")
        with open(os.path.join(d, "ok.tf"), "w", encoding="utf-8") as f:
            f.write('resource "aws_s3_bucket" "b" { bucket = "x" }')
        idx = CC.build_iac_index(d)          # must not raise
        assert len(idx.resources) == 1
