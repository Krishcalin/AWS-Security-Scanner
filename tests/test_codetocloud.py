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


def test_t2_unique_tag():
    idx = _index()
    # no physical-name match, but a distinctive tag hits exactly one resource
    m = CC.match_to_iac("some-bucket", "S3Bucket", {"ManagedBy": "terraform"}, idx)
    assert m is not None and m.confidence == "high" and "T2" in m.evidence


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


def test_parse_error_file_skipped():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "bad.json"), "w", encoding="utf-8") as f:
            f.write("{ not valid json ")
        with open(os.path.join(d, "ok.tf"), "w", encoding="utf-8") as f:
            f.write('resource "aws_s3_bucket" "b" { bucket = "x" }')
        idx = CC.build_iac_index(d)          # must not raise
        assert len(idx.resources) == 1
