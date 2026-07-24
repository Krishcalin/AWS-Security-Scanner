"""Slice 1 · Batch 4 — pure AWS-resident secrets core (aws_secrets). No boto3."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_secrets as S
import aws_deepplane as D


def test_name_looks_secret():
    assert S.name_looks_secret("DB_PASSWORD") and S.name_looks_secret("apiKey")
    assert S.name_looks_secret("client-secret") and S.name_looks_secret("AWS_ACCESS_KEY")
    assert not S.name_looks_secret("username") and not S.name_looks_secret("HOSTNAME")
    # references to a secret (suffix arn/id/name/...) are NOT the secret itself
    assert not S.name_looks_secret("SECRETS_MANAGER_ARN")
    assert not S.name_looks_secret("API_KEY_ID") and not S.name_looks_secret("SECRET_NAME")
    assert not S.name_looks_secret("passwordless")           # exact deny
    # adversarial-verify regression: a real credential that merely CONTAINS a deny substring
    assert S.name_looks_secret("PASSWORDLESS_SECRET")
    assert S.name_looks_secret("SECRETSMANAGER_FALLBACK_PASSWORD")


def test_classify_ssm_plaintext_string():
    c = S.classify_ssm_parameter({"Name": "/app/db_password", "Type": "String"})
    assert c["plaintext"] and c["kms"] == "none" and c["name_secret"]


def test_classify_ssm_securestring_managed_vs_cmk():
    managed = S.classify_ssm_parameter({"Name": "/app/x", "Type": "SecureString"})
    assert not managed["plaintext"] and managed["kms"] == "managed"
    managed2 = S.classify_ssm_parameter({"Name": "/app/x", "Type": "SecureString",
                                         "KeyId": "alias/aws/ssm"})
    assert managed2["kms"] == "managed"
    cmk = S.classify_ssm_parameter({"Name": "/app/x", "Type": "SecureString",
                                    "KeyId": "arn:aws:kms:us-east-1:111:key/abc"})
    assert cmk["kms"] == "cmk"


def test_classify_ssm_staleness():
    now = 1_000_000_000
    c = S.classify_ssm_parameter({"Name": "n", "Type": "String",
                                  "LastModifiedDate": now - 100 * 86400}, now_epoch=now)
    assert c["stale_days"] == 100
    assert S.classify_ssm_parameter({"Name": "n", "Type": "String"}, now_epoch=now)["stale_days"] is None


def test_classify_ssm_datetime_last_modified():
    import datetime
    now = 1_000_000_000
    dt = datetime.datetime.fromtimestamp(now - 30 * 86400, datetime.timezone.utc)
    c = S.classify_ssm_parameter({"Name": "n", "Type": "String", "LastModifiedDate": dt}, now_epoch=now)
    assert c["stale_days"] == 30


def test_env_secret_findings_literal_only():
    hits = S.env_secret_findings([("DB_PASSWORD", "hunter2"), ("HOST", "db.local"),
                                  ("API_KEY", "")], "ecs:svc")
    assert len(hits) == 1 and hits[0]["name"] == "DB_PASSWORD"


def test_content_secret_findings_preview_only():
    key = "AKIAQK7R3ZP2W9NB4XTL"                      # AKIA + 16, not the denied *EXAMPLE key
    hits = S.content_secret_findings(f"export AWS_ACCESS_KEY_ID={key}", "userdata:i-1")
    assert hits and all("preview" in h for h in hits)
    assert all(key not in h["preview"] for h in hits)  # never the raw secret


def test_cfn_plaintext_secret_params():
    params = {"DBPassword": {"Type": "String", "NoEcho": False},
              "SafePassword": {"Type": "String", "NoEcho": True},
              "InstanceType": {"Type": "String"}}
    assert S.cfn_plaintext_secret_params(params) == ["DBPassword"]


def test_secret_read_actions_via_role_can_read_store():
    arn = "arn:aws:secretsmanager:us-east-1:111:secret:prod/db-AbCdEf"
    st = [{"effect": "Allow", "actions": {"secretsmanager:getsecretvalue"},
           "resources": {arn.lower()}, "not_resources": set(), "condition": None}]
    assert D.role_can_read_store(st, arn, S.SECRET_READ_ACTIONS) == {"conditioned": False}
    # a non-read action does not grant
    st2 = [{"effect": "Allow", "actions": {"secretsmanager:describesecret"},
            "resources": {arn.lower()}, "not_resources": set(), "condition": None}]
    assert D.role_can_read_store(st2, arn, S.SECRET_READ_ACTIONS) is None
