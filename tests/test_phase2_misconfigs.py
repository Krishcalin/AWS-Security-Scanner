"""Phase 2 marquee-misconfig checks (OverWatch vuln roadmap): KMS-02/04 key-policy
public/cross-account, SEC-05 secret policy, IAMPE-23 federated trust, R53-06 dangling
DNS, CW-01..16 CloudWatch CIS §4, LOG-07..10 CloudTrail depth, COG-05/06 Cognito
identity pools. Reuses the mocked-boto3 harness from test_live_scanner; no AWS creds."""
import json
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import aws_live_scanner as A
from test_live_scanner import MockClientError, MockPaginator, make_scanner

OWN = "123456789012"       # make_scanner sets scanner.account to this
EXT = "999999999999"


# ── classify_resource_policy_stmt (shared public/cross-account classifier) ────
def _c(stmt, own=OWN):
    return A.classify_resource_policy_stmt(stmt, own)


def test_classify_public_wildcard():
    assert _c({"Effect": "Allow", "Principal": "*", "Action": "kms:*"})["kind"] == "public"
    assert _c({"Effect": "Allow", "Principal": {"AWS": "*"}})["kind"] == "public"
    assert _c({"Effect": "Allow", "Principal": {"AWS": ["*", f"arn:aws:iam::{OWN}:root"]}})["kind"] == "public"


def test_classify_public_conditioned():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:username": "bob"}}})
    assert r["kind"] == "public_conditioned"


def test_classify_wildcard_scoped_to_own_is_private():
    # Principal "*" + kms:CallerAccount == own -> NOT public (the #1 FP trap)
    assert _c({"Effect": "Allow", "Principal": "*",
               "Condition": {"StringEquals": {"kms:CallerAccount": OWN}}}) is None


def test_classify_wildcard_scoped_to_other_account():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:SourceAccount": EXT}}})
    assert r["kind"] == "cross_account" and r["external_accounts"] == [EXT]


def test_classify_org_scoped():
    r = _c({"Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}})
    assert r["kind"] == "org" and r["org_id"] == "o-abc123"


def test_classify_cross_account_explicit():
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"}})["kind"] == "cross_account"
    assert _c({"Effect": "Allow", "Principal": {"AWS": EXT}})["external_accounts"] == [EXT]  # bare 12-digit id


def test_classify_own_and_service_and_deny_are_none():
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"}}) is None
    assert _c({"Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"}}) is None
    assert _c({"Effect": "Deny", "Principal": "*"}) is None
    assert _c({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:role/app"}}) is None


def test_classify_notprincipal_is_public():
    assert _c({"Effect": "Allow", "NotPrincipal": {"AWS": f"arn:aws:iam::{OWN}:root"},
               "Action": "kms:*"})["kind"] == "public"


# ── KMS-02 / KMS-04 integration ──────────────────────────────────────────────
def _kms_scanner(meta, policies):
    s = make_scanner(["KMS"])
    kms = MagicMock()
    kms.get_paginator.return_value = MockPaginator("Keys", [{"KeyId": k} for k in meta])
    kms.describe_key.side_effect = lambda KeyId: {"KeyMetadata": meta[KeyId]}
    kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
    kms.get_key_policy.side_effect = lambda KeyId, PolicyName: {"Policy": policies.get(KeyId, "{}")}
    s._clients["kms:us-east-1"] = kms
    return s


def _cmk(arn_suffix):
    return {"KeyManager": "CUSTOMER", "KeyState": "Enabled",
            "Arn": f"arn:aws:kms:us-east-1:{OWN}:key/{arn_suffix}", "MultiRegion": False}


def test_kms_02_public_and_kms_04_crossaccount():
    pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "kms:*", "Resource": "*"}]})
    root = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                                      "Action": "kms:*", "Resource": "*"}]})
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "kms:Decrypt", "Resource": "*"}]})
    s = _kms_scanner({"k-pub": _cmk("k-pub"), "k-clean": _cmk("k-clean"), "k-cross": _cmk("k-cross")},
                     {"k-pub": pub, "k-clean": root, "k-cross": cross})
    s._check_kms()
    assert any(r.check_id == "KMS-02" and r.status == "FAIL" and r.resource == "k-pub" for r in s.results)
    assert any(r.check_id == "KMS-04" and r.status == "FAIL" and r.resource == "k-cross"
               and EXT in r.message for r in s.results)
    # the default root-only key policy is benign — no FAIL
    assert not any(r.check_id in ("KMS-02", "KMS-04") and r.status == "FAIL" and r.resource == "k-clean"
                   for r in s.results)
    st = s.graph.stats()
    assert "PUBLIC_KMS" in st["edge_kinds"] and "SHARED_KMS" in st["edge_kinds"]


def test_kms_02_skips_aws_managed_keys():
    aws_key = {"KeyManager": "AWS", "KeyState": "Enabled", "Arn": "arn:...:key/aws"}
    s = _kms_scanner({"k-aws": aws_key},
                     {"k-aws": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*"}]})})
    s._check_kms()
    assert not any(r.check_id in ("KMS-02", "KMS-04") for r in s.results)   # AWS-managed skipped


def test_kms_02_org_share_warns_not_fails():
    org = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                     "Action": "kms:Decrypt", "Resource": "*",
                                     "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xyz"}}}]})
    s = _kms_scanner({"k-org": _cmk("k-org")}, {"k-org": org})
    s._check_kms()
    assert any(r.check_id == "KMS-04" and r.status == "WARN" and "o-xyz" in r.message for r in s.results)
    assert not any(r.check_id == "KMS-04" and r.status == "FAIL" for r in s.results)


def test_kms_02_get_key_policy_denied_warns():
    s = _kms_scanner({"k-deny": _cmk("k-deny")}, {})
    s._clients["kms:us-east-1"].get_key_policy.side_effect = RuntimeError("AccessDeniedException")
    s._check_kms()
    assert any(r.check_id == "KMS-02" and r.status == "WARN" and "could not evaluate" in r.message
               for r in s.results)


def test_kms_02_trusted_account_suppressed():
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "kms:Decrypt", "Resource": "*"}]})
    s = _kms_scanner({"k-t": _cmk("k-t")}, {"k-t": cross})
    s.trusted_accounts = {EXT}
    s._check_kms()
    assert not any(r.check_id == "KMS-04" and r.status == "FAIL" for r in s.results)


def test_kms_02_04_map_entries_complete():
    for cid in ("KMS-02", "KMS-04"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── SEC-05 — Secrets Manager resource policy public / cross-account ───────────
def _secrets_scanner(secrets, policies):
    s = make_scanner(["SECRETS"])
    sm = MagicMock()
    sm.get_paginator.return_value = MockPaginator("SecretList", secrets)
    sm.get_resource_policy.side_effect = lambda SecretId: (
        {"ResourcePolicy": policies[SecretId]} if SecretId in policies else {})
    s._clients["secretsmanager:us-east-1"] = sm
    return s


def _sec(arn, name):
    return {"ARN": arn, "Name": name, "RotationEnabled": True,
            "RotationRules": {"AutomaticallyAfterDays": 30}, "KmsKeyId": "arn:aws:kms:::key/cmk"}


def test_sec_05_public_and_crossaccount():
    pub = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*",
                                     "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    cross = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{EXT}:root"},
                                       "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    own = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{OWN}:root"},
                                     "Action": "secretsmanager:GetSecretValue", "Resource": "*"}]})
    secrets = [_sec("arn:pub", "pub"), _sec("arn:cross", "cross"),
               _sec("arn:own", "own"), _sec("arn:nopol", "nopol")]
    s = _secrets_scanner(secrets, {"arn:pub": pub, "arn:cross": cross, "arn:own": own})
    s._check_secrets()
    assert any(r.check_id == "SEC-05" and r.status == "FAIL" and r.resource == "pub" for r in s.results)
    assert any(r.check_id == "SEC-05" and r.status == "FAIL" and r.resource == "cross"
               and EXT in r.message for r in s.results)
    # own-account-only policy and no-policy secret -> no SEC-05 noise
    assert not any(r.check_id == "SEC-05" and r.resource in ("own", "nopol") for r in s.results)
    assert "SHARED_SECRET" in s.graph.stats()["edge_kinds"]


def test_sec_05_denied_policy_is_silent():
    s = _secrets_scanner([_sec("arn:x", "x")], {})
    s._clients["secretsmanager:us-east-1"].get_resource_policy.side_effect = RuntimeError("AccessDenied")
    s._check_secrets()
    assert not any(r.check_id == "SEC-05" for r in s.results)   # per-secret error is swallowed, not a crash


def test_sec_05_map_complete():
    assert A.CHECK_SEVERITY.get("SEC-05") == "CRITICAL" and "SEC-05" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("SEC-05", "").lower()


# ── IAMPE-23 — federated OIDC/SAML wildcard trust ────────────────────────────
import aws_graph


def _role(name, trust):
    return {"type": "role", "name": name, "_node": f"arn:aws:iam::{OWN}:role/{name}", "trust": trust}


def _oidc(sub=None, host="token.actions.githubusercontent.com", aud="sts.amazonaws.com"):
    se = {}
    if aud is not None:
        se[f"{host}:aud"] = aud
    if sub is not None:
        se[f"{host}:sub"] = sub
    return {"effect": "Allow", "aws": [], "service": [],
            "federated": [f"arn:aws:iam::{OWN}:oidc-provider/{host}"],
            "actions": {"sts:assumerolewithwebidentity"}, "wildcard": False,
            "has_condition": bool(se), "condition": {"StringEquals": se} if se else None}


def _fed_scanner():
    s = make_scanner(["IAMPRIVESC"])
    s.graph = aws_graph.SecurityGraph()
    return s


def test_oidc_sub_scope_classification():
    f = A.AWSLiveScanner._oidc_sub_scope
    assert f([]) == "open"
    assert f(["*"]) == "open"
    assert f(["repo:my-org/*"]) == "org-wildcard"
    assert f(["repo:my-org/my-repo:*"]) == "branch-wildcard"
    assert f(["repo:my-org/my-repo:ref:refs/heads/main"]) == "concrete"
    # most-permissive wins across a list
    assert f(["repo:a/b:ref:refs/heads/main", "repo:a/*"]) == "org-wildcard"


def test_iampe_23_github_open_and_orgwildcard_fail():
    s = _fed_scanner()
    assert s._check_federated_trust(_role("gha", [_oidc(sub=None)])) is True    # aud only, no sub
    assert any(r.check_id == "IAMPE-23" and r.status == "FAIL" for r in s.results)
    s2 = _fed_scanner()
    s2._check_federated_trust(_role("gha2", [_oidc(sub="repo:my-org/*")]))
    assert any(r.check_id == "IAMPE-23" and r.status == "FAIL" for r in s2.results)


def test_iampe_23_concrete_sub_passes():
    s = _fed_scanner()
    assert s._check_federated_trust(
        _role("gha", [_oidc(sub="repo:my-org/my-repo:ref:refs/heads/main")])) is False
    assert not any(r.check_id == "IAMPE-23" for r in s.results)


def test_iampe_23_branch_wildcard_warns():
    s = _fed_scanner()
    s._check_federated_trust(_role("gha", [_oidc(sub="repo:my-org/my-repo:*")]))
    assert any(r.check_id == "IAMPE-23" and r.status == "WARN" for r in s.results)


def test_iampe_23_private_oidc_open_warns_not_critical():
    s = _fed_scanner()
    s._check_federated_trust(_role("eks", [_oidc(sub=None, host="oidc.eks.us-east-1.amazonaws.com/id/ABC")]))
    w = [r for r in s.results if r.check_id == "IAMPE-23"]
    assert w and all(r.status == "WARN" for r in w)   # private issuer -> WARN, never CRITICAL FAIL


def test_iampe_23_graph_edge_emitted():
    s = _fed_scanner()
    s._check_federated_trust(_role("gha", [_oidc(sub=None)]))
    st = s.graph.stats()
    assert "FederatedPrincipal" in st["node_kinds"] and "FEDERATED_CAN_ASSUME" in st["edge_kinds"]


def test_parse_trust_policy_carries_condition():
    doc = {"Statement": [{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::1:oidc-provider/x"},
                          "Action": "sts:AssumeRoleWithWebIdentity",
                          "Condition": {"StringEquals": {"x:sub": "repo:o/r"}}}]}
    stmts = A.parse_trust_policy(doc)
    assert stmts[0]["condition"] == {"StringEquals": {"x:sub": "repo:o/r"}}


def test_iampe_23_map_complete():
    assert A.CHECK_SEVERITY.get("IAMPE-23") == "CRITICAL" and "IAMPE-23" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("IAMPE-23", "").lower()


# ── LOG-07..10 — CloudTrail configuration depth ──────────────────────────────
from datetime import datetime as _dt2, timezone as _tz2, timedelta as _td2


def _ct_scanner(trails):
    s = make_scanner(["LOGGING"])
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": trails}
    ct.get_event_selectors.return_value = {"EventSelectors": [{"DataResources": []}]}
    ct.get_trail_status.return_value = {"IsLogging": True, "LatestDeliveryError": "",
                                        "LatestDeliveryTime": _dt2.now(_tz2.utc)}
    s._clients["cloudtrail:us-east-1"] = ct
    s3, s3c = MagicMock(), MagicMock()
    s3c.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
    s._clients["s3:us-east-1"] = s3
    s._clients["s3control:us-east-1"] = s3c
    return s, ct


def _trail(name="t1", arn=None, kms=None, bucket="log-bkt"):
    d = {"Name": name, "TrailARN": arn or f"arn:aws:cloudtrail:us-east-1:{OWN}:trail/{name}",
         "IsMultiRegionTrail": True, "S3BucketName": bucket}
    if kms:
        d["KmsKeyId"] = kms
    return d


def test_log_07_kms_pass_and_dedup_shadow_trails():
    t = _trail(kms="arn:aws:kms:us-east-1:1:key/k")
    s, ct = _ct_scanner([t, dict(t)])          # same TrailARN twice (region shadows)
    s._check_cloudtrail_config()
    l7 = [r for r in s.results if r.check_id == "LOG-07"]
    assert len(l7) == 1 and l7[0].status == "PASS"    # deduped to one finding


def test_log_07_no_kms_fails():
    s, ct = _ct_scanner([_trail(kms=None)])
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-07" and r.status == "FAIL" for r in s.results)


def test_log_08_data_events_pass_and_management_only_warn():
    s, ct = _ct_scanner([_trail()])
    ct.get_event_selectors.return_value = {"EventSelectors": [
        {"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::x/"]}]}]}
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-08" and r.status == "PASS" for r in s.results)
    s2, ct2 = _ct_scanner([_trail()])          # default: management-only
    s2._check_cloudtrail_config()
    assert any(r.check_id == "LOG-08" and r.status == "WARN" for r in s2.results)


def test_log_08_advanced_selectors_data_pass():
    s, ct = _ct_scanner([_trail()])
    ct.get_event_selectors.return_value = {"AdvancedEventSelectors": [
        {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}]}
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-08" and r.status == "PASS" for r in s.results)


def test_log_09_account_bpa_passes():
    s, ct = _ct_scanner([_trail()])
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-09" and r.status == "PASS" for r in s.results)


def test_log_09_public_bucket_policy_fails():
    s, ct = _ct_scanner([_trail()])
    s._clients["s3control:us-east-1"].get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}
    s3 = s._clients["s3:us-east-1"]
    s3.get_public_access_block.side_effect = RuntimeError("NoSuchPublicAccessBlockConfiguration")
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]})}
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-09" and r.status == "FAIL" for r in s.results)
    assert "EXPOSED_TO" in s.graph.stats()["edge_kinds"]


def test_log_09_accessdenied_is_info_not_fail():
    s, ct = _ct_scanner([_trail()])
    s._clients["s3control:us-east-1"].get_public_access_block.side_effect = RuntimeError("AccessDenied")
    s._clients["s3:us-east-1"].get_public_access_block.side_effect = RuntimeError("AccessDeniedException")
    s._check_cloudtrail_config()
    l9 = [r for r in s.results if r.check_id == "LOG-09"]
    assert l9 and all(r.status == "INFO" for r in l9)   # cross-account central bucket -> INFO


def test_log_10_delivery_error_fails_and_stale_warns():
    s, ct = _ct_scanner([_trail()])
    ct.get_trail_status.return_value = {"IsLogging": True,
        "LatestDeliveryError": "AccessDenied writing to bucket",
        "LatestDeliveryTime": _dt2.now(_tz2.utc)}
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-10" and r.status == "FAIL" for r in s.results)
    s2, ct2 = _ct_scanner([_trail()])
    ct2.get_trail_status.return_value = {"IsLogging": True, "LatestDeliveryError": "",
        "LatestDeliveryTime": _dt2.now(_tz2.utc) - _td2(days=3)}
    s2._check_cloudtrail_config()
    assert any(r.check_id == "LOG-10" and r.status == "WARN" for r in s2.results)


def test_log_10_not_logging_no_finding():
    s, ct = _ct_scanner([_trail()])
    ct.get_trail_status.return_value = {"IsLogging": False}   # LOG-01 owns the logging-off finding
    s._check_cloudtrail_config()
    assert not any(r.check_id == "LOG-10" for r in s.results)


def test_log_07_10_maps_complete():
    for cid in ("LOG-07", "LOG-08", "LOG-09", "LOG-10"):
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── COG-05 / COG-06 — Cognito identity pools (unauthenticated access) ─────────
def _ci_scanner(pools, describe=None, roles=None):
    s = make_scanner(["COGNITO_IDENTITY"])
    s.graph = aws_graph.SecurityGraph()
    ci = MagicMock()
    ci.list_identity_pools.return_value = {"IdentityPools": pools}
    describe = describe or {}
    ci.describe_identity_pool.side_effect = lambda IdentityPoolId: describe.get(
        IdentityPoolId, {"AllowUnauthenticatedIdentities": False})
    roles = roles or {}
    ci.get_identity_pool_roles.side_effect = lambda IdentityPoolId: {"Roles": roles.get(IdentityPoolId, {})}
    s._clients["cognito-identity:us-east-1"] = ci
    return s


def test_cog_05_unauth_pool_fails_with_internet_edge():
    role = f"arn:aws:iam::{OWN}:role/pool-unauth"
    s = _ci_scanner(
        [{"IdentityPoolId": "us-east-1:pool-open", "IdentityPoolName": "open"}],
        describe={"us-east-1:pool-open": {"AllowUnauthenticatedIdentities": True}},
        roles={"us-east-1:pool-open": {"unauthenticated": role, "authenticated": "arn:...:role/auth"}})
    s._check_cognito_identity()
    assert any(r.check_id == "COG-05" and r.status == "FAIL" and r.resource == "open" for r in s.results)
    st = s.graph.stats()
    assert "CAN_ASSUME" in st["edge_kinds"] and "InternetSource" in st["node_kinds"]


def test_cog_05_no_unauth_disabled_passes():
    s = _ci_scanner([{"IdentityPoolId": "us-east-1:p", "IdentityPoolName": "safe"}],
                    describe={"us-east-1:p": {"AllowUnauthenticatedIdentities": False}})
    s._check_cognito_identity()
    assert any(r.check_id == "COG-05" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "COG-05" and r.status == "FAIL" for r in s.results)


def test_cog_05_allow_unauth_but_no_role_warns():
    s = _ci_scanner([{"IdentityPoolId": "us-east-1:p", "IdentityPoolName": "latent"}],
                    describe={"us-east-1:p": {"AllowUnauthenticatedIdentities": True}},
                    roles={"us-east-1:p": {}})           # no 'unauthenticated' role
    s._check_cognito_identity()
    assert any(r.check_id == "COG-05" and r.status == "WARN" for r in s.results)


def test_cog_06_over_permissioned_unauth_role():
    role = f"arn:aws:iam::{OWN}:role/pool-unauth"
    s = _ci_scanner([{"IdentityPoolId": "us-east-1:p", "IdentityPoolName": "danger"}],
                    describe={"us-east-1:p": {"AllowUnauthenticatedIdentities": True}},
                    roles={"us-east-1:p": {"unauthenticated": role}})
    iam = MagicMock()
    iam.list_attached_role_policies.return_value = {"AttachedPolicies": [
        {"PolicyName": "AdministratorAccess",
         "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}]}
    s._clients["iam:us-east-1"] = iam
    s._check_cognito_identity()
    assert any(r.check_id == "COG-06" and r.status == "FAIL" for r in s.results)


def test_cog_05_no_pools_is_info():
    s = _ci_scanner([])
    s._check_cognito_identity()
    assert any(r.check_id == "COG-05" and r.status == "INFO" for r in s.results)


def test_cog_05_06_maps_complete():
    assert A.CHECK_SEVERITY.get("COG-05") == "HIGH" and A.CHECK_SEVERITY.get("COG-06") == "CRITICAL"
    for cid in ("COG-05", "COG-06"):
        assert cid in A.COMPLIANCE_MAP and "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ── R53-06 — dangling DNS / subdomain takeover ───────────────────────────────
def _r53_scanner(records, zones=None):
    s = make_scanner(["ROUTE53"])
    s.graph = aws_graph.SecurityGraph()
    r53 = MagicMock()
    zones = zones or [{"Id": "/hostedzone/Z1", "Name": "example.com.",
                       "Config": {"PrivateZone": False}}]

    def _pag(op):
        if op == "list_hosted_zones":
            return MockPaginator("HostedZones", zones)
        if op == "list_resource_record_sets":
            return MockPaginator("ResourceRecordSets", records)
        return MockPaginator("X", [])
    r53.get_paginator.side_effect = _pag
    s._clients["route53:us-east-1"] = r53
    return s


def _cname(name, value, rtype="CNAME"):
    return {"Name": name, "Type": rtype, "ResourceRecords": [{"Value": value}]}


def test_r53_06_s3_website_takeover_fail():
    s = _r53_scanner([_cname("app.example.com.",
                             "app.example.com.s3-website-us-east-1.amazonaws.com")])
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}
    s3.head_bucket.side_effect = RuntimeError("NoSuchBucket")
    s._clients["s3:us-east-1"] = s3
    s._check_dangling_dns()
    assert any(r.check_id == "R53-06" and r.status == "FAIL" and "app.example.com" in r.resource
               for r in s.results)
    assert "CAN_TAKEOVER" in s.graph.stats()["edge_kinds"]


def test_r53_06_s3_website_exists_no_finding():
    s = _r53_scanner([_cname("app.example.com.",
                             "app.example.com.s3-website-us-east-1.amazonaws.com")])
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "app.example.com"}]}
    s._clients["s3:us-east-1"] = s3
    s._check_dangling_dns()
    assert not any(r.check_id == "R53-06" and r.status == "FAIL" for r in s.results)
    assert any(r.check_id == "R53-06" and r.status == "PASS" for r in s.results)


def test_r53_06_beanstalk_terminated_fail():
    s = _r53_scanner([_cname("eb.example.com.", "my-env.us-west-2.elasticbeanstalk.com")])
    eb = MagicMock()
    eb.describe_environments.return_value = {"Environments": []}   # env gone
    s._clients["elasticbeanstalk:us-west-2"] = eb
    s._check_dangling_dns()
    assert any(r.check_id == "R53-06" and r.status == "FAIL" and "eb.example.com" in r.resource
               for r in s.results)


def test_r53_06_beanstalk_live_no_finding():
    s = _r53_scanner([_cname("eb.example.com.", "my-env.us-west-2.elasticbeanstalk.com")])
    eb = MagicMock()
    eb.describe_environments.return_value = {"Environments": [
        {"CNAME": "my-env.us-west-2.elasticbeanstalk.com", "Status": "Ready"}]}
    s._clients["elasticbeanstalk:us-west-2"] = eb
    s._check_dangling_dns()
    assert not any(r.check_id == "R53-06" and r.status == "FAIL" for r in s.results)


def test_r53_06_cloudfront_unverified_warns_not_fails():
    alias = {"Name": "cf.example.com.", "Type": "A",
             "AliasTarget": {"HostedZoneId": "Z2FDTNDATAQYW2",
                             "DNSName": "d123abc.cloudfront.net", "EvaluateTargetHealth": False}}
    s = _r53_scanner([alias])
    cf = MagicMock()
    cf.get_paginator.return_value = MockPaginator("DistributionList", {"Items": []})
    s._clients["cloudfront:us-east-1"] = cf
    s._check_dangling_dns()
    r6 = [r for r in s.results if r.check_id == "R53-06" and "cf.example.com" in r.resource]
    assert r6 and all(r.status == "WARN" for r in r6)   # cross-account/deleted -> WARN, never FAIL


def test_r53_06_private_zone_skipped():
    s = _r53_scanner([_cname("x.internal.", "x.s3-website-us-east-1.amazonaws.com")],
                     zones=[{"Id": "/hostedzone/Z1", "Name": "internal.",
                             "Config": {"PrivateZone": True}}])
    s._check_dangling_dns()
    assert any(r.check_id == "R53-06" and r.status == "INFO" for r in s.results)
    assert not any(r.check_id == "R53-06" and r.status == "FAIL" for r in s.results)


def test_r53_06_map_complete():
    assert A.CHECK_SEVERITY.get("R53-06") == "HIGH" and "R53-06" in A.COMPLIANCE_MAP
    assert "aws " in A.REMEDIATION_MAP.get("R53-06", "").lower()


# ── CW-01..16 — CloudWatch CIS §4 metric-filter + alarm coverage ─────────────
_UNAUTH_PATTERN = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'


def _cw_scanner(filter_specs, alarms=None, subs_confirmed=True):
    """filter_specs: list of (filterPattern, metricName, metricNamespace)."""
    s = make_scanner(["CLOUDWATCH"])
    lg_arn = f"arn:aws:logs:us-east-1:{OWN}:log-group:ct-logs:*"
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{
        "Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/t",
        "IsMultiRegionTrail": True, "CloudWatchLogsLogGroupArn": lg_arn}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    s._clients["cloudtrail:us-east-1"] = ct
    logs = MagicMock()
    logs.get_paginator.return_value = MockPaginator("metricFilters", [
        {"filterPattern": p, "metricTransformations": [{"metricName": m, "metricNamespace": ns}]}
        for p, m, ns in filter_specs])
    s._clients["logs:us-east-1"] = logs
    cw = MagicMock()
    cw.describe_alarms_for_metric.return_value = {"MetricAlarms": alarms if alarms is not None else [
        {"ActionsEnabled": True, "AlarmActions": [f"arn:aws:sns:us-east-1:{OWN}:sec-alarms"]}]}
    s._clients["cloudwatch:us-east-1"] = cw
    sns = MagicMock()
    sub = "arn:aws:sns:us-east-1:1:sec-alarms:s1" if subs_confirmed else "PendingConfirmation"
    sns.get_paginator.return_value = MockPaginator("Subscriptions", [{"SubscriptionArn": sub}])
    s._clients["sns:us-east-1"] = sns
    return s


def test_cw_norm_filter():
    assert A.AWSLiveScanner._norm_filter('( $.errorCode = "AccessDenied*" )') == "$.errorcode=accessdenied*"


def test_cw_01_gate_no_trail_single_fail_no_storm():
    s = make_scanner(["CLOUDWATCH"])
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": []}
    s._clients["cloudtrail:us-east-1"] = ct
    s._check_cloudwatch()
    assert len([r for r in s.results if r.check_id == "CW-01" and r.status == "FAIL"]) == 1
    # gate short-circuits -> no 15x per-control storm
    assert not any(r.check_id.startswith("CW-") and r.check_id != "CW-01" for r in s.results)


def test_cw_matched_control_passes_others_fail():
    s = _cw_scanner([(_UNAUTH_PATTERN, "UnauthorizedAPICalls", "CISBenchmark")])
    s._check_cloudwatch()
    assert any(r.check_id == "CW-01" and r.status == "PASS" for r in s.results)
    assert any(r.check_id == "CW-02" and r.status == "PASS" for r in s.results)   # CIS 4.1 covered
    assert any(r.check_id == "CW-03" and r.status == "FAIL" for r in s.results)   # 4.2 not present
    # exactly 15 per-control results (CW-02..CW-16)
    per = {r.check_id for r in s.results if r.check_id not in ("CW-01",) and r.check_id.startswith("CW-")}
    assert len(per) == 15


def test_cw_02_alarm_without_subscription_warns():
    s = _cw_scanner([(_UNAUTH_PATTERN, "UnauthorizedAPICalls", "CISBenchmark")], subs_confirmed=False)
    s._check_cloudwatch()
    assert any(r.check_id == "CW-02" and r.status == "WARN" for r in s.results)


def test_cw_02_filter_without_alarm_fails():
    s = _cw_scanner([(_UNAUTH_PATTERN, "UnauthorizedAPICalls", "CISBenchmark")], alarms=[])
    s._check_cloudwatch()
    assert any(r.check_id == "CW-02" and r.status == "FAIL" for r in s.results)


def test_cw_01_org_owned_loggroup_is_info():
    s = make_scanner(["CLOUDWATCH"])
    lg_arn = f"arn:aws:logs:us-east-1:{EXT}:log-group:ct-logs:*"   # another account
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{
        "Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/t",
        "IsMultiRegionTrail": True, "CloudWatchLogsLogGroupArn": lg_arn}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    s._clients["cloudtrail:us-east-1"] = ct
    s._check_cloudwatch()
    assert any(r.check_id == "CW-01" and r.status == "INFO" for r in s.results)
    assert not any(r.check_id == "CW-02" for r in s.results)   # per-control skipped


def test_cw_maps_complete():
    for n in range(1, 17):
        cid = f"CW-{n:02d}"
        assert cid in A.CHECK_SEVERITY and cid in A.COMPLIANCE_MAP
        assert "aws " in A.REMEDIATION_MAP.get(cid, "").lower()


# ══════════════════════════════════════════════════════════════════════════════
# Regressions for the adversarial-verify fixes (11 confirmed defects)
# ══════════════════════════════════════════════════════════════════════════════

# 1. classifier: a NEGATED account-scope condition must NOT be read as private
def test_classify_negated_condition_is_not_private():
    r = _c({"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*",
            "Condition": {"StringNotEquals": {"kms:CallerAccount": OWN}}})
    assert r is not None and r["kind"] in ("public", "public_conditioned")   # was falsely None


# 2. IAMPE-23: org/group-wide wildcard from a NON-GitHub public issuer => FAIL
def test_oidc_sub_scope_issuer_generic():
    f = A.AWSLiveScanner._oidc_sub_scope
    assert f(["project_path:mygroup/*"]) == "org-wildcard"                 # GitLab group-wide
    assert f(["project_path:mygroup/myproject:ref_type:branch:ref:main"]) == "concrete"


def test_iampe_23_gitlab_group_wildcard_fails():
    s = _fed_scanner()
    st = {"effect": "Allow", "aws": [], "service": [],
          "federated": [f"arn:aws:iam::{OWN}:oidc-provider/gitlab.com"],
          "actions": {"sts:assumerolewithwebidentity"}, "wildcard": False, "has_condition": True,
          "condition": {"StringLike": {"gitlab.com:sub": "project_path:mygroup/*"}}}
    s._check_federated_trust(_role("gl", [st]))
    assert any(r.check_id == "IAMPE-23" and r.status == "FAIL" for r in s.results)


# 3. LOG-09: a cross-account trail bucket must be INFO even when own-account BPA is full
def test_log_09_crossaccount_bucket_not_false_pass():
    s, ct = _ct_scanner([_trail()])                 # _ct_scanner sets account BPA fully on
    s._clients["s3:us-east-1"].get_public_access_block.side_effect = RuntimeError("AccessDenied")
    s._check_cloudtrail_config()
    l9 = [r for r in s.results if r.check_id == "LOG-09"]
    assert l9 and all(r.status == "INFO" for r in l9)          # not a false account-BPA PASS
    assert not any(r.check_id == "LOG-09" and r.status == "PASS" for r in s.results)


# 4. R53-06: apex S3-website ALIAS (bare regional endpoint) takeover is detected
def test_r53_06_s3_website_alias_apex_takeover():
    alias = {"Name": "example.com.", "Type": "A",
             "AliasTarget": {"HostedZoneId": "Z3AQBSTGFYJSTF",     # S3 website HZ != customer zid
                             "DNSName": "s3-website-us-east-1.amazonaws.com",
                             "EvaluateTargetHealth": False}}
    s = _r53_scanner([alias])
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": []}
    s3.head_bucket.side_effect = RuntimeError("NoSuchBucket")
    s._clients["s3:us-east-1"] = s3
    s._check_dangling_dns()
    assert any(r.check_id == "R53-06" and r.status == "FAIL" and "example.com" in r.resource
               for r in s.results)


# 5. CW-01: GetTrailStatus AccessDenied must not fabricate a FAIL / short-circuit CIS §4
def test_cw_01_trail_status_denied_still_evaluates():
    s = _cw_scanner([(_UNAUTH_PATTERN, "UnauthorizedAPICalls", "CISBenchmark")])
    s._clients["cloudtrail:us-east-1"].get_trail_status.side_effect = RuntimeError("AccessDeniedException")
    s._check_cloudwatch()
    assert any(r.check_id == "CW-01" and r.status == "PASS" for r in s.results)
    assert not any(r.check_id == "CW-01" and r.status == "FAIL" for r in s.results)


# 6. LOG-09: a public policy neutralized by full bucket BPA is WARN, not FAIL
def test_log_09_public_policy_but_bpa_full_warns():
    s, ct = _ct_scanner([_trail()])
    s._clients["s3control:us-east-1"].get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}      # account BPA not full
    s3 = s._clients["s3:us-east-1"]
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}         # bucket BPA full
    s3.get_bucket_policy.return_value = {"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]})}
    s._check_cloudtrail_config()
    assert any(r.check_id == "LOG-09" and r.status == "WARN" for r in s.results)
    assert not any(r.check_id == "LOG-09" and r.status == "FAIL" for r in s.results)


# 7. Sections run in canonical order regardless of --sections ordering
def test_sections_canonicalized_for_graph_deps():
    s = make_scanner(["CORRELATE", "COGNITO_IDENTITY", "IAMPRIVESC"])
    assert (s.sections.index("IAMPRIVESC") < s.sections.index("COGNITO_IDENTITY")
            < s.sections.index("CORRELATE"))


# 8. COG-06: a Condition-gated privesc edge is WARN, not a CRITICAL FAIL
def test_cog_06_conditioned_privesc_warns_not_critical():
    role = f"arn:aws:iam::{OWN}:role/pool-unauth"
    s = _ci_scanner([{"IdentityPoolId": "us-east-1:p", "IdentityPoolName": "cond"}],
                    describe={"us-east-1:p": {"AllowUnauthenticatedIdentities": True}},
                    roles={"us-east-1:p": {"unauthenticated": role}})
    s.graph.add_node(role, "IAMRole")
    s.graph.add_node("admin:x", "AdminCapability")
    s.graph.add_edge(role, "admin:x", "CAN_PRIVESC_TO", conditioned=True)   # gated
    s._check_cognito_identity()
    assert any(r.check_id == "COG-06" and r.status == "WARN" for r in s.results)
    assert not any(r.check_id == "COG-06" and r.status == "FAIL" for r in s.results)


# 9. R53-06: Route53 octal-escaped wildcard records (\052) are skipped, no mangled findings
def test_r53_06_wildcard_record_skipped():
    rec = _cname("\\052.example.com.", "\\052.example.com.s3-website-us-east-1.amazonaws.com")
    s = _r53_scanner([rec])
    s._check_dangling_dns()
    assert not any(r.check_id == "R53-06" and "052" in r.resource for r in s.results)


# 10/11. CW token matching is boundary-aware (peering-only != VPC changes)
def test_cw_15_peering_only_filter_does_not_pass():
    peering = "{ ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) }"
    s = _cw_scanner([(peering, "VpcPeering", "CIS")])
    s._check_cloudwatch()
    assert any(r.check_id == "CW-15" and r.status == "FAIL" for r in s.results)


def test_cw_15_proper_vpc_filter_passes():
    vpc = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) }"
    s = _cw_scanner([(vpc, "VpcChanges", "CIS")])
    s._check_cloudwatch()
    assert any(r.check_id == "CW-15" and r.status == "PASS" for r in s.results)
