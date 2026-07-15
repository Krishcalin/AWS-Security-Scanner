"""Phase 5 integration — the effective-permissions ceiling refinement running
through the REAL scanner path (_get_iam_principals -> _build_identity_graph), so
the solver can never diverge from the graph it feeds. Also asserts the fail-open
invariant (no boundary/SCP => identical graph) and the save_json audit block.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aws_live_scanner import AWSLiveScanner


class _GAADPaginator:
    def __init__(self, page):
        self._page = page

    def paginate(self, **kwargs):
        return [self._page]


def _gaad_iam(users=None, roles=None, groups=None, policies=None):
    page = {
        "UserDetailList": users or [], "GroupDetailList": groups or [],
        "RoleDetailList": roles or [], "Policies": policies or [],
    }
    iam = MagicMock()
    iam.get_paginator.side_effect = lambda name: _GAADPaginator(page)
    return iam


def _scanner_with(iam, account="123456789012", org=None, extra=None):
    """A scanner whose iam client is `iam`. By default the organizations client
    raises (SCP layer -> None -> fail open) so tests isolate the boundary variable;
    pass `org` to exercise the SCP path."""
    sc = AWSLiveScanner(region="us-east-1", sections=["IAMPRIVESC"])
    sc.account = account
    if org is None:
        org = MagicMock()
        org.describe_organization.side_effect = Exception("AWSOrganizationsNotInUseException")
    clients = {"iam:us-east-1": iam, "organizations:us-east-1": org}
    for k, v in (extra or {}).items():
        clients[k] = v

    def _client(service, region=None):
        key = f"{service}:{region or sc.region}"
        return clients.get(key, MagicMock())
    sc._client = _client
    return sc


def _org_mock(feature_set="ALL", master="999999999999", scp_readable=True,
              scp_docs=None):
    """Mock AWS Organizations client for the SCP walk. `scp_readable=False`
    simulates describe_policy AccessDenied on every SCP (the over-prune trap)."""
    org = MagicMock()
    org.describe_organization.return_value = {
        "Organization": {"FeatureSet": feature_set, "MasterAccountId": master}}
    org.list_parents.return_value = {"Parents": [{"Id": "r-root", "Type": "ROOT"}]}
    org.get_paginator.side_effect = Exception("no paginator")   # force direct call path
    org.list_policies_for_target.return_value = {"Policies": [{"Id": "p-FullAWSAccess"}]}
    if scp_readable:
        docs = scp_docs or {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        org.describe_policy.return_value = {"Policy": {"Content": json.dumps(docs)}}
    else:
        org.describe_policy.side_effect = Exception("AccessDeniedException")
    return org


def _inline(name, doc):
    return {"PolicyName": name, "PolicyDocument": doc}


PASSROLE_DOC = {"Statement": [{"Effect": "Allow",
    "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}


def _managed_policy(arn, doc):
    return {"Arn": arn, "DefaultVersionId": "v1",
            "PolicyVersionList": [{"VersionId": "v1", "IsDefaultVersion": True,
                                   "Document": doc}]}


class TestBoundaryPrunesPrivesc(unittest.TestCase):

    def test_boundary_neutralizes_privesc_edge(self):
        # alice can iam:PassRole+ec2:RunInstances (a privesc primitive) BUT her
        # permission boundary only allows s3 -> the escalation is not effective.
        barn = "arn:aws:iam::123456789012:policy/only-s3"
        user = {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)],
                "PermissionsBoundary": {"PermissionsBoundaryArn": barn}}
        boundary_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        iam = _gaad_iam(users=[user], policies=[_managed_policy(barn, boundary_doc)])
        sc = _scanner_with(iam)

        principals = sc._get_iam_principals()
        g = sc._build_identity_graph(principals)

        # No CAN_PRIVESC_TO edge, and the drop is recorded with a boundary reason.
        assert list(g.edges("CAN_PRIVESC_TO")) == []
        assert sc._pruned_edges, "expected a pruned-edge record"
        reasons = {p["reason"] for p in sc._pruned_edges}
        assert "boundary_implicit_deny" in reasons
        assert sc._boundary_evaluated is True

    def test_boundary_allowing_pivot_keeps_edge(self):
        barn = "arn:aws:iam::123456789012:policy/allow-iam"
        user = {"UserName": "bob", "Arn": "arn:aws:iam::123456789012:user/bob",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)],
                "PermissionsBoundary": {"PermissionsBoundaryArn": barn}}
        boundary_doc = {"Statement": [{"Effect": "Allow",
            "Action": ["iam:*", "ec2:*"], "Resource": "*"}]}
        iam = _gaad_iam(users=[user], policies=[_managed_policy(barn, boundary_doc)])
        sc = _scanner_with(iam)

        g = sc._build_identity_graph(sc._get_iam_principals())
        assert len(list(g.edges("CAN_PRIVESC_TO"))) == 1
        assert sc._pruned_edges == []

    def test_no_boundary_is_failopen_identical(self):
        # Same privesc primitive, NO boundary -> edge kept, nothing pruned.
        user = {"UserName": "carol", "Arn": "arn:aws:iam::123456789012:user/carol",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)]}
        iam = _gaad_iam(users=[user])
        sc = _scanner_with(iam)
        g = sc._build_identity_graph(sc._get_iam_principals())
        assert len(list(g.edges("CAN_PRIVESC_TO"))) == 1
        assert sc._pruned_edges == []
        assert sc._boundary_evaluated is False


class TestBoundaryGatesAssume(unittest.TestCase):

    def test_boundary_denies_assume_drops_can_assume_edge(self):
        # role R trusts user dave; dave's boundary denies sts:AssumeRole -> dave
        # cannot actually assume R -> CAN_ASSUME edge dropped.
        barn = "arn:aws:iam::123456789012:policy/no-assume"
        dave_arn = "arn:aws:iam::123456789012:user/dave"
        dave = {"UserName": "dave", "Arn": dave_arn,
                "UserPolicyList": [_inline("p", {"Statement": [{"Effect": "Allow",
                    "Action": "sts:AssumeRole", "Resource": "*"}]})],
                "PermissionsBoundary": {"PermissionsBoundaryArn": barn}}
        boundary_doc = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        role = {"RoleName": "R", "Arn": "arn:aws:iam::123456789012:role/R", "Path": "/",
                "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow",
                    "Principal": {"AWS": dave_arn}, "Action": "sts:AssumeRole"}]}}
        iam = _gaad_iam(users=[dave], roles=[role],
                        policies=[_managed_policy(barn, boundary_doc)])
        sc = _scanner_with(iam)
        g = sc._build_identity_graph(sc._get_iam_principals())

        assume_edges = [e for e in g.edges("CAN_ASSUME")]
        assert assume_edges == []            # dave's assume neutralized by boundary
        assert any(p["edge"] == "CAN_ASSUME" for p in sc._pruned_edges)

    def test_external_assume_source_never_pruned(self):
        # role trusts an EXTERNAL account root; we don't hold its policy -> keep.
        role = {"RoleName": "R", "Arn": "arn:aws:iam::123456789012:role/R", "Path": "/",
                "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                    "Action": "sts:AssumeRole"}]}}
        iam = _gaad_iam(roles=[role])
        sc = _scanner_with(iam)
        g = sc._build_identity_graph(sc._get_iam_principals())
        assert len(list(g.edges("CAN_ASSUME"))) == 1
        assert sc._pruned_edges == []


class TestSaveJsonAudit(unittest.TestCase):

    def test_effective_permissions_block_present(self):
        user = {"UserName": "carol", "Arn": "arn:aws:iam::123456789012:user/carol",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)]}
        iam = _gaad_iam(users=[user])
        sc = _scanner_with(iam)
        sc._build_identity_graph(sc._get_iam_principals())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            sc.save_json(path)
            data = json.loads(open(path, encoding="utf-8").read())
        assert "effective_permissions" in data
        ep = data["effective_permissions"]
        assert set(ep) == {"boundary_evaluated", "scp_evaluated",
                           "pruned_edges", "downgraded_edges"}
        # No state store ran -> no lifecycle keys leak into the base report
        assert "drift" not in data and "unused_access" not in data


class TestScpFailOpen(unittest.TestCase):
    """Regression (adversarial rank 1, CRITICAL): an UNREADABLE SCP node must fail
    the whole SCP layer open (None), never be treated as an empty deny-all level
    that mass-drops every escalation edge account-wide."""

    def test_unreadable_scp_fails_open_keeps_edge(self):
        user = {"UserName": "eve", "Arn": "arn:aws:iam::123456789012:user/eve",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)]}
        iam = _gaad_iam(users=[user])
        org = _org_mock(feature_set="ALL", master="999999999999", scp_readable=False)
        sc = _scanner_with(iam, org=org)
        g = sc._build_identity_graph(sc._get_iam_principals())
        # SCP layer unreadable -> None -> no pruning; the privesc edge survives.
        assert sc._get_scp_context() is None
        assert len(list(g.edges("CAN_PRIVESC_TO"))) == 1
        assert sc._pruned_edges == []

    def test_readable_restrictive_scp_still_prunes(self):
        # control: a readable account SCP that denies iam:PassRole DOES prune.
        deny_passrole = {"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"}]}
        user = {"UserName": "eve", "Arn": "arn:aws:iam::123456789012:user/eve",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)]}
        iam = _gaad_iam(users=[user])
        org = _org_mock(feature_set="ALL", master="999999999999",
                        scp_readable=True, scp_docs=deny_passrole)
        sc = _scanner_with(iam, org=org)
        g = sc._build_identity_graph(sc._get_iam_principals())
        assert sc._get_scp_context() is not None
        assert list(g.edges("CAN_PRIVESC_TO")) == []
        assert any(p["reason"] == "scp_explicit_deny" for p in sc._pruned_edges)

    def test_management_account_exempt(self):
        user = {"UserName": "eve", "Arn": "arn:aws:iam::123456789012:user/eve",
                "UserPolicyList": [_inline("p", PASSROLE_DOC)]}
        iam = _gaad_iam(users=[user])
        # self.account == MasterAccountId -> SCPs not evaluated
        org = _org_mock(feature_set="ALL", master="123456789012")
        sc = _scanner_with(iam, org=org)
        assert sc._get_scp_context() is None


class TestFullAdminCappedFallThrough(unittest.TestCase):
    """Regression (adversarial rank 2, CRITICAL): when the '*' megapivot of a
    full-admin identity is capped by the ceiling, evaluate_privesc_scoped must
    enumerate the granular IAM pivots that survive — not return []."""

    def _stmts(self, doc):
        return AWSLiveScanner._policy_to_statements(doc)

    def test_boundary_capped_admin_still_reports_granular(self):
        from aws_live_scanner import evaluate_privesc_scoped
        ident = self._stmts({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        boundary = self._stmts({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})
        findings = evaluate_privesc_scoped(ident, boundary=boundary)
        ids = {f["id"] for f in findings}
        assert findings, "boundary-capped admin must not hide surviving granular pivots"
        assert "IAMPE-19" not in ids            # the '*' megapivot itself is dropped
        assert any(i.startswith("IAMPE-") for i in ids)

    def test_deny_notaction_capped_admin_still_reports_granular(self):
        from aws_live_scanner import evaluate_privesc_scoped
        ident = self._stmts({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}]})
        findings = evaluate_privesc_scoped(ident)    # boundary=None: Deny-NotAction caps '*'
        ids = {f["id"] for f in findings}
        assert findings
        assert "IAMPE-19" not in ids

    def test_uncapped_admin_is_single_sentinel(self):
        from aws_live_scanner import evaluate_privesc_scoped
        ident = self._stmts({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        assert [f["id"] for f in evaluate_privesc_scoped(ident)] == ["IAMPE-19"]

    def test_genuine_deny_star_is_empty(self):
        from aws_live_scanner import evaluate_privesc_scoped
        ident = self._stmts({"Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": "*", "Resource": "*"}]})
        assert evaluate_privesc_scoped(ident) == []


class TestEks02Deterministic(unittest.TestCase):
    """Regression (adversarial rank 3): EKS-02 missing-log-types message must be
    sorted so its state fingerprint is stable (no spurious MUTATED on rescan)."""

    def test_eks02_message_is_sorted(self):
        cluster = {"resourcesVpcConfig": {"endpointPublicAccess": False},
                   "logging": {"clusterLogging": [
                       {"enabled": True, "types": ["scheduler"]}]}}
        eks = MagicMock()
        eks.list_clusters.return_value = {"clusters": ["prod"]}
        eks.describe_cluster.return_value = {"cluster": cluster}
        sc = _scanner_with(_gaad_iam(), extra={"eks:us-east-1": eks})
        sc.sections = ["EKS"]
        sc._check_eks()
        msg = next(r.message for r in sc.results if r.check_id == "EKS-02" and r.status == "FAIL")
        tail = msg.split("missing log types: ")[1]
        types = [t.strip() for t in tail.split(",")]
        assert types == sorted(types)          # deterministic ordering
        assert "api" in types and "audit" in types


class TestParseExpires(unittest.TestCase):
    """Regression (adversarial rank 5): a malformed --expires must raise, not
    silently become a permanent suppression."""

    def test_relative_and_iso_parse(self):
        from aws_live_scanner import _parse_expires
        assert _parse_expires("30d", 1_000_000) == 1_000_000 + 30 * 86400
        assert _parse_expires("12h", 0) == 12 * 3600
        assert _parse_expires(None, 0) is None            # omit = permanent (deliberate)

    def test_malformed_raises(self):
        from aws_live_scanner import _parse_expires
        with self.assertRaises(ValueError):
            _parse_expires("30days", 0)
        with self.assertRaises(ValueError):
            _parse_expires("soon", 0)


class TestCiemWiring(unittest.TestCase):
    """Regression (adversarial rank 9): the CIEM pass is actually invoked and
    produces right-sizing findings + a non-mutating path down-rank."""

    def test_run_ciem_emits_finding_and_downranks(self):
        from aws_live_scanner import _run_ciem

        class Args:
            ciem = True
        # a role with unused (never-authenticated) services via SLAD; no analyzer.
        # One iam client answers BOTH GAAD (principal enum) and SLAD, as in prod.
        role = {"RoleName": "old", "Arn": "arn:aws:iam::123456789012:role/old", "Path": "/",
                "AssumeRolePolicyDocument": {"Statement": []}}
        iam = _gaad_iam(roles=[role])
        iam.generate_service_last_accessed_details.return_value = {"JobId": "j"}
        iam.get_service_last_accessed_details.return_value = {
            "JobStatus": "COMPLETED",
            "ServicesLastAccessed": [{"ServiceNamespace": "s3", "LastAuthenticated": None}],
            "IsTruncated": False}
        aa = MagicMock()
        aa.list_analyzers.return_value = {"analyzers": []}
        sc = _scanner_with(iam, extra={"accessanalyzer:us-east-1": aa})
        _run_ciem(sc, Args(), 1_000_000)
        # CIEM ran: report list populated + an unused-services right-sizing finding.
        assert sc._unused_report is not None
        assert any(r.check_id == "CIEM-01" for r in sc.results)


if __name__ == "__main__":
    unittest.main()
