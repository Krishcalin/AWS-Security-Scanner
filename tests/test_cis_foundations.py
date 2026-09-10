"""Driving tests for the 19 CIS AWS Foundations Benchmark v7.0.0 checks.

WHY THIS FILE HAS TO EXIST. `docs/CHECK_FIRING.md` exists because this codebase has
repeatedly shipped checks that were registered in all five projections, counted in the
published total, and could not fire. Nineteen new checks in one commit is the single most
likely way to do that again, so every one of them is driven here to an actual FAIL through
`AWSLiveScanner` rather than through its evaluator.

THE ORGANIZATIONS SECTION NEEDS A THIRD KIND OF TEST, and it is the one that matters most
for this batch. Six of these checks read APIs that only the management account may call,
so their normal outcome in a member account is neither a pass nor a failure. A section
that answered a denial with silence would report an organisation nobody could inspect as
an organisation with nothing wrong with it — so there is a case per check proving the
denial produces an INFO that names the action, and proving it produces no PASS.

THE NEGATIVE CASES ARE NOT DECORATION. A check that fires unconditionally is worse than no
check, because it trains people to filter the id out. Each control has at least one case
proving the compliant configuration is silent.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_foundations as F                          # noqa: E402
from engine import aws_cis_foundations_map as M                      # noqa: E402
# MockClientError, not botocore's: `ClientError` is bound in aws_live_scanner only when
# boto3 imported, and `_is_access_denied` reads the code off the exception for exactly
# that reason. A fixture raising the real type would test a path production never takes.
from test_live_scanner import MockClientError, make_scanner          # noqa: E402

OWN = "123456789012"
OTHER = "999988887777"
DENIED = MockClientError("AccessDeniedException", "not authorized")


# ── shared helpers ───────────────────────────────────────────────────────────────
def _ids(s, cid, status=None):
    return [r for r in s.results
            if r.check_id == cid and (status is None or r.status == status)]


def _renders(s, cid, contains=None):
    """The finding fired AND carries what the catalogue holds for it.

    `_add` reads severity, compliance and remediation from the catalogue for a FAIL and
    for no other status, so "the check fired" and "the finding renders what the catalogue
    promises" are different claims. Only the second is worth anything to an operator.
    """
    from engine.aws_live_scanner import CHECK_SEVERITY
    hits = _ids(s, cid, "FAIL")
    assert hits, f"{cid} did not FAIL"
    r = hits[0]
    assert r.severity == CHECK_SEVERITY[cid], (
        f"{cid} rendered {r.severity!r}, catalogue says {CHECK_SEVERITY[cid]!r}")
    assert r.remediation_cmd, f"{cid} FAIL carries no remediation command"
    assert r.compliance.get("CIS"), f"{cid} FAIL carries no Foundations citation"
    assert r.compliance["CIS"] == M.recommendation_for(cid), (
        f"{cid} cites {r.compliance['CIS']}, the mapping says "
        f"{M.recommendation_for(cid)}")
    if contains:
        assert contains in r.message, f"{cid} message lacks {contains!r}: {r.message}"
    return r


def _not_evaluated(s, cid, contains=""):
    """A read that did not happen renders as INFO, never as PASS."""
    infos = _ids(s, cid, "INFO")
    assert infos, f"{cid} emitted no coverage statement"
    assert not _ids(s, cid, "PASS"), f"{cid} reported a PASS it could not have earned"
    assert not _ids(s, cid, "FAIL"), f"{cid} FAILed on a read it could not make"
    assert "NOT EVALUATED" in infos[0].message, infos[0].message
    if contains:
        assert contains in infos[0].message, infos[0].message
    return infos[0]


class _Pager:
    def __init__(self, key, items):
        self._key, self._items = key, items

    def paginate(self, **kw):
        return [{self._key: self._items}]


def _pagers(**by_method):
    """get_paginator side-effect: method name -> (key, items) or an Exception."""
    def _get(method):
        if method not in by_method:
            return _Pager("Unused", [])
        spec = by_method[method]
        if isinstance(spec, Exception):
            raise spec
        return _Pager(*spec)
    return _get


# ═════════════════════════════════════════════════════════════════════════════════
# 2.1 Organizations — ORG-01..06
# ═════════════════════════════════════════════════════════════════════════════════
def _org_scanner(*, org=None, iam=None, account=None, region_clients=None):
    s = make_scanner(sections=["ORGANIZATIONS"])
    s.account = OWN
    s._clients["organizations:us-east-1"] = org if org is not None else MagicMock()
    s._clients["iam:us-east-1"] = iam if iam is not None else MagicMock()
    s._clients["account:us-east-1"] = account if account is not None else MagicMock()
    for k, v in (region_clients or {}).items():
        s._clients[f"{k}:us-east-1"] = v
    return s


def _quiet_account():
    """An `account` client that answers both contact reads compliantly."""
    a = MagicMock()
    a.get_contact_information.return_value = {"ContactInformation": {
        "FullName": "Ops", "AddressLine1": "1 St", "City": "Town",
        "PostalCode": "AB1", "CountryCode": "GB", "PhoneNumber": "+44"}}
    a.get_alternate_contact.return_value = {
        "AlternateContact": {"EmailAddress": "sec@example.test"}}
    return a


def _org_client(*, master=OTHER, features=None, accounts=(), policies_for=None,
                roots=(), root_accounts=(), ous=(), delegated=(),
                resource_policy=None, trusted=(), delegated_services=()):
    org = MagicMock()
    org.describe_organization.return_value = {
        "Organization": {"Id": "o-1", "MasterAccountId": master}}
    org.list_parents.return_value = {"Parents": [{"Id": "ou-1", "Type": "ORGANIZATIONAL_UNIT"}]}
    if resource_policy is None:
        org.describe_resource_policy.side_effect = MockClientError(
            "ResourcePolicyNotFoundException", "none")
    else:
        org.describe_resource_policy.return_value = {
            "ResourcePolicy": {"Content": resource_policy}}

    pols = policies_for if policies_for is not None else {}

    def get_paginator(method):
        if method == "list_accounts":
            return _Pager("Accounts", [{"Id": a, "Status": "ACTIVE"} for a in accounts])
        if method == "list_policies_for_target":
            class P:
                def paginate(self, TargetId=None, Filter=None, **kw):
                    if Filter != "SERVICE_CONTROL_POLICY":
                        raise MockClientError("PolicyTypeNotEnabledException", "off")
                    return [{"Policies": [{"Id": p} for p in pols.get(TargetId, [])]}]
            return P()
        if method == "list_roots":
            return _Pager("Roots", [{"Id": r} for r in roots])
        if method == "list_accounts_for_parent":
            return _Pager("Accounts", [{"Id": a} for a in root_accounts])
        if method == "list_organizational_units_for_parent":
            return _Pager("OrganizationalUnits", [{"Id": o} for o in ous])
        if method == "list_delegated_administrators":
            return _Pager("DelegatedAdministrators", [{"Id": d} for d in delegated])
        if method == "list_aws_service_access_for_organization":
            return _Pager("EnabledServicePrincipals",
                          [{"ServicePrincipal": t} for t in trusted])
        if method == "list_delegated_services_for_account":
            return _Pager("DelegatedServices",
                          [{"ServicePrincipal": t} for t in delegated_services])
        return _Pager("Unused", [])

    org.get_paginator.side_effect = get_paginator
    return org


def test_org01_fails_when_root_credentials_are_not_centrally_managed():
    iam = MagicMock()
    iam.list_organizations_features.return_value = {"EnabledFeatures": []}
    s = _org_scanner(org=_org_client(), iam=iam, account=_quiet_account())
    s._check_organizations()
    _renders(s, "ORG-01", contains="standing credential")


def test_org01_passes_when_both_features_are_enabled():
    iam = MagicMock()
    iam.list_organizations_features.return_value = {
        "EnabledFeatures": ["RootCredentialsManagement", "RootSessions"]}
    s = _org_scanner(org=_org_client(), iam=iam, account=_quiet_account())
    s._check_organizations()
    assert _ids(s, "ORG-01", "PASS")
    assert not _ids(s, "ORG-01", "FAIL")


def test_org01_distinguishes_sessions_only_from_nothing_at_all():
    """Enabling root SESSIONS without root CREDENTIALS MANAGEMENT leaves every member
    root credential exactly where it was. Reporting the two states identically would tell
    an operator who did half the work that they had done none of it."""
    r = F.central_root_access(["RootCredentialsManagement"])
    assert r["failed"] and "privileged root sessions" in r["statement"]
    r2 = F.central_root_access([])
    assert r2["failed"] and "standing credential" in r2["statement"]
    assert r["statement"] != r2["statement"]


def test_org02_fails_only_when_the_default_policy_is_all_there_is():
    """THE TRAP THIS CONTROL EXISTS FOR. Organizations attaches FullAWSAccess to every
    target and refuses to let the last policy be detached, so 'an SCP is attached' is true
    of every account that exists and measures nothing."""
    org = _org_client(accounts=[OWN, OTHER],
                      policies_for={OWN: ["p-FullAWSAccess"],
                                    "ou-1": ["p-FullAWSAccess"],
                                    OTHER: ["p-FullAWSAccess", "p-baseline"]})
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    r = _renders(s, "ORG-02", contains="FullAWSAccess")
    assert r.resource == OWN, r.resource
    assert not [x for x in _ids(s, "ORG-02", "FAIL") if x.resource == OTHER]


def test_org02_counts_a_policy_inherited_from_an_ou():
    """An account with no policy of its own is properly governed when its OU has one.
    Reading only the account would report every well-structured organisation as bare."""
    org = _org_client(accounts=[OWN],
                      policies_for={OWN: ["p-FullAWSAccess"],
                                    "ou-1": ["p-FullAWSAccess", "p-baseline"]})
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    assert not _ids(s, "ORG-02", "FAIL")
    assert _ids(s, "ORG-02", "PASS")


def test_org03_fails_only_inside_the_management_account():
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_instances=("Reservations", [{"Instances": [{"InstanceId": "i-1"}]}]))
    s = _org_scanner(org=_org_client(master=OWN), account=_quiet_account(),
                     region_clients={"ec2": ec2})
    s._check_organizations()
    _renders(s, "ORG-03", contains="1 EC2 instance(s)")


def test_org03_says_it_could_not_look_from_a_member_account():
    """The finding is undecidable from a member account, and saying so is the point: a
    PASS here would be evidence nobody gathered."""
    s = _org_scanner(org=_org_client(master=OTHER), account=_quiet_account())
    s._check_organizations()
    _not_evaluated(s, "ORG-03", "member account")


def test_org04_fails_for_accounts_parented_to_the_root():
    org = _org_client(roots=["r-1"], root_accounts=[OWN], ous=["ou-1", "ou-2"])
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    r = _renders(s, "ORG-04", contains="directly under the organisation root")
    assert "2 OU(s)" in r.message


def test_org04_does_not_grade_the_names_of_the_ous():
    """2.1.4 asks that OUs reflect environment and sensitivity. This decides only the
    readable half; a check that scored OU names would be scoring a naming convention."""
    org = _org_client(roots=["r-1"], root_accounts=[], ous=["ou-whatever"])
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    assert not _ids(s, "ORG-04", "FAIL")
    assert M.verdict_for("2.1.4") == M.NARROWED


def test_org05_fails_when_no_resource_policy_delegates_administration():
    s = _org_scanner(org=_org_client(), account=_quiet_account())
    s._check_organizations()
    _renders(s, "ORG-05", contains="management account")


def test_org05_passes_when_a_delegation_policy_exists():
    s = _org_scanner(org=_org_client(resource_policy='{"Statement":[]}'),
                     account=_quiet_account())
    s._check_organizations()
    assert _ids(s, "ORG-05", "PASS")
    assert not _ids(s, "ORG-05", "FAIL")


def test_org06_names_the_undelegated_services():
    org = _org_client(trusted=["cloudtrail.amazonaws.com", "guardduty.amazonaws.com"],
                      delegated=["111122223333"],
                      delegated_services=["guardduty.amazonaws.com"])
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    r = _renders(s, "ORG-06", contains="cloudtrail.amazonaws.com")
    assert "guardduty" not in r.message, (
        "a delegated service must not be reported as undelegated")


def test_the_whole_organizations_block_degrades_to_coverage_in_a_member_account():
    """THE CASE THAT MATTERS MOST FOR THIS SECTION. A member account is refused
    DescribeOrganization, and all six checks must then say so rather than pass."""
    org = MagicMock()
    org.describe_organization.side_effect = DENIED
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    for cid in ("ORG-01", "ORG-02", "ORG-03", "ORG-04", "ORG-05", "ORG-06"):
        _not_evaluated(s, cid, "denied")
    # The coverage ledger is the other half: the evidence pack's denominator has to
    # shrink, or the report claims a completeness the scan never had.
    assert set(s._coverage.not_evaluated) >= {
        "ORG-01", "ORG-02", "ORG-03", "ORG-04", "ORG-05", "ORG-06"}, (
        s._coverage.not_evaluated)
    assert "organizations:DescribeOrganization" in s._coverage.missing_actions


def test_a_standalone_account_is_told_it_has_no_organisation():
    """Not in an organisation is not non-compliance; it is a different shape of estate."""
    org = MagicMock()
    org.describe_organization.side_effect = MockClientError(
        "AWSOrganizationsNotInUseException", "no org")
    s = _org_scanner(org=org, account=_quiet_account())
    s._check_organizations()
    info = _not_evaluated(s, "ORG-02", "not a member of an AWS Organization")
    assert "denied" not in info.message


# ═════════════════════════════════════════════════════════════════════════════════
# 2.2 / 2.3 — account contacts
# ═════════════════════════════════════════════════════════════════════════════════
def test_acct01_fails_on_an_incomplete_contact_record():
    a = _quiet_account()
    a.get_contact_information.return_value = {"ContactInformation": {
        "FullName": "Ops", "AddressLine1": "", "City": "Town",
        "PostalCode": "AB1", "CountryCode": "GB", "PhoneNumber": ""}}
    s = _org_scanner(org=_org_client(), account=a)
    s._check_organizations()
    _renders(s, "ACCT-01", contains="AddressLine1")


def test_acct01_does_not_claim_the_details_are_current():
    """The API cannot say whether a number still reaches anyone, so the finding says which
    half it checked. Claiming currency would be answering an easier question than asked."""
    r = F.contact_details({"FullName": "x"})
    assert "CURRENT is not readable" in r["statement"]


def test_acct02_fails_when_no_security_contact_is_registered():
    a = _quiet_account()
    a.get_alternate_contact.side_effect = MockClientError(
        "ResourceNotFoundException", "no alternate contact")
    s = _org_scanner(org=_org_client(), account=a)
    s._check_organizations()
    _renders(s, "ACCT-02", contains="SECURITY alternate contact")


def test_acct02_tells_not_set_apart_from_not_permitted():
    """The AWS API raises ResourceNotFound for 'not set', which is the finding, and
    AccessDenied for 'not permitted', which is not. Conflating them would report an
    unreadable account as non-compliant."""
    a = _quiet_account()
    a.get_alternate_contact.side_effect = DENIED
    s = _org_scanner(org=_org_client(), account=a)
    s._check_organizations()
    _not_evaluated(s, "ACCT-02", "denied")


# ═════════════════════════════════════════════════════════════════════════════════
# IAM — IAM-11..15
# ═════════════════════════════════════════════════════════════════════════════════
def _iam_scanner(report, iam=None):
    s = make_scanner(sections=["IAM"])
    s.account = OWN
    s._cred_report = report
    s._clients["iam:us-east-1"] = iam if iam is not None else MagicMock()
    return s


def _report(**over):
    row = {"user": "alice", "password_enabled": "false", "mfa_active": "true"}
    row.update(over)
    return row


def _iam_client(*, virtual_root=True, attached=(), inline=(),
                support=(), cloudshell=(), saml=(), oidc=()):
    iam = MagicMock()
    devices = ([{"SerialNumber": f"arn:aws:iam::{OWN}:mfa/root-account-mfa-device",
                 "User": {"Arn": f"arn:aws:iam::{OWN}:root"}}] if virtual_root else [])

    def get_paginator(method):
        if method == "list_virtual_mfa_devices":
            return _Pager("VirtualMFADevices", devices)
        if method == "list_entities_for_policy":
            class P:
                def paginate(self, PolicyArn="", **kw):
                    which = support if "Support" in PolicyArn else cloudshell
                    return [{"PolicyRoles": [{"RoleName": n} for n in which],
                             "PolicyUsers": [], "PolicyGroups": []}]
            return P()
        return _Pager("Unused", [])

    iam.get_paginator.side_effect = get_paginator
    iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{"PolicyName": p} for p in attached]}
    iam.list_user_policies.return_value = {"PolicyNames": list(inline)}
    iam.list_saml_providers.return_value = {"SAMLProviderList": list(saml)}
    iam.list_open_id_connect_providers.return_value = {
        "OpenIDConnectProviderList": list(oidc)}
    return iam


def test_iam11_fails_when_root_mfa_is_virtual():
    s = _iam_scanner([_report(user="<root_account>", mfa_active="true")],
                     _iam_client(virtual_root=True))
    s._check_iam_foundations()
    _renders(s, "IAM-11", contains="virtual device")


def test_iam11_passes_when_root_mfa_is_hardware():
    """A root user with MFA that appears in NO virtual-device listing is holding a
    hardware token — the absence IS the evidence."""
    s = _iam_scanner([_report(user="<root_account>", mfa_active="true")],
                     _iam_client(virtual_root=False))
    s._check_iam_foundations()
    assert _ids(s, "IAM-11", "PASS")
    assert not _ids(s, "IAM-11", "FAIL")


def test_iam11_stays_silent_when_root_has_no_mfa_at_all():
    """IAM-01 owns that finding and rates it CRITICAL. Reporting it again here as a
    MEDIUM would count one problem twice and understate it the second time."""
    s = _iam_scanner([_report(user="<root_account>", mfa_active="false")],
                     _iam_client())
    s._check_iam_foundations()
    _not_evaluated(s, "IAM-11", "IAM-01")


def test_iam12_fails_on_a_directly_attached_policy():
    s = _iam_scanner([_report(user="alice")],
                     _iam_client(attached=["AdministratorAccess"]))
    s._check_iam_foundations()
    _renders(s, "IAM-12", contains="AdministratorAccess")


def test_iam12_finds_inline_policies_too():
    """An inline policy has no ARN, so an inventory built from policy ARNs cannot see it.
    That is the half a permissions audit most often misses."""
    r = F.user_attached_policies("bob", [], ["adhoc-grant"])
    assert r["failed"] and "adhoc-grant" in r["statement"]


def test_iam12_passes_when_permissions_come_only_from_groups():
    s = _iam_scanner([_report(user="alice")], _iam_client())
    s._check_iam_foundations()
    assert not _ids(s, "IAM-12", "FAIL")
    assert _ids(s, "IAM-12", "PASS")


def test_iam13_fails_when_nothing_holds_the_support_policy():
    s = _iam_scanner([_report()], _iam_client(support=()))
    s._check_iam_foundations()
    _renders(s, "IAM-13", contains="support case")


def test_iam13_passes_when_a_role_holds_it():
    s = _iam_scanner([_report()], _iam_client(support=("SupportRole",)))
    s._check_iam_foundations()
    assert _ids(s, "IAM-13", "PASS")


def test_iam14_fails_for_console_users_and_names_the_identity_source():
    s = _iam_scanner([_report(user="alice", password_enabled="true")],
                     _iam_client(saml=[{"Arn": "arn:aws:iam::1:saml-provider/corp"}]))
    s._check_iam_foundations()
    r = _renders(s, "IAM-14", contains="alice")
    assert "parallel path" in r.message


def test_iam14_ignores_service_users_with_no_console_password():
    """An IAM user without a password is a service account, not a person bypassing
    federation. Failing it would push an operator toward a migration that improves
    nothing and breaks a running integration."""
    s = _iam_scanner([_report(user="ci-bot", password_enabled="false")], _iam_client())
    s._check_iam_foundations()
    assert not _ids(s, "IAM-14", "FAIL")


def test_iam15_fails_when_cloudshell_full_access_is_attached():
    s = _iam_scanner([_report()], _iam_client(cloudshell=("DevRole",)))
    s._check_iam_foundations()
    _renders(s, "IAM-15", contains="DevRole")


def test_iam15_passes_when_nothing_holds_it():
    s = _iam_scanner([_report()], _iam_client(cloudshell=()))
    s._check_iam_foundations()
    assert _ids(s, "IAM-15", "PASS")


def test_the_managed_policy_arn_follows_the_partition():
    """Hard-coding arn:aws: would make IAM-13 unable to fire in China or GovCloud: the
    read would raise NoSuchEntity, be read as 'nothing holds it', and the check would
    report the support role ABSENT in every account in those partitions."""
    s = make_scanner(sections=["IAM"])
    s.region = "cn-north-1"
    assert s._iam_partition() == "aws-cn"
    s.region = "us-gov-west-1"
    assert s._iam_partition() == "aws-us-gov"
    s.region = "eu-west-2"
    assert s._iam_partition() == "aws"


# ═════════════════════════════════════════════════════════════════════════════════
# EC2-18, S3-11, LOG-11, LOG-12, VPC-07, VPC-08
# ═════════════════════════════════════════════════════════════════════════════════
def test_ec2_18_fails_on_a_running_instance_with_no_instance_profile():
    r = F.instance_without_role({"InstanceId": "i-1"})
    assert r["failed"] and "no IAM instance profile" in r["statement"]


def test_ec2_18_passes_when_a_profile_is_attached():
    r = F.instance_without_role(
        {"InstanceId": "i-1", "IamInstanceProfile": {"Arn": "arn:aws:iam::1:i/p"}})
    assert not r["failed"]


def test_ec2_18_fires_through_the_scanner():
    s = make_scanner(sections=["EC2"])
    s.account = OWN
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_instances=("Reservations", [{"Instances": [
            {"InstanceId": "i-1", "State": {"Name": "running"},
             "LaunchTime": None, "Monitoring": {"State": "detailed"},
             "SecurityGroups": [], "BlockDeviceMappings": []}]}]),
        describe_security_groups=("SecurityGroups", []),
        describe_network_interfaces=("NetworkInterfaces", []))
    s._clients["ec2:us-east-1"] = ec2
    s._check_ec2_hygiene()
    _renders(s, "EC2-18", contains="no IAM instance profile")


def test_s3_11_distinguishes_unversioned_from_versioned_without_mfa_delete():
    """On an unversioned bucket MFA Delete cannot be set at all, so 'enable MFA Delete'
    is not actionable advice — the finding has to say 'enable versioning first'."""
    unver = F.bucket_mfa_delete("b", {"Status": "Suspended"})
    ver = F.bucket_mfa_delete("b", {"Status": "Enabled"})
    assert unver["failed"] and unver["versioning"] is False
    assert "enable versioning first" in unver["statement"]
    assert ver["failed"] and ver["versioning"] is True
    assert "s3:DeleteObjectVersion" in ver["statement"]
    assert not F.bucket_mfa_delete("b", {"Status": "Enabled",
                                         "MFADelete": "Enabled"})["failed"]


def test_s3_11_fires_through_the_scanner():
    s = make_scanner(sections=["S3"])
    s.account = OWN
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "b"}]}
    s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
    s3.get_bucket_location.return_value = {"LocationConstraint": None}
    s3.get_public_access_block.side_effect = MockClientError("NoSuchBucket", "x")
    s3.get_bucket_policy.side_effect = MockClientError("NoSuchBucketPolicy", "x")
    s._clients["s3:us-east-1"] = s3
    s._check_s3()
    _renders(s, "S3-11", contains="MFA Delete")


def test_log_11_fails_when_log_file_validation_is_off():
    assert F.trail_log_validation({"Name": "t"})["failed"]
    assert not F.trail_log_validation(
        {"Name": "t", "LogFileValidationEnabled": True})["failed"]


def test_log_12_is_scoped_to_the_trails_own_bucket():
    """S3-05 asks the same question of every bucket and only WARNs. This one fails,
    because this is the bucket whose readers are worth recording."""
    r = F.trail_bucket_access_logging("t", "trail-bucket", {})
    assert r["failed"] and "trail-bucket" in r["statement"]
    ok = F.trail_bucket_access_logging(
        "t", "trail-bucket", {"LoggingEnabled": {"TargetBucket": "logs"}})
    assert not ok["failed"]
    assert F.trail_bucket_access_logging("t", None, {})["unknown"]


def test_log_11_and_12_fire_through_the_scanner():
    s = make_scanner(sections=["LOGGING"])
    s.account = OWN
    ct = MagicMock()
    ct.describe_trails.return_value = {"trailList": [{
        "Name": "t", "TrailARN": "arn:aws:cloudtrail:us-east-1:1:trail/t",
        "IsMultiRegionTrail": True, "S3BucketName": "trail-bucket",
        "LogFileValidationEnabled": False, "HomeRegion": "us-east-1"}]}
    ct.get_trail_status.return_value = {"IsLogging": True}
    ct.get_event_selectors.return_value = {"EventSelectors": []}
    s._clients["cloudtrail:us-east-1"] = ct
    s3 = MagicMock()
    s3.get_bucket_logging.return_value = {}
    s3.get_public_access_block.side_effect = MockClientError("NoSuchBucket", "x")
    s3.get_bucket_policy.side_effect = MockClientError("NoSuchBucketPolicy", "x")
    s3.get_bucket_acl.return_value = {"Grants": []}
    s._clients["s3:us-east-1"] = s3
    s._check_cloudtrail_config()
    _renders(s, "LOG-11", contains="signed digest")
    _renders(s, "LOG-12", contains="server access logging")


def test_vpc_07_fails_on_a_whole_vpc_peering_route():
    wide = {"RouteTableId": "rtb-1", "Routes": [
        {"DestinationCidrBlock": "10.0.0.0/16", "VpcPeeringConnectionId": "pcx-1",
         "State": "active"}]}
    narrow = {"RouteTableId": "rtb-2", "Routes": [
        {"DestinationCidrBlock": "10.0.3.0/24", "VpcPeeringConnectionId": "pcx-1",
         "State": "active"}]}
    assert F.peering_route_scope(wide)["failed"]
    assert not F.peering_route_scope(narrow)["failed"]
    # a route that is not a peering route is none of this check's business
    igw = {"RouteTableId": "rtb-3", "Routes": [
        {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}
    assert not F.peering_route_scope(igw)["failed"]


def test_vpc_08_needs_both_no_endpoints_and_a_path_to_the_internet():
    """An isolated VPC is not reaching AWS over the public network whatever its endpoint
    list says. Failing it would put an unfixable finding on every private VPC."""
    assert F.vpc_endpoint_usage("vpc-1", 0, True)["failed"]
    assert not F.vpc_endpoint_usage("vpc-1", 0, False)["failed"]
    assert not F.vpc_endpoint_usage("vpc-1", 3, True)["failed"]


def test_vpc_07_and_08_fire_through_the_scanner():
    s = make_scanner(sections=["VPC"])
    s.account = OWN
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = _pagers(
        describe_route_tables=("RouteTables", [{
            "RouteTableId": "rtb-1", "VpcId": "vpc-1", "Routes": [
                {"DestinationCidrBlock": "10.0.0.0/16",
                 "VpcPeeringConnectionId": "pcx-1", "State": "active"},
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"}]}]),
        describe_vpc_endpoints=("VpcEndpoints", []),
        describe_vpcs=("Vpcs", [{"VpcId": "vpc-1"}]))
    s._clients["ec2:us-east-1"] = ec2
    s._check_vpc_foundations(ec2, [{"VpcPeeringConnectionId": "pcx-1",
                                    "AccepterVpcInfo": {"CidrBlock": "10.0.0.0/16"}}])
    _renders(s, "VPC-07", contains="whole-VPC prefixes")
    _renders(s, "VPC-08", contains="no VPC endpoints")


# ═════════════════════════════════════════════════════════════════════════════════
# the batch as a whole
# ═════════════════════════════════════════════════════════════════════════════════
def test_the_organizations_section_runs_once_per_scan_not_once_per_region():
    """Found by probing the dispatch rather than by a unit test, which is the point.

    Every client this section builds is pinned to us-east-1 — Organizations and the
    account contact APIs have no regional endpoints. Left out of GLOBAL_SECTIONS,
    `--all-regions` would re-run the identical us-east-1 reads once per enabled region
    and emit every ORG-* and ACCT-* finding N times. The worst case is the coverage
    statement, not the finding: a member account would report the same denial thirty
    times over and read as thirty separate problems.
    """
    from engine.aws_live_scanner import AWSLiveScanner
    assert "ORGANIZATIONS" in AWSLiveScanner.GLOBAL_SECTIONS
    s = make_scanner(sections=["ORGANIZATIONS"])
    s.all_regions_scan = True
    s._all_regions = ["us-east-1", "eu-west-1", "ap-south-1"]
    assert s._regions_for_section("ORGANIZATIONS") == [s.region], (
        "the section would run once per region and duplicate every finding")


def test_the_organizations_section_is_dispatched_by_a_default_scan():
    """A section in CHECK_MAP and absent from SECTIONS never runs on a default scan —
    the defect that once hid four AI sections. This asserts the run list, not the table.
    """
    from engine.aws_live_scanner import SECTIONS, SECTION_LABELS
    assert "ORGANIZATIONS" in SECTIONS
    assert SECTIONS.index("ORGANIZATIONS") == 0, (
        "it runs first on purpose: it is the one section normally refused, so its "
        "coverage statement should be the first thing an operator reads")
    assert "ORGANIZATIONS" in SECTION_LABELS


def test_every_new_check_is_declared_once_and_completely():
    """CheckDef validates each projection at construction, so this asserts the set rather
    than the shape: nineteen ids, each mapped to a v7.0.0 recommendation that exists."""
    ids = sorted(c.id for c in F.CHECKS)
    assert len(ids) == 19, ids
    assert len(set(ids)) == 19, "duplicate id in the batch"
    for c in F.CHECKS:
        rec = c.compliance.get("CIS")
        assert rec in M.RECOMMENDATIONS, f"{c.id} cites {rec!r}, which is not in v7.0.0"
        assert M.recommendation_for(c.id) == rec, (
            f"{c.id} is keyed to {rec} but the mapping homes it at "
            f"{M.recommendation_for(c.id)}")


def test_the_batch_closes_every_gap_the_mapping_recorded():
    """The mapping and the batch have to agree that there are no gaps left. If they
    disagree, one of them is describing a product that does not exist."""
    gaps = [r for r, v in M.RECOMMENDATIONS.items() if v[2] == M.NO_CHECK]
    assert not gaps, f"recommendations still recorded as gaps: {sorted(gaps)}"


def test_fifteen_manual_recommendations_are_decided_automatically():
    """The interesting number in this batch. A Manual recommendation is one the benchmark
    does not believe a single API read settles; automating one is worth more than
    automating an Automated one, and the count is asserted so it cannot quietly shrink."""
    manual = [c.id for c in F.CHECKS
              if M.RECOMMENDATIONS[c.compliance["CIS"]][1] == M.MANUAL]
    assert len(manual) == 15, sorted(manual)


def test_a_narrowed_recommendation_still_owns_its_check_but_a_partial_one_does_not():
    """The distinction that cost a design pass. ORG-04 and ACCT-01 answer a SUBSET of
    their recommendation and can FAIL, so each needs a citation on its findings. RDS-03
    reads Multi-AZ and can never fail on it, so a citation would promise an enforcement
    that does not exist. Collapsing the two verdicts left ORG-04 and ACCT-01 homeless."""
    assert M.verdict_for("2.1.4") == M.NARROWED
    assert M.recommendation_for("ORG-04") == "2.1.4"
    assert M.verdict_for("2.2") == M.NARROWED
    assert M.recommendation_for("ACCT-01") == "2.2"
    assert M.verdict_for("3.2.4") == M.PARTIAL
    assert M.recommendation_for("RDS-03") == "3.2.2", (
        "RDS-03 must be homed on the control it can fail on, not on Multi-AZ")
