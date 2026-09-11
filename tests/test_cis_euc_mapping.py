"""CIS AWS End User Compute v1.2.0 — the mapping, the fifteen checks, and a refusal.

Four jobs, in descending order of how much they matter.

1. THE REFUSAL. Six WorkDocs recommendations are blocked because the only WorkDocs
   operations an IAM role can reach read CUSTOMER DOCUMENTS.
   `test_no_check_ever_reads_workdocs_content` is the guard that keeps it that way:
   if somebody later "closes the gap" by calling DescribeUsers or GetDocument, the
   build fails. A blocked row looks like an unbuilt backlog item to whoever reads
   the mapping next year, and the whole point is that it must not be built.

2. THE UNSOUND ROWS. 2.12 and 2.17 have audit procedures that do not test what they
   recommend. Implementing them faithfully would ship checks that pass and fail for
   reasons unrelated to the control, so no check may cite them.

3. BOTH-DIRECTION AGREEMENT between the mapping and the catalogue, the contract the
   four sibling mappings hold. The reverse direction is the one that rots.

4. DRIVING TESTS for all fifteen new checks. `MAX_NEVER_OBSERVED` is 0, so a check
   shipped without one fails the build rather than joining a backlog.
"""
from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import aws_cis_euc as E                                  # noqa: E402
from engine import aws_cis_euc_map as M                              # noqa: E402
from engine import aws_live_scanner as A                             # noqa: E402
from test_live_scanner import make_scanner                           # noqa: E402
from test_unproven_checks_tranche5 import _ids, _renders             # noqa: E402

REGION = "us-east-1"
OWN = "123456789012"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "CIS_EUC_BENCHMARK.md")
GENERATOR = os.path.join(ROOT, "scripts", "cis_euc_benchmark.py")

DAY = 86400.0
NOW = 1_760_000_000.0          # pinned; the postures take `now` rather than read it


# ═════════════════════════════════════════════════════════════════════════════
# 1. The refusal
# ═════════════════════════════════════════════════════════════════════════════
#: Operations that return document or user CONTENT rather than configuration. The
#: workdocs model has no others worth having -- that is precisely the finding.
WORKDOCS_DATA_READS = (
    "describe_users", "get_document", "get_document_version", "get_folder",
    "search_resources", "describe_folder_contents", "describe_comments",
    "describe_activities", "get_current_user", "describe_root_folders",
)


def test_the_workdocs_rows_are_blocked_and_stay_blocked():
    """All six, pinned by number. Un-blocking one has to be a deliberate act."""
    blocked = set(M.by_verdict(M.BLOCKED))
    assert {"4.3", "4.4", "4.5", "4.6", "4.7", "4.8"} <= blocked
    for rec in ("4.3", "4.4", "4.5", "4.6", "4.7", "4.8"):
        assert "WORKDOCS_ADMIN" in M.RECOMMENDATIONS[rec][3], rec
        assert not M.checks_for(rec), f"{rec} is blocked and names a check"


def test_no_check_ever_reads_workdocs_content():
    """THE GUARD THIS MODULE EXISTS FOR.

    Six recommendations are blocked not because the work is hard but because the
    only way to answer them is to read the customer's documents. If a later change
    "closes the gap" by calling into workdocs, this fails. The charter is
    read-only-of-CONFIG, and a document store is the one service where the
    distinction between configuration and content is the whole point."""
    src = open(os.path.join(ROOT, "engine", "aws_live_scanner.py"),
               encoding="utf-8").read()
    assert '_client("workdocs")' not in src, (
        "the scanner opens a workdocs client. Every readable workdocs operation "
        "returns document or user content, which this product refuses to read -- "
        "see BLOCKERS['WORKDOCS_ADMIN'] in engine/aws_cis_euc_map.py")
    for op in WORKDOCS_DATA_READS:
        assert f".{op}(" not in src, f"scanner calls workdocs {op}"


def test_workdocs_has_no_check_family():
    """Nothing may claim to cover section 4, because nothing can."""
    assert "4" not in set(M.FAMILY_SECTION.values())
    for cid in A.CHECK_SEVERITY:
        assert not cid.startswith("WDOC"), f"{cid} implies WorkDocs coverage"


# ═════════════════════════════════════════════════════════════════════════════
# 2. The unsound rows
# ═════════════════════════════════════════════════════════════════════════════
def test_the_unsound_rows_are_the_two_that_were_read_and_rejected():
    assert M.by_verdict(M.UNSOUND) == ("2.12", "2.17")


def test_no_check_cites_an_unsound_recommendation():
    """2.17 asks whether an API call crossed a VPC endpoint -- a property of the
    caller's network that the account does not record, and its audit tests nothing.
    2.12 concludes that uniform bundles are approved bundles, which does not follow.
    A check citing either would be measuring something other than the control."""
    unsound = set(M.by_verdict(M.UNSOUND))
    cited = {cid: keys["CIS-EUC"] for cid, keys in A.COMPLIANCE_MAP.items()
             if keys.get("CIS-EUC") in unsound}
    assert not cited, (
        f"checks cite an UNSOUND recommendation: {cited}. Those rows are recorded "
        f"as UNSOUND because the source's own audit does not test the thing it "
        f"recommends -- see engine/aws_cis_euc_map.py")


# ═════════════════════════════════════════════════════════════════════════════
# 3. Mapping invariants
# ═════════════════════════════════════════════════════════════════════════════
def test_every_recommendation_is_present_once_and_the_numbering_is_dense():
    for num, _name, declared in M.SECTIONS:
        nums = sorted(int(r.split(".", 1)[1])
                      for r in M.RECOMMENDATIONS if r.split(".", 1)[0] == num)
        assert nums == list(range(1, declared + 1)), (
            f"section {num} is {nums}, expected 1..{declared}")


def test_the_section_counts_sum_to_the_benchmark_total():
    assert sum(c for _n, _l, c in M.SECTIONS) == len(M.RECOMMENDATIONS) == 34


def test_every_verdict_is_declared_and_every_declared_verdict_is_used():
    used = {row[1] for row in M.RECOMMENDATIONS.values()}
    assert used <= set(M.VERDICTS), f"unknown: {used - set(M.VERDICTS)}"
    assert used == set(M.VERDICTS), f"declared but unused: {set(M.VERDICTS) - used}"


def test_every_check_named_in_the_mapping_exists():
    named = {c for row in M.RECOMMENDATIONS.values() for c in row[2]}
    missing = sorted(c for c in named if c not in A.CHECK_SEVERITY)
    assert not missing, f"mapping cites checks that do not exist: {missing}"


def test_only_covered_rows_name_checks():
    for rec, (_l, verdict, checks, _n) in M.RECOMMENDATIONS.items():
        if verdict == M.COVERED:
            assert checks, f"{rec} is covered and names no check"
        else:
            assert not checks, f"{rec} is {verdict} and names {checks}"


def test_every_cis_euc_key_matches_the_mapping():
    """Forward: a key must name a row that exists and lists the check."""
    for cid, keys in A.COMPLIANCE_MAP.items():
        rec = keys.get("CIS-EUC")
        if not rec:
            continue
        assert rec in M.RECOMMENDATIONS, f"{cid} cites unknown {rec}"
        assert cid in M.checks_for(rec), f"{cid} cites {rec}, which omits it"


def test_every_covered_check_in_its_own_section_carries_the_key():
    """Reverse -- the direction that rots."""
    for rec, (_l, verdict, checks, _n) in M.RECOMMENDATIONS.items():
        if verdict != M.COVERED:
            continue
        for cid in checks:
            if M.FAMILY_SECTION.get(cid.rsplit("-", 1)[0]) != rec.split(".", 1)[0]:
                continue
            assert A.COMPLIANCE_MAP.get(cid, {}).get("CIS-EUC") == \
                M.recommendation_for(cid), (
                    f"{cid} is a covering check for {rec} and does not cite its home")


def test_the_key_only_lands_on_this_benchmarks_families():
    for cid, keys in A.COMPLIANCE_MAP.items():
        if "CIS-EUC" not in keys:
            continue
        fam = cid.rsplit("-", 1)[0]
        assert fam in M.FAMILY_SECTION, (
            f"{cid} carries CIS-EUC but {fam} is not one of this benchmark's "
            f"service families {sorted(M.FAMILY_SECTION)}")


def test_the_two_checks_the_benchmark_never_asks_for_carry_no_key():
    """WKS-08 and APS-05 answer no recommendation, and the absence is the point."""
    for cid in ("WKS-08", "APS-05"):
        assert cid in A.CHECK_SEVERITY
        assert "CIS-EUC" not in A.COMPLIANCE_MAP.get(cid, {})


def test_wsw_02_is_reused_rather_than_duplicated():
    """3.1 was already covered before this benchmark was read. Adding a second
    check for it would have been the easy mistake."""
    assert M.checks_for("3.1") == ("WSW-02",)
    assert A.COMPLIANCE_MAP["WSW-02"].get("CIS-EUC") == "3.1"


# ═════════════════════════════════════════════════════════════════════════════
# 4a. Pure decisions
# ═════════════════════════════════════════════════════════════════════════════
def test_either_unencrypted_volume_is_a_finding_and_names_which():
    p = E.workspace_volume_posture({"WorkspaceId": "ws-1",
                                    "RootVolumeEncryptionEnabled": True,
                                    "UserVolumeEncryptionEnabled": False})
    assert p["any_unencrypted"] and p["unencrypted"] == ("user",)
    both = E.workspace_volume_posture({"RootVolumeEncryptionEnabled": False,
                                       "UserVolumeEncryptionEnabled": False})
    assert both["unencrypted"] == ("root", "user")


def test_absent_encryption_fields_are_unknown_not_unencrypted():
    p = E.workspace_volume_posture({"WorkspaceId": "ws-1"})
    assert not p["known"] and not p["any_unencrypted"]


def test_an_empty_ip_group_list_is_the_permissive_default():
    """The whole of 2.8: no group attached means the default group, which the
    source itself describes as admitting every address."""
    assert not E.directory_posture({"ipGroupIds": []})["ip_restricted"]
    assert E.directory_posture({"ipGroupIds": ["wsipg-1"]})["ip_restricted"]


def test_web_access_allow_and_deny_are_told_apart():
    assert E.directory_posture(
        {"WorkspaceAccessProperties": {"DeviceTypeWeb": "ALLOW"}})["web_allowed"]
    d = E.directory_posture(
        {"WorkspaceAccessProperties": {"DeviceTypeWeb": "DENY"}})
    assert d["web_known"] and not d["web_allowed"]
    assert not E.directory_posture({})["web_known"]


def test_radius_failed_is_distinguished_from_absent():
    """A FAILED RADIUS is worse than none: the console reports MFA while sign-in
    silently falls back to a password."""
    absent = E.radius_posture({"DirectoryId": "d-1"})
    assert not absent["configured"] and not absent["active"]
    failed = E.radius_posture({"DirectoryId": "d-1", "RadiusStatus": "Failed",
                               "RadiusSettings": {"RadiusServers": ["r1"]}})
    assert failed["failed"] and not failed["active"]
    ok = E.radius_posture({"DirectoryId": "d-1", "RadiusStatus": "Completed",
                           "RadiusSettings": {"RadiusServers": ["r1"]}})
    assert ok["active"] and not ok["failed"]


def test_the_healthy_radius_status_is_completed_not_enabled():
    """The source document uses both words; only one is in the service model."""
    assert E.RADIUS_COMPLETED == "Completed"
    assert E.radius_posture({"RadiusStatus": "Enabled"})["active"] is False


def test_the_three_weak_radius_protocols_fail_and_ms_chapv2_does_not():
    for proto in ("PAP", "CHAP", "MS-CHAPv1"):
        r = E.radius_posture({"RadiusSettings": {"AuthenticationProtocol": proto}})
        assert r["weak_protocol"], proto
    best = E.radius_posture(
        {"RadiusSettings": {"AuthenticationProtocol": "MS-CHAPv2"}})
    assert best["protocol_known"] and not best["weak_protocol"]


def test_a_never_connected_workspace_is_idle_rather_than_unknown():
    p = E.workspace_idle_posture({"WorkspaceId": "ws-1"}, NOW)
    assert p["known"] and p["never"] and p["idle"]


def test_workspace_idle_boundary_is_the_benchmarks_thirty_days():
    fresh = E.workspace_idle_posture(
        {"LastKnownUserConnectionTimestamp": _dt(NOW - 29 * DAY)}, NOW)
    stale = E.workspace_idle_posture(
        {"LastKnownUserConnectionTimestamp": _dt(NOW - 31 * DAY)}, NOW)
    assert not fresh["idle"] and fresh["days"] == 29
    assert stale["idle"] and stale["days"] == 31


def test_appstream_timeouts_are_compared_in_seconds_not_minutes():
    """The document and console speak minutes; the API returns seconds. A check
    written from the prose compares 600 against 36000 and passes everything."""
    assert E.MAX_SESSION_SECONDS == 36000
    ok = E.fleet_session_posture({"Name": "f", "MaxUserDurationInSeconds": 36000,
                                  "DisconnectTimeoutInSeconds": 300,
                                  "IdleDisconnectTimeoutInSeconds": 600})
    assert ok["known"] and not ok["any_over"]
    over = E.fleet_session_posture({"Name": "f", "MaxUserDurationInSeconds": 57600})
    assert over["any_over"] and "max session 960min" in over["over"][0]


def test_a_zero_idle_timeout_is_the_worst_value_not_the_best():
    p = E.fleet_session_posture({"Name": "f", "IdleDisconnectTimeoutInSeconds": 0})
    assert p["any_over"] and "disabled" in p["over"][0]


def test_disable_imdsv1_is_read_as_a_posture_not_as_its_name():
    """The field is named for the action. True means v1 is OFF, which is good."""
    on = E.fleet_network_posture({"Name": "f", "DisableIMDSV1": False})
    off = E.fleet_network_posture({"Name": "f", "DisableIMDSV1": True})
    assert on["imdsv1_enabled"] and not off["imdsv1_enabled"]
    assert not E.fleet_network_posture({"Name": "f"})["imds_known"]


def test_a_stack_needs_a_streaming_endpoint_with_a_vpce_id():
    assert not E.stack_endpoint_posture(
        {"Name": "s", "AccessEndpoints": []})["private_streaming"]
    # An endpoint entry with no VpceId is not a private path.
    assert not E.stack_endpoint_posture(
        {"AccessEndpoints": [{"EndpointType": "STREAMING"}]})["private_streaming"]
    good = E.stack_endpoint_posture(
        {"AccessEndpoints": [{"EndpointType": "STREAMING", "VpceId": "vpce-1"}]})
    assert good["private_streaming"] and good["endpoints"] == ("vpce-1",)


def test_image_age_boundary_is_thirty_days():
    assert not E.image_age_posture(_dt(NOW - 29 * DAY), NOW)["stale"]
    assert E.image_age_posture(_dt(NOW - 31 * DAY), NOW)["stale"]
    assert not E.image_age_posture(None, NOW)["known"]


class _Ts:
    """A boto3-style tz-aware timestamp: only .timestamp() is relied on."""

    def __init__(self, epoch):
        self._e = epoch

    def timestamp(self):
        return self._e


def _dt(epoch):
    return _Ts(epoch)


# ═════════════════════════════════════════════════════════════════════════════
# 4b. Driving tests
# ═════════════════════════════════════════════════════════════════════════════
def _ws(directories=(), workspaces=(), statuses=(), dirs_ds=()):
    wsc, dsc = MagicMock(), MagicMock()
    wsc.describe_workspace_directories.return_value = {
        "Directories": list(directories)}
    wsc.describe_workspaces.return_value = {"Workspaces": list(workspaces)}
    wsc.describe_workspaces_connection_status.return_value = {
        "WorkspacesConnectionStatus": list(statuses)}
    dsc.describe_directories.return_value = {
        "DirectoryDescriptions": list(dirs_ds)}
    s = make_scanner(sections=["WORKSPACES"])
    s.account = OWN
    s._clients[f"workspaces:{REGION}"] = wsc
    s._clients[f"ds:{REGION}"] = dsc
    return s


DIR_OK = {
    "DirectoryId": "d-1", "WorkspaceDirectoryName": "corp",
    "ipGroupIds": ["wsipg-1"],
    "WorkspaceAccessProperties": {"DeviceTypeWeb": "DENY"},
    "WorkspaceCreationProperties": {"EnableMaintenanceMode": True,
                                    "EnableInternetAccess": False,
                                    "UserEnabledAsLocalAdministrator": False},
}


def _dir(**over):
    d = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list)
             else v) for k, v in DIR_OK.items()}
    for k, v in over.items():
        if k in ("WorkspaceAccessProperties", "WorkspaceCreationProperties"):
            d[k].update(v)
        else:
            d[k] = v
    return d


def test_wks01_an_unencrypted_desktop_volume_fails():
    s = _ws(workspaces=[{"WorkspaceId": "ws-1", "UserName": "ana",
                         "RootVolumeEncryptionEnabled": True,
                         "UserVolumeEncryptionEnabled": False}])
    s._check_workspaces()
    r = _renders(s, "WKS-01", "HIGH", contains="ws-1")
    assert "user" in r.message and "ana" in r.message


def test_wks01_passes_when_both_volumes_are_encrypted():
    s = _ws(workspaces=[{"WorkspaceId": "ws-1",
                         "RootVolumeEncryptionEnabled": True,
                         "UserVolumeEncryptionEnabled": True}])
    s._check_workspaces()
    assert not _ids(s, "WKS-01", "FAIL") and _ids(s, "WKS-01", "PASS")


def test_wks02_browser_access_fails():
    s = _ws(directories=[_dir(WorkspaceAccessProperties={"DeviceTypeWeb": "ALLOW"})])
    s._check_workspaces()
    _renders(s, "WKS-02", "MEDIUM", contains="corp")


def test_wks03_a_directory_with_no_ip_group_fails():
    s = _ws(directories=[_dir(ipGroupIds=[])])
    s._check_workspaces()
    _renders(s, "WKS-03", "MEDIUM", contains="corp")


def test_wks04_maintenance_mode_off_fails():
    s = _ws(directories=[_dir(WorkspaceCreationProperties={
        "EnableMaintenanceMode": False})])
    s._check_workspaces()
    _renders(s, "WKS-04", "LOW", contains="corp")


def test_wks05_a_never_used_desktop_fails_and_says_so():
    s = _ws(statuses=[{"WorkspaceId": "ws-9"}])
    s._check_workspaces()
    r = _renders(s, "WKS-05", "LOW", contains="ws-9")
    assert "never" in r.message


def test_wks05_passes_on_a_recently_used_desktop():
    import time
    s = _ws(statuses=[{"WorkspaceId": "ws-9",
                       "LastKnownUserConnectionTimestamp": _dt(time.time())}])
    s._check_workspaces()
    assert not _ids(s, "WKS-05", "FAIL") and _ids(s, "WKS-05", "PASS")


def test_wks06_a_directory_with_no_second_factor_fails():
    s = _ws(directories=[_dir()], dirs_ds=[{"DirectoryId": "d-1", "Name": "corp"}])
    s._check_workspaces()
    _renders(s, "WKS-06", "MEDIUM", contains="corp")


def test_wks06_a_failed_radius_is_reported_as_worse_than_absent():
    s = _ws(directories=[_dir()],
            dirs_ds=[{"DirectoryId": "d-1", "RadiusStatus": "Failed",
                      "RadiusSettings": {"RadiusServers": ["r1"],
                                         "AuthenticationProtocol": "MS-CHAPv2"}}])
    s._check_workspaces()
    r = _renders(s, "WKS-06", "MEDIUM")
    assert "FAILED" in r.message and "does not actually require" in r.message


def test_wks06_passes_when_radius_is_completed():
    s = _ws(directories=[_dir()],
            dirs_ds=[{"DirectoryId": "d-1", "RadiusStatus": "Completed",
                      "RadiusSettings": {"RadiusServers": ["r1"],
                                         "AuthenticationProtocol": "MS-CHAPv2"}}])
    s._check_workspaces()
    assert not _ids(s, "WKS-06", "FAIL") and _ids(s, "WKS-06", "PASS")


def test_wks07_a_weak_radius_protocol_fails_and_refuses_to_oversell_the_fix():
    s = _ws(directories=[_dir()],
            dirs_ds=[{"DirectoryId": "d-1", "RadiusStatus": "Completed",
                      "RadiusSettings": {"RadiusServers": ["r1"],
                                         "AuthenticationProtocol": "PAP"}}])
    s._check_workspaces()
    r = _renders(s, "WKS-07", "HIGH", contains="PAP")
    assert "not the same as strong" in r.message, (
        "the message must not imply MS-CHAPv2 is strong; it is the least bad of four")


def test_wks08_users_as_local_administrators_fails():
    s = _ws(directories=[_dir(WorkspaceCreationProperties={
        "UserEnabledAsLocalAdministrator": True})])
    s._check_workspaces()
    r = _renders(s, "WKS-08", "MEDIUM", contains="corp")
    assert "benchmark never asks" in r.message


def test_wks09_direct_internet_access_fails():
    s = _ws(directories=[_dir(WorkspaceCreationProperties={
        "EnableInternetAccess": True})])
    s._check_workspaces()
    _renders(s, "WKS-09", "MEDIUM", contains="corp")


def test_workspaces_says_nothing_about_an_account_that_does_not_use_it():
    s = _ws()
    s._check_workspaces()
    assert not [f for f in s.results if f.check_id.startswith("WKS-")]


def _aps(fleets=(), stacks=(), images=()):
    c = MagicMock()
    c.describe_fleets.return_value = {"Fleets": list(fleets)}
    c.describe_stacks.return_value = {"Stacks": list(stacks)}
    c.describe_images.return_value = {"Images": list(images)}
    s = make_scanner(sections=["APPSTREAM"])
    s.account = OWN
    s._clients[f"appstream:{REGION}"] = c
    return s


FLEET_OK = {"Name": "apps", "EnableDefaultInternetAccess": False,
            "VpcConfig": {"SubnetIds": ["subnet-a", "subnet-b"]},
            "DisableIMDSV1": True, "MaxUserDurationInSeconds": 36000,
            "DisconnectTimeoutInSeconds": 300,
            "IdleDisconnectTimeoutInSeconds": 600}


def _fleet(**over):
    f = dict(FLEET_OK)
    f.update(over)
    return f


def test_aps01_default_internet_access_fails():
    s = _aps(fleets=[_fleet(EnableDefaultInternetAccess=True)])
    s._check_appstream()
    _renders(s, "APS-01", "MEDIUM", contains="apps")


def test_aps02_a_fleet_outside_a_vpc_fails():
    s = _aps(fleets=[_fleet(VpcConfig={"SubnetIds": []})])
    s._check_appstream()
    _renders(s, "APS-02", "MEDIUM", contains="apps")


def test_aps03_a_stack_streaming_over_the_internet_fails():
    s = _aps(stacks=[{"Name": "st", "AccessEndpoints": []}])
    s._check_appstream()
    _renders(s, "APS-03", "MEDIUM", contains="st")


def test_aps03_passes_with_a_vpc_streaming_endpoint():
    s = _aps(stacks=[{"Name": "st", "AccessEndpoints": [
        {"EndpointType": "STREAMING", "VpceId": "vpce-1"}]}])
    s._check_appstream()
    assert not _ids(s, "APS-03", "FAIL") and _ids(s, "APS-03", "PASS")


def test_aps04_generous_session_limits_fail_and_name_which():
    s = _aps(fleets=[_fleet(MaxUserDurationInSeconds=57600,
                            IdleDisconnectTimeoutInSeconds=0)])
    s._check_appstream()
    r = _renders(s, "APS-04", "LOW", contains="apps")
    assert "960min" in r.message and "disabled" in r.message


def test_aps04_passes_at_exactly_the_benchmark_bounds():
    s = _aps(fleets=[_fleet()])
    s._check_appstream()
    assert not _ids(s, "APS-04", "FAIL") and _ids(s, "APS-04", "PASS")


def test_aps05_imdsv1_still_answering_fails():
    s = _aps(fleets=[_fleet(DisableIMDSV1=False)])
    s._check_appstream()
    r = _renders(s, "APS-05", "HIGH", contains="apps")
    assert "benchmark never asks" in r.message


def test_aps06_a_stale_image_fails():
    import time
    s = _aps(images=[{"Name": "img", "CreatedTime": _dt(time.time() - 60 * DAY)}])
    s._check_appstream()
    _renders(s, "APS-06", "LOW", contains="img")


def test_appstream_says_nothing_about_an_account_that_does_not_use_it():
    s = _aps()
    s._check_appstream()
    assert not [f for f in s.results if f.check_id.startswith("APS-")]


def test_appstream_images_are_fetched_private_only():
    """A public base image's age is AWS's business, not the account's, and every
    account can see all of them -- fetching PUBLIC would fail every account."""
    s = _aps(images=[])
    s._check_appstream()
    kwargs = s._clients[f"appstream:{REGION}"].describe_images.call_args
    assert kwargs and kwargs.kwargs.get("Type") == "PRIVATE"


# ═════════════════════════════════════════════════════════════════════════════
# 5. The document
# ═════════════════════════════════════════════════════════════════════════════
def test_the_document_is_not_stale():
    proc = subprocess.run([sys.executable, GENERATOR, "--check"],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, (
        f"docs/CIS_EUC_BENCHMARK.md is stale:\n{proc.stdout}\n{proc.stderr}")


def test_the_document_names_its_generator_and_the_licence_position():
    text = open(DOC, encoding="utf-8").read()
    assert "scripts/cis_euc_benchmark.py" in text
    assert "may not be redistributed" in text


def test_the_document_carries_no_benchmark_prose():
    """Recommendation NUMBERS are references; the document's own words are not
    ours to republish."""
    text = open(DOC, encoding="utf-8").read().lower()
    for phrase in ("profile applicability", "rationale statement",
                   "impact statement", "audit procedure:", "remediation procedure",
                   "ensure administration of", "ensure mfa is enabled",
                   "ensure workspace volumes"):
        assert phrase not in text, f"source prose leaked: {phrase}"


def test_the_generator_emits_no_timestamp():
    """The CCM generator shipped a `generated:` date and its own staleness test
    then failed every day after. Not again."""
    src = open(GENERATOR, encoding="utf-8").read()
    for banned in ("date.today", "datetime.now", "time.time"):
        assert banned not in src, f"{GENERATOR} reads the clock: {banned}"
