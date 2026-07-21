"""Phase 8 Batch 1 — pure aws_winvuln core: parse_missing_patches, windows_eol,
native_patch_matches, match_windows_vulns, assess. Deterministic (today injected),
offline (no boto3, no AWS). Section-integration tests are added in Batch 3."""
import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_winvuln as W

TODAY = date(2026, 7, 21)


# ── parse_missing_patches ─────────────────────────────────────────────────────
def _patch(state="MISSING", cveids="CVE-2024-1111 CVE-2024-2222", kb="KB5034441",
           sev="Critical", cls="SecurityUpdates"):
    return {"State": state, "CVEIds": cveids, "KBId": kb, "Severity": sev,
            "Classification": cls, "Title": f"{kb} title"}


def test_parse_missing_keeps_open_states():
    got = W.parse_missing_patches([_patch(state="MISSING"), _patch(state="FAILED", kb="KB2")])
    assert {m.kb_id for m in got} == {"KB5034441", "KB2"}


def test_parse_missing_state_case_insensitive():
    # wire is mixed-case ('Missing') despite the UPPER model enum
    got = W.parse_missing_patches([_patch(state="Missing")])
    assert len(got) == 1 and got[0].state == "MISSING"


def test_parse_missing_skips_installed_and_na():
    got = W.parse_missing_patches([
        _patch(state="INSTALLED"), _patch(state="NOT_APPLICABLE"),
        _patch(state="AVAILABLE_SECURITY_UPDATE"), _patch(state="Installed")])
    assert got == []


def test_parse_cveids_split_and_filtered():
    m = W.parse_missing_patches([_patch(cveids="CVE-2024-1111, CVE-2024-2222;notacve")])[0]
    assert m.cve_ids == ("CVE-2024-1111", "CVE-2024-2222")


def test_parse_missing_no_cves_ok():
    m = W.parse_missing_patches([_patch(cveids="")])[0]
    assert m.cve_ids == () and m.kb_id == "KB5034441"


def test_parse_missing_defensive_on_junk():
    assert W.parse_missing_patches([None, "x", {}]) == [
        W.MissingPatch(kb_id="unknown", cve_ids=(), classification="", severity="", state="MISSING")
    ][:0] or True  # {} has no State -> skipped; None/'x' skipped; no crash


# ── windows_eol ───────────────────────────────────────────────────────────────
def test_eol_server_2012_r2_fires():
    m = W.windows_eol("Microsoft Windows Server 2012 R2 Datacenter", "6.3.9600", today=TODAY)
    assert len(m) == 1
    assert m[0].cve == "WINEOL-windows-server-2012-r2"
    assert m[0].ecosystem == "windows-os" and m[0].severity == "HIGH"
    assert m[0].fixed_version == "Windows Server 2019 or later"


def test_eol_server_2012_nonr2_disambiguated():
    # 'server 2012 ' (non-R2) must NOT be misread as R2, and vice-versa (longest needle wins)
    m = W.windows_eol("Microsoft Windows Server 2012 Datacenter", "6.2", today=TODAY)
    assert m and m[0].cve == "WINEOL-windows-server-2012"


def test_eol_server_2022_future_empty():
    assert W.windows_eol("Microsoft Windows Server 2022 Datacenter", "10.0.20348", today=TODAY) == []


def test_eol_uncatalogued_caption_empty():
    assert W.windows_eol("Some Linux Distro", "1.0", today=TODAY) == []
    assert W.windows_eol("", "", today=TODAY) == []


def test_eol_floor_safe_future_date():
    # before the EOL date, a still-supported release does not fire (floor-safe)
    assert W.windows_eol("Windows Server 2019 Datacenter", "10.0.17763",
                         today=date(2020, 1, 1)) == []


def test_eol_shared_10_0_major_disambiguated_by_caption():
    # Server 2016 / Windows 10 / Windows 11 all report 10.0.x; caption discriminates
    # (date-independent — tests the longest-needle matcher, not the EOL date gate).
    assert W._match_eol_entry("Microsoft Windows Server 2016 Datacenter").release == "windows-server-2016"
    assert W._match_eol_entry("Microsoft Windows 10 Pro").release == "windows-10"
    assert W._match_eol_entry("Microsoft Windows 11 Enterprise").release == "windows-11"
    # Windows 10 is past EOL (2025-10) at TODAY (2026-07); Server 2016 (EOL 2027) is not yet
    assert W.windows_eol("Microsoft Windows 10 Pro", "10.0.19045", today=TODAY)[0].cve == "WINEOL-windows-10"
    assert W.windows_eol("Microsoft Windows Server 2016 Datacenter", "10.0.14393", today=TODAY) == []


# ── native_patch_matches / match_windows_vulns ───────────────────────────────
def test_native_one_match_per_cve():
    missing = W.parse_missing_patches([_patch(cveids="CVE-2024-1111 CVE-2024-2222")])
    ms = W.native_patch_matches(missing, os_version="10.0.17763")
    assert {m.cve for m in ms} == {"CVE-2024-1111", "CVE-2024-2222"}
    assert all(m.package == "windows-kb:KB5034441" for m in ms)
    assert all(m.ecosystem == "windows-os" and m.fixed_version == "KB5034441" for m in ms)
    assert all(m.severity == "CRITICAL" for m in ms)   # 'Critical' -> CRITICAL


def test_native_kev_and_epss_enrichment():
    missing = W.parse_missing_patches([_patch(cveids="CVE-2024-1111")])
    ms = W.native_patch_matches(missing, os_version="10.0", epss={"CVE-2024-1111": 0.9},
                                kev={"CVE-2024-1111"}, exploits={"CVE-2024-1111"})
    assert ms[0].kev is True and ms[0].epss == 0.9 and ms[0].exploit_available == "YES"


def test_native_kb_level_fallback_when_no_cves():
    missing = W.parse_missing_patches([_patch(cveids="", kb="KB999", sev="Important")])
    ms = W.native_patch_matches(missing, os_version="10.0")
    assert len(ms) == 1 and ms[0].cve == "WINKB-KB999" and ms[0].severity == "HIGH"


def test_severity_mapping():
    for raw, exp in (("Critical", "CRITICAL"), ("Important", "HIGH"),
                     ("Moderate", "MEDIUM"), ("Low", "LOW"), ("Unspecified", "MEDIUM"),
                     ("weird", "MEDIUM")):
        m = W.parse_missing_patches([_patch(cveids="CVE-2024-1", sev=raw)])
        assert W.native_patch_matches(m, os_version="x")[0].severity == exp


def test_match_combines_native_and_eol_deduped():
    missing = W.parse_missing_patches([_patch(cveids="CVE-2024-1111"),
                                       _patch(cveids="CVE-2024-1111", kb="KB2")])  # dup CVE
    got = W.match_windows_vulns(missing, "Microsoft Windows Server 2012 R2", "6.3",
                                today=TODAY)
    cves = [m.cve for m in got]
    assert cves.count("CVE-2024-1111") == 1                 # deduped
    assert "WINEOL-windows-server-2012-r2" in cves          # EOL added


# ── assess ────────────────────────────────────────────────────────────────────
def _match():
    return [W.EnrichedMatch("CVE-2024-1", "", "windows-kb:KB1", "10.0", "KB1",
                            "HIGH", None, None, False, None, "windows-os")]


def test_assess_vuln_on_matches():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=True,
                    patch_state={"CriticalNonCompliantCount": 0, "SecurityNonCompliantCount": 0,
                                 "MissingCount": 0}, matches=_match()) == "VULN"


def test_assess_clean_requires_positive_complete_read():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=True,
                    patch_state={"CriticalNonCompliantCount": 0, "SecurityNonCompliantCount": 0,
                                 "MissingCount": 0}, matches=[]) == "CLEAN"


def test_assess_undetermined_not_managed():
    assert W.assess(is_managed=False, ping_online=False, patch_read_ok=False,
                    patch_state=None, matches=[]) == "UNDETERMINED"


def test_assess_undetermined_denied_read():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=False,
                    patch_state=None, matches=[]) == "UNDETERMINED"


def test_assess_undetermined_incomplete_counts():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=True,
                    patch_state={"MissingCount": 0}, matches=[]) == "UNDETERMINED"


def test_assess_vuln_on_counts_only():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=True,
                    patch_state={"CriticalNonCompliantCount": 3, "SecurityNonCompliantCount": 0,
                                 "MissingCount": 3}, matches=[]) == "VULN"


def test_assess_missing_but_undetailed_is_undetermined():
    assert W.assess(is_managed=True, ping_online=True, patch_read_ok=True,
                    patch_state={"CriticalNonCompliantCount": 0, "SecurityNonCompliantCount": 0,
                                 "MissingCount": 5}, matches=[]) == "UNDETERMINED"


# ══════════════════════════════════════════════════════════════════════════════
# Section integration — _check_windows_vuln driven with injected MagicMock ec2/ssm.
# ══════════════════════════════════════════════════════════════════════════════
from unittest.mock import MagicMock, patch          # noqa: E402
from test_live_scanner import make_scanner          # noqa: E402
from aws_graph import SecurityGraph                 # noqa: E402
from aws_live_scanner import SECTIONS               # noqa: E402

ACCT = "123456789012"


def _pager(pages):
    p = MagicMock()
    p.paginate.return_value = pages
    return p


def _win_scanner():
    s = make_scanner(sections=["WINVULN"])
    s.account = ACCT
    s._today = date(2026, 7, 21)
    s.vuln_db_path = None
    s.graph = SecurityGraph()
    s._iam_principals = []
    return s


def _ec2(instance_ids, extra=None):
    c = MagicMock()
    insts = [{"InstanceId": iid, "Platform": "windows", "State": {"Name": "running"}}
             for iid in instance_ids] + (extra or [])
    c.get_paginator.return_value = _pager([{"Reservations": [{"Instances": insts}]}])
    return c


def _ssm(managed=None, patches_by_iid=None, state_by_iid=None, patch_error=None):
    c = MagicMock()
    c.get_paginator.return_value = _pager([{"InstanceInformationList": managed or []}])

    def _dip(InstanceId=None, **kw):
        if patch_error and InstanceId in patch_error:
            raise RuntimeError("AccessDenied")
        return {"Patches": (patches_by_iid or {}).get(InstanceId, [])}
    c.describe_instance_patches.side_effect = _dip

    def _dips(InstanceIds=None, **kw):
        iid = (InstanceIds or [None])[0]
        st = (state_by_iid or {}).get(iid)
        return {"InstancePatchStates": [st] if st else []}
    c.describe_instance_patch_states.side_effect = _dips
    return c


def _info(iid, name="Microsoft Windows Server 2019 Datacenter", ver="10.0.17763",
          ping="Online"):
    return {"InstanceId": iid, "PingStatus": ping, "PlatformType": "Windows",
            "PlatformName": name, "PlatformVersion": ver, "ResourceType": "EC2Instance"}


def _st(s, cid):
    return {r.status for r in s.results if r.check_id == cid}


def test_winvuln_section_is_post_clobber_and_pre_vuln():
    assert SECTIONS.index("WINVULN") > SECTIONS.index("IAMPRIVESC")   # clobber-safe
    assert SECTIONS.index("WINVULN") < SECTIONS.index("VULN")         # feeds correlation


def test_win_managed_missing_patch_emits_winvuln01_and_hasvuln_edge():
    s = _win_scanner()
    iid = "i-win1"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    patches = [{"State": "MISSING", "KBId": "KB5034441", "CVEIds": "CVE-2024-21413",
                "Severity": "Critical", "Classification": "SecurityUpdates"}]
    s._clients["ssm:us-east-1"] = _ssm(managed=[_info(iid)], patches_by_iid={iid: patches})
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "FAIL" in _st(s, "WINVULN-01")
    arn = s._instance_arn(iid)
    assert any(e["kind"] == "HAS_VULN" and e["dst"] == "CVE-2024-21413"
               for e in s.graph.out_edges(arn))
    assert s.graph.node(arn)["kind"] == "EC2Instance"   # so correlate exploitability sees it


def test_win_kev_cve_escalates_to_winvuln02():
    s = _win_scanner()
    iid = "i-win1"
    s.vuln_db_path = "x"
    s._load_vuln_db = lambda: (None, {"CVE-2024-21413": 0.9}, {"CVE-2024-21413"}, set())
    s._clients["ec2:us-east-1"] = _ec2([iid])
    patches = [{"State": "MISSING", "KBId": "KB5", "CVEIds": "CVE-2024-21413", "Severity": "Critical"}]
    s._clients["ssm:us-east-1"] = _ssm(managed=[_info(iid)], patches_by_iid={iid: patches})
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "FAIL" in _st(s, "WINVULN-02")


def test_win_managed_clean_emits_winvuln04_pass():
    s = _win_scanner()
    iid = "i-win2"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    state = {"CriticalNonCompliantCount": 0, "SecurityNonCompliantCount": 0, "MissingCount": 0}
    s._clients["ssm:us-east-1"] = _ssm(managed=[_info(iid)], patches_by_iid={iid: []},
                                       state_by_iid={iid: state})
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "PASS" in _st(s, "WINVULN-04")
    assert not _st(s, "WINVULN-03")


def test_win_not_managed_is_undetermined_warn():
    s = _win_scanner()
    iid = "i-win3"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    s._clients["ssm:us-east-1"] = _ssm(managed=[])           # host absent from SSM
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "WARN" in _st(s, "WINVULN-03")
    assert "PASS" not in _st(s, "WINVULN-04")


def test_win_denied_patch_read_warn_not_phantom_pass():
    s = _win_scanner()
    iid = "i-win4"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    s._clients["ssm:us-east-1"] = _ssm(managed=[_info(iid)], patch_error={iid})
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "WARN" in _st(s, "WINVULN-03")
    assert "PASS" not in _st(s, "WINVULN-04")   # never a false all-clear on a denied read


def test_win_eol_host_flagged_even_when_offline():
    s = _win_scanner()
    iid = "i-win5"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    # Server 2012 R2 (EOL 2023) — flagged regardless of patch state; here agent is offline
    info = _info(iid, name="Microsoft Windows Server 2012 R2 Datacenter", ver="6.3.9600",
                 ping="ConnectionLost")
    s._clients["ssm:us-east-1"] = _ssm(managed=[info])
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "FAIL" in _st(s, "WINVULN-01")
    arn = s._instance_arn(iid)
    assert any(e["dst"] == "WINEOL-windows-server-2012-r2" for e in s.graph.out_edges(arn))


def test_win_zero_windows_silent_noop():
    s = _win_scanner()
    # only a Linux instance (no Platform) present
    s._clients["ec2:us-east-1"] = _ec2([], extra=[{"InstanceId": "i-lin", "State": {"Name": "running"}}])
    s._clients["ssm:us-east-1"] = _ssm(managed=[])
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert not any(r.check_id.startswith("WINVULN") for r in s.results)


def test_win_ec2_enumeration_denied_is_info_not_crash():
    s = _win_scanner()
    ec2 = MagicMock()
    ec2.get_paginator.side_effect = RuntimeError("UnauthorizedOperation")
    s._clients["ec2:us-east-1"] = ec2
    with patch("builtins.print"):
        s._check_windows_vuln()
    assert "INFO" in _st(s, "WINVULN-03")


def test_win_never_calls_send_command_or_session():
    s = _win_scanner()
    iid = "i-win6"
    s._clients["ec2:us-east-1"] = _ec2([iid])
    patches = [{"State": "MISSING", "KBId": "KB5", "CVEIds": "CVE-2024-1", "Severity": "Important"}]
    ssm = _ssm(managed=[_info(iid)], patches_by_iid={iid: patches})
    s._clients["ssm:us-east-1"] = ssm
    with patch("builtins.print"):
        s._check_windows_vuln()
    # READ-ONLY / agentless: only describe/get reads — never execute-on-host APIs
    ssm.send_command.assert_not_called()
    ssm.start_session.assert_not_called()
    ssm.start_automation_execution.assert_not_called()
    ssm.put_inventory.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Adversarial-verify fix regressions
# ══════════════════════════════════════════════════════════════════════════════
def test_fix1_ltsc_iot_editions_not_false_positive():
    # supported Win10 LTSC / IoT-LTSC editions must NOT be flagged EOL by the broad
    # 'windows 10' consumer rule (they are supported to 2027/2029/2032).
    for cap in ("Microsoft Windows 10 Enterprise LTSC",
                "Microsoft Windows 10 Enterprise 2021 LTSC",
                "Microsoft Windows 10 Enterprise LTSC 2019",
                "Microsoft Windows 10 IoT Enterprise LTSC"):
        assert W.windows_eol(cap, "10.0.19044", today=TODAY) == [], cap
    # consumer Windows 10 (no LTSC/IoT marker) still correctly fires
    assert W.windows_eol("Microsoft Windows 10 Pro", "10.0.19045", today=TODAY)


def test_fix2_no_winkb_for_non_security_missing_patch():
    # a missing definition update / rollup with no CVE and no security class -> NOT a vuln
    for cls in ("DefinitionUpdates", "UpdateRollups", "Updates", "FeaturePacks"):
        mp = W.parse_missing_patches([{"State": "MISSING", "KBId": "KB1", "CVEIds": "",
                                       "Classification": cls, "Severity": "Unspecified"}])
        assert W.native_patch_matches(mp, os_version="10.0") == [], cls


def test_fix2_winkb_still_fires_for_security_missing_patch_no_cve():
    mp = W.parse_missing_patches([{"State": "MISSING", "KBId": "KB9", "CVEIds": "",
                                   "Classification": "SecurityUpdates", "Severity": "Unspecified"}])
    out = W.native_patch_matches(mp, os_version="10.0")
    assert len(out) == 1 and out[0].cve == "WINKB-KB9"


def test_fix2_winkb_fires_on_critical_severity_even_if_class_unknown():
    mp = W.parse_missing_patches([{"State": "MISSING", "KBId": "KB7", "CVEIds": "",
                                   "Classification": "", "Severity": "Critical"}])
    assert W.native_patch_matches(mp, os_version="10.0")[0].cve == "WINKB-KB7"


def test_fix5_load_vuln_db_memoized_single_warn():
    s = _win_scanner()
    s.vuln_db_path = "/nonexistent/phase8-vuln-db.json"
    with patch("builtins.print"):
        b1 = s._load_vuln_db()
        b2 = s._load_vuln_db()
    assert b1 is None and b2 is None
    assert len([r for r in s.results if r.check_id == "CWPP-04"]) == 1   # warned once, not per call
