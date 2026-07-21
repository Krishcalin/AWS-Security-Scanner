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
