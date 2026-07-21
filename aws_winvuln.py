"""Windows agentless OS-vulnerability signal — Phase 8 "Windows CWPP" (the final phase).

A PURE, offline, deterministic module that closes the Linux-only side-scan blind spot
WITHOUT reading a filesystem: it turns AWS Systems Manager patch-compliance data
(``ssm:DescribeInstancePatches`` / ``DescribeInstancePatchStates`` /
``DescribeInstanceInformation``) into HAS_VULN edges byte-identical in shape to the
Inspector / side-scan / managed-EOL edges, plus a lifecycle EOL signal and — the headline —
an explicit UNDETERMINED verdict so a Windows host is NEVER silently reported clean.

WHY SSM PATCH COMPLIANCE, NOT A HOME-GROWN KB->CVE FEED
------------------------------------------------------
``DescribeInstancePatches`` returns, per host, the patches AWS Patch Manager evaluated
against a baseline — and each ``PatchComplianceData`` carries the **real MSRC CVE ids**
(``CVEIds``) that its KB fixes. AWS has already done the KB->CVE mapping. So the primary
signal is AWS-native real CVE ids for the *actually-missing* KBs — sidestepping the
"Windows KB->CVE feed fidelity is lower than Linux OSV" risk. A home-grown supersedence
matcher over the *sparse* installed-KB inventory (a monthly cumulative update collapses
to one HotFixId while silently including hundreds of fixes) would false-positive patched
CVEs, so it is deliberately DEFERRED (see aws_live_scanner Phase-8 notes).

The **Windows-EOL** table is the same honest synthetic-lifecycle signal proven in
``aws_engine_eol``: an end-of-support DATE is a public deterministic fact (FP ~= 0). The
synthetic id is namespaced ``WINEOL-<release>`` so it never collides with a real CVE node.

DETERMINISM
-----------
``today`` is a REQUIRED keyword — this module never calls ``date.today()``, so a scan's
verdict is a pure function of its inputs. Tests inject a fixed date. The EOL DATES below
are DATA (refreshable as Microsoft lifecycle calendars move); the correctness tests lock
the ALGORITHM (floor-safe threshold + injectable ``today`` + longest-caption-needle
disambiguation across the shared ``10.0`` build major), not the specific dates.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import AbstractSet, Dict, List, Mapping, Optional, Tuple

from aws_sidescan import EnrichedMatch

# ── data models ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class MissingPatch:
    """One open (not-installed) patch from DescribeInstancePatches, with its real CVEs."""
    kb_id: str
    cve_ids: Tuple[str, ...]      # normalized real CVE ids parsed from CVEIds
    classification: str
    severity: str                 # raw MSRC severity ('Critical'/'Important'/'Moderate'/'Low'/...)
    state: str                    # normalized UPPER, e.g. 'MISSING' / 'FAILED'


@dataclass(frozen=True)
class WindowsInventory:
    """Optional context/SBOM from SSM inventory (AWS:InstanceInformation / :WindowsUpdate /
    :Application). ``installed_kbs`` is for the DEFERRED authoritative matcher only;
    ``software`` is report-SBOM only (Phase 8 makes no app->CVE claims)."""
    os_caption: str               # DescribeInstanceInformation.PlatformName
    os_version: str               # DescribeInstanceInformation.PlatformVersion, e.g. '10.0.17763'
    installed_kbs: Tuple[str, ...]
    software: Tuple[Tuple[str, str], ...]   # (name, version)


@dataclass(frozen=True)
class WinEolEntry:
    """One Windows end-of-support cutoff. A host whose PlatformName contains a
    ``caption_needle`` and is scanned on/after ``eol`` is end-of-life. ``caption_needles``
    are matched longest-first so the shared ``10.0`` build major (Win10/11/Server
    2016/2019/2022) is disambiguated by the human-readable release name."""
    release: str                  # slug, e.g. 'windows-server-2012-r2'
    caption_needles: Tuple[str, ...]   # lowercased substrings of PlatformName
    eol: date
    severity: str
    recommend: str                # -> EnrichedMatch.fixed_version


# ── bundled Windows end-of-support table (public-calendar DATA; refreshable) ──
# Floor-safe: a rule fires only when ``today >= eol``, so future dates simply never fire
# and a stale table under-reports (FN) rather than false-alarms (FP). Needles are matched
# longest-first, so 'server 2012 r2' wins over the 'server 2012 ' non-R2 rule.
WINDOWS_EOL: Tuple[WinEolEntry, ...] = (
    WinEolEntry("windows-server-2003",    ("server 2003",),      date(2015, 7, 14), "HIGH", "Windows Server 2019 or later"),
    WinEolEntry("windows-server-2008",    ("server 2008",),      date(2020, 1, 14), "HIGH", "Windows Server 2019 or later"),
    WinEolEntry("windows-server-2008-r2", ("server 2008 r2",),   date(2020, 1, 14), "HIGH", "Windows Server 2019 or later"),
    WinEolEntry("windows-server-2012",    ("server 2012 ",),     date(2023, 10, 10), "HIGH", "Windows Server 2019 or later"),
    WinEolEntry("windows-server-2012-r2", ("server 2012 r2",),   date(2023, 10, 10), "HIGH", "Windows Server 2019 or later"),
    WinEolEntry("windows-server-2016",    ("server 2016",),      date(2027, 1, 12), "HIGH", "Windows Server 2022 or later"),
    WinEolEntry("windows-server-2019",    ("server 2019",),      date(2029, 1, 9),  "HIGH", "a supported release"),
    WinEolEntry("windows-server-2022",    ("server 2022",),      date(2031, 10, 14), "HIGH", "a supported release"),
    WinEolEntry("windows-7",              ("windows 7",),        date(2020, 1, 14), "HIGH", "Windows 10/11"),
    WinEolEntry("windows-8.1",            ("windows 8.1",),      date(2023, 1, 10), "HIGH", "Windows 10/11"),
    WinEolEntry("windows-10",             ("windows 10",),       date(2025, 10, 14), "HIGH", "Windows 11"),
    WinEolEntry("windows-11",             ("windows 11",),       date(2031, 10, 14), "MEDIUM", "a supported feature update"),
)

_ECOSYSTEM = "windows-os"
_CVE_RX = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
# States that mean the fix is genuinely NOT applied. INSTALLED* / NOT_APPLICABLE are clean;
# AVAILABLE_SECURITY_UPDATE means a newer optional update exists (not a compliance gap).
_OPEN_STATES = frozenset({"MISSING", "FAILED"})
_SEV_MAP = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM",
            "low": "LOW", "unspecified": "MEDIUM"}
# Only these classifications (or a Critical/Important MSRC severity) justify the no-CVE
# KB-level fallback — so a missing Defender definition / update-rollup / feature update with
# no CVE is never flagged as a vulnerability (a false positive).
_SECURITY_CLASSES = frozenset({"securityupdates", "criticalupdates"})


def _map_sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").strip().lower(), "MEDIUM")


def _is_security_patch(mp: "MissingPatch") -> bool:
    """A missing patch worth a no-CVE KB-level finding: a security/critical classification
    OR a Critical/Important MSRC severity. Guards against flagging non-security missing
    patches (definition updates, rollups, feature updates) that carry no CVE."""
    return ((mp.classification or "").strip().lower() in _SECURITY_CLASSES
            or _map_sev(mp.severity) in ("CRITICAL", "HIGH"))


# ── pure parsers ─────────────────────────────────────────────────────────────
def parse_missing_patches(patches: List[Dict]) -> List[MissingPatch]:
    """From ``DescribeInstancePatches['Patches']`` -> the open (missing/failed) patches with
    their real CVE ids. ``State`` is normalized case-insensitively (the wire is mixed-case
    despite the UPPER model enum). ``CVEIds`` is split on ``[,\\s]+`` and filtered to real
    ``CVE-YYYY-NNNN`` ids. Installed / not-applicable / available-optional states are skipped
    (no false positive). Defensive on absent fields."""
    out: List[MissingPatch] = []
    for p in patches or []:
        if not isinstance(p, dict):
            continue
        state = str(p.get("State", "")).strip().upper()
        if state not in _OPEN_STATES:
            continue
        cve_ids = tuple(dict.fromkeys(   # de-dup, preserve order
            m.group(0).upper() for m in _CVE_RX.finditer(str(p.get("CVEIds", "") or ""))))
        out.append(MissingPatch(
            kb_id=str(p.get("KBId", "") or p.get("Title", "") or "unknown"),
            cve_ids=cve_ids,
            classification=str(p.get("Classification", "") or ""),
            severity=str(p.get("Severity", "") or ""),
            state=state))
    return out


def _inv_get(entry: Dict[str, str], *keys: str) -> str:
    """Case/name-defensive lookup over an opaque ListInventoryEntries content map."""
    if not isinstance(entry, dict):
        return ""
    lower = {str(k).lower(): v for k, v in entry.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v:
            return str(v)
    return ""


def parse_windows_inventory(dii_item: Optional[Dict[str, str]],
                            win_update_entries: Optional[List[Dict[str, str]]] = None,
                            app_entries: Optional[List[Dict[str, str]]] = None
                            ) -> WindowsInventory:
    """Pure. Assemble a WindowsInventory from DescribeInstanceInformation (OS caption/version)
    + optional SSM inventory entries (AWS:WindowsUpdate HotFixId, AWS:Application Name/Version).
    Defensive on the opaque, AWS-runtime inventory key names/case."""
    dii = dii_item or {}
    kbs = tuple(dict.fromkeys(
        _norm_kb(_inv_get(e, "HotFixId", "HotfixId", "Id"))
        for e in (win_update_entries or [])
        if _inv_get(e, "HotFixId", "HotfixId", "Id")))
    software = tuple((_inv_get(e, "Name"), _inv_get(e, "Version"))
                     for e in (app_entries or []) if _inv_get(e, "Name"))
    return WindowsInventory(
        os_caption=str(dii.get("PlatformName", "") or ""),
        os_version=str(dii.get("PlatformVersion", "") or ""),
        installed_kbs=tuple(k for k in kbs if k),
        software=software)


def _norm_kb(kb: str) -> str:
    """'kb5034441' / '5034441' -> 'KB5034441'."""
    kb = (kb or "").strip().upper()
    if not kb:
        return ""
    return kb if kb.startswith("KB") else "KB" + kb.lstrip("KB")


# ── pure matchers (-> EnrichedMatch, feeds emit_node_vuln_edges byte-identically) ──
def native_patch_matches(missing: List[MissingPatch], *, os_version: str,
                         epss: Mapping[str, float] = {},
                         kev: AbstractSet[str] = frozenset(),
                         exploits: AbstractSet[str] = frozenset()) -> List[EnrichedMatch]:
    """One EnrichedMatch per REAL CVE in each open MissingPatch (AWS Patch Manager already
    mapped the KB -> its MSRC CVEs). KEV/EPSS/exploit enrichment from the optional --vuln-db
    bundle. A missing patch with no CVE ids still yields one KB-level match so the host is
    never silently clean when a security KB is missing."""
    out: List[EnrichedMatch] = []
    for mp in missing or []:
        sev = _map_sev(mp.severity)
        if mp.cve_ids:
            # AWS already mapped this KB to CVEs -> it IS a security fix; emit unconditionally.
            for cve in mp.cve_ids:
                out.append(EnrichedMatch(
                    cve=cve, osv_id="", package=f"windows-kb:{mp.kb_id}",
                    installed_version=os_version or "?", fixed_version=mp.kb_id,
                    severity=sev, cvss_base=None, epss=epss.get(cve),
                    kev=cve in kev, exploit_available="YES" if cve in exploits else None,
                    ecosystem=_ECOSYSTEM))
        elif _is_security_patch(mp):
            # KB-level fallback ONLY for a missing SECURITY/critical KB with no enumerated CVE.
            # A non-security missing patch (definition update / rollup / feature update) is
            # skipped so it is never a phantom vulnerability.
            out.append(EnrichedMatch(
                cve=f"WINKB-{mp.kb_id}", osv_id="", package=f"windows-kb:{mp.kb_id}",
                installed_version=os_version or "?", fixed_version=mp.kb_id,
                severity=sev, cvss_base=None, epss=None, kev=False,
                exploit_available=None, ecosystem=_ECOSYSTEM))
    return out


def _match_eol_entry(os_caption: str) -> Optional[WinEolEntry]:
    """The WINDOWS_EOL entry whose LONGEST caption_needle is a substring of PlatformName,
    or None. Longest-needle wins so 'server 2012 r2' beats the 'server 2012 ' non-R2 rule."""
    cap = (os_caption or "").lower()
    best: Optional[Tuple[int, WinEolEntry]] = None
    for e in WINDOWS_EOL:
        for n in e.caption_needles:
            if n in cap and (best is None or len(n) > best[0]):
                best = (len(n), e)
    return best[1] if best else None


def windows_eol(os_caption: str, os_version: str, *, today: date) -> List[EnrichedMatch]:
    """SHIPS-NOW lifecycle signal (FP ~= 0). 0-or-1 synthetic EnrichedMatch with a namespaced
    ``WINEOL-<release>`` id (never collides with a real CVE node). Empty when the caption
    matches no rule OR the rule's ``eol`` is in the future (floor-safe: table lag -> FN not FP)."""
    e = _match_eol_entry(os_caption)
    if e is None or today < e.eol:
        return []
    # LTSC / LTSB / IoT client editions have much longer, edition-specific support than the
    # mainstream client rule their caption would otherwise match (e.g. Win10 LTSC 2021 -> 2027,
    # IoT Enterprise LTSC 2021 -> 2032) — suppress rather than false-positive. Floor-safe: the
    # rare genuinely-EOL LTSC host is still caught by the native missing-patch signal (an EOL
    # host stops receiving updates -> DescribeInstancePatches reports missing CVE-bearing KBs).
    cap = (os_caption or "").lower()
    if e.release in ("windows-10", "windows-11") and any(
            k in cap for k in ("ltsc", "ltsb", "iot")):
        return []
    label = (os_caption or e.release).strip()
    if os_version:
        label = f"{label} ({os_version})"
    return [EnrichedMatch(
        cve=f"WINEOL-{e.release}", osv_id="", package=f"windows:{e.release}",
        installed_version=label, fixed_version=e.recommend, severity=e.severity,
        cvss_base=None, epss=None, kev=False, exploit_available=None,
        ecosystem=_ECOSYSTEM)]


def _dedup_by_cve(matches: List[EnrichedMatch]) -> List[EnrichedMatch]:
    """Keep the first EnrichedMatch per cve id (a CVE can appear across several missing KBs).
    Real CVEs and synthetic WINEOL-/WINKB- ids are namespaced apart, so they never collide."""
    seen: set = set()
    out: List[EnrichedMatch] = []
    for m in matches:
        if m.cve in seen:
            continue
        seen.add(m.cve)
        out.append(m)
    return out


def match_windows_vulns(missing: List[MissingPatch], os_caption: str, os_version: str, *,
                        today: date, epss: Mapping[str, float] = {},
                        kev: AbstractSet[str] = frozenset(),
                        exploits: AbstractSet[str] = frozenset()) -> List[EnrichedMatch]:
    """All Windows OS-vuln EnrichedMatches for one host: native missing-patch CVEs (primary)
    + the synthetic EOL lifecycle signal. De-duplicated by cve id."""
    out = native_patch_matches(missing, os_version=os_version, epss=epss, kev=kev,
                               exploits=exploits) + windows_eol(os_caption, os_version, today=today)
    return _dedup_by_cve(out)


# ── verdict (AGGREGATE-PASS-MUST-COUNT: CLEAN requires a positive, complete read) ──
def assess(*, is_managed: bool, ping_online: bool, patch_read_ok: bool,
           patch_state: Optional[Dict], matches: List[EnrichedMatch]) -> str:
    """Return ``'VULN' | 'CLEAN' | 'UNDETERMINED'`` for one Windows host. CLEAN is only ever
    returned on a POSITIVE, complete assessment (SSM-managed + agent online + patch state
    readable with all compliance counts present and zero, and no EOL match) — so a denied
    read, an unmanaged host, or a missing-but-undetailed host degrades to UNDETERMINED, never
    a phantom clean. Mirrors the aggregate-pass-must-count rule used across the scanner."""
    if matches:
        return "VULN"                       # a real missing-patch CVE or an EOL host
    if not (is_managed and ping_online):
        return "UNDETERMINED"               # can't see the host via SSM -> not clean
    if not patch_read_ok or patch_state is None:
        return "UNDETERMINED"               # denied/failed patch read -> not clean
    crit = patch_state.get("CriticalNonCompliantCount")
    sec = patch_state.get("SecurityNonCompliantCount")
    miss = patch_state.get("MissingCount")
    if crit is None or sec is None or miss is None:
        return "UNDETERMINED"               # incomplete state -> not clean
    if crit or sec:
        return "VULN"                       # counts-only non-compliance (no per-CVE detail)
    if miss:
        return "UNDETERMINED"               # missing-but-undetailed -> not clean
    return "CLEAN"
