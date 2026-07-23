#!/usr/bin/env python3
"""aws_ingest.py — ingest external scanner output (SARIF / CycloneDX / SPDX),
normalize onto OverWatch's own vulnerability model, dedup + own, and rank by
ACTUAL attack-path reachability rather than raw CVSS.

Design (grounded in the ingest-reachability spec):

  * **Two lanes, one convergence point** (``aws_sidescan.EnrichedMatch``):
      - FINDINGS lane — the doc already names CVEs (SARIF from Trivy/Grype/Snyk,
        CycloneDX with a ``vulnerabilities[]`` array). Parse → ``IngestedFinding``
        → (B3) enrich against OverWatch's OWN OSV/EPSS/KEV bundle.
      - INVENTORY lane — the doc carries only components/purls (SPDX 2.3, Syft,
        CycloneDX with no ``vulnerabilities[]``). Parse purls → ``Package`` →
        (B3) ``match_vulns`` — OverWatch's own matcher decides the CVEs.

  * **This module (B2) is PURE**: ``dict -> ParsedDoc`` (findings-or-packages +
    subject locator + producing tool). No enrichment, no graph, no I/O. Every
    parser fails soft: a malformed row becomes a ``note``, never a crash or a
    fabricated finding.

  * Every extraction helper is the exact inverse of an ``aws_sidescan`` builder
    (``_purl``/``_lang_purl``/``_ECO``/``_pep503``) so an ingested package keys
    byte-identically against the same OSV feed a native side-scan uses.

CodeQL SARIF is SAST (ruleId = a query id, no CVE, no package) and is EXCLUDED
from the CVE pipeline (spec D7 / invariant I14).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote

from aws_sidescan import (
    Package, EnrichedMatch, _ECO, _pep503, _lang_pkg, _OSV_ECO, prefer_cve, _band,
    _cvss3_base_from_vector, enrich_match, emit_node_vuln_edges,
)

# ── identity dataclasses ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class IngestedFinding:
    """One raw external finding, pre-attribution / pre-enrichment (FINDINGS lane)."""
    cve: str                                # normalized identity (CVE, else GHSA/SNYK id)
    osv_id: str                             # the doc's own id (SNYK-.../GHSA-.../CVE-...)
    source_tool: str                        # trivy | grype | snyk | ...
    source_format: str                      # sarif | cyclonedx
    package: str
    installed_version: str
    fixed_version: Optional[str]
    purl: Optional[str]
    ecosystem: str                          # best-effort; display/enrich hint only
    severity: str                           # doc-supplied band (fallback only)
    cvss_base: Optional[float]              # doc-supplied score (fallback only)
    vex_state: Optional[str] = None         # CycloneDX analysis.state, else None
    raw_locator: str = ""                   # image ref / lockfile path
    doc_id: str = ""


@dataclass(frozen=True)
class VulnInventory:
    """An owned, enriched, reachability-ranked inventory row (built in B3/B5)."""
    account: str
    node_id: str
    node_kind: str
    cve: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    cvss_base: Optional[float]
    epss: Optional[float]
    kev: bool
    exploit_available: Optional[str]
    sources: Tuple[str, ...]                # {"inspector","sidescan","ingest:trivy",...}
    suppressed: bool                        # VEX not_affected / false_positive
    reachable_from_internet: bool
    on_attack_path: bool
    reaches_crown: bool
    terminal_kinds: Tuple[str, ...]
    priority_score: int
    priority_band: str
    driving_path: Optional[str]
    mapping_status: str                     # resolved | unmapped
    first_ingested_epoch: int
    last_seen_epoch: int
    doc_id: str


@dataclass
class ParsedDoc:
    """The pure output of a parser: exactly one lane is populated."""
    lane: str                               # "findings" | "inventory"
    findings: List[IngestedFinding] = field(default_factory=list)
    packages: List[Package] = field(default_factory=list)
    subject_locator: Optional[str] = None   # image ref / bom subject
    source_tool: str = ""
    source_format: str = ""                 # sarif | cyclonedx | spdx
    notes: List[str] = field(default_factory=list)


# ── shared regexes / helpers ─────────────────────────────────────────────────
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.IGNORECASE)
ADVISORY_RE = re.compile(
    r"(?:GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}"
    r"|ALAS\d*-\d{4}-\d+|DLA-\d+-\d+|DSA-\d+-\d+|RUSTSEC-\d{4}-\d+)",
    re.IGNORECASE,
)
_LEVEL_BAND = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}
# purl distro-qualifier id -> _ECO key (Trivy/Grype name divergence from os-release ID)
_DISTRO_ALIAS = {"amazon": "amzn", "amazonlinux": "amzn", "oracle": "rhel",
                 "ol": "rhel", "opensuse": "opensuse-leap"}
# purl `type` -> language origin understood by aws_sidescan (_lang_pkg / cmp_for)
_LANG_TYPE = {"npm": "npm", "pypi": "pypi", "golang": "go", "gem": "gem",
              "cargo": "cargo", "maven": "maven"}


def _text(node) -> str:
    """Read a SARIF multiformatMessageString / message ({text|markdown} or str)."""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        return node.get("text") or node.get("markdown") or ""
    return ""


def doc_content_id(content) -> str:
    """Stable content hash → the ``ingest_docs`` primary key (re-upload = no-op)."""
    if isinstance(content, (bytes, bytearray)):
        raw = bytes(content)
    elif isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ── format sniff + dispatch ──────────────────────────────────────────────────
def sniff_format(doc: dict) -> Optional[str]:
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "spdxVersion" in doc:
        return "spdx"
    if "runs" in doc and (doc.get("version") == "2.1.0"
                          or "sarif" in str(doc.get("$schema", "")).lower()):
        return "sarif"
    return None


def parse_document(doc: dict, doc_id: str = "") -> ParsedDoc:
    """Sniff + route. Raises ValueError on an unrecognizable document."""
    fmt = sniff_format(doc)
    if fmt == "sarif":
        return parse_sarif(doc, doc_id)
    if fmt == "cyclonedx":
        return parse_cyclonedx(doc, doc_id)
    if fmt == "spdx":
        return parse_spdx(doc, doc_id)
    raise ValueError("unrecognized document: expected SARIF 2.1.0, CycloneDX, or SPDX")


# ── purl -> Package (inverse of _purl / _lang_purl) ──────────────────────────
def _eco_from_distro(distro: str) -> str:
    """`?distro=ubuntu-22.04` -> `Ubuntu:22.04` (inverse of parse_os_release's _ECO).

    Resolves the distro id by LONGEST known-key prefix, not a first-hyphen split, so a
    multi-token id whose own name contains a hyphen (``opensuse-leap-15.5``) maps to
    ``openSUSE:Leap:15.5`` and keys byte-identically against the native side-scan."""
    if not distro:
        return ""
    d = distro.lower()
    did, vid = None, ""
    for k in sorted(set(_ECO) | set(_DISTRO_ALIAS), key=len, reverse=True):
        if d == k:
            did = k
            break
        if d.startswith(k + "-"):
            did, vid = k, d[len(k) + 1:]
            break
    if did is None:
        did, _, vid = d.partition("-")
    did = _DISTRO_ALIAS.get(did, did)
    tmpl, _ = _ECO.get(did, ("", ""))
    if not tmpl:
        return ""
    vmaj = vid.split(".")[0] if vid else ""
    vmm = ".".join(vid.split(".")[:2]) if vid else ""
    return tmpl.format(v=vid, vmaj=vmaj, vmm=vmm)


def parse_purl(purl: str) -> Optional[Package]:
    """Reconstruct a ``Package`` from a Package-URL. Returns None if not a purl
    or if no name is present. Low-fidelity OS purls (no ``?distro=``) come back
    with ``ecosystem == ""`` so the caller can flag them, never fabricated."""
    if not purl or not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0]                     # drop subpath
    coord, _, qual_str = body.partition("?")
    quals: Dict[str, str] = {}
    for kv in qual_str.split("&"):
        if "=" in kv:
            k, _, v = kv.partition("=")
            quals[k.strip().lower()] = unquote(v)
    if "@" in coord:                                     # version is never before the last @
        coord, _, version = coord.rpartition("@")
        version = unquote(version)
    else:
        version = ""                                     # version-less purl (valid; no OSV range match)
    parts = [p for p in coord.split("/") if p != ""]
    if len(parts) < 2:
        return None
    typ = parts[0].lower()
    namespace = "/".join(parts[1:-1])
    name = unquote(parts[-1])
    ns = unquote(namespace)
    if not name:
        return None

    # ── language ecosystems ──
    if typ in _LANG_TYPE:
        origin = _LANG_TYPE[typ]
        if origin == "npm":
            full = f"{ns}/{name}" if ns else name          # %40scope -> @scope
            return _lang_pkg("npm", full, version)
        if origin == "pypi":
            return _lang_pkg("pypi", _pep503(name), version)
        if origin == "go":
            full = f"{ns}/{name}" if ns else name
            return _lang_pkg("go", full, version.lstrip("v") if version[:1] == "v" else version)
        if origin == "maven":
            return _lang_pkg("maven", f"{ns}:{name}" if ns else name, version)
        # gem / cargo
        return _lang_pkg(origin, name, version)

    # ── OS package ecosystems ──
    origin = {"deb": "dpkg", "rpm": "rpm", "apk": "apk"}.get(typ)
    if origin:
        eco = _eco_from_distro(quals.get("distro", ""))
        arch = quals.get("arch", "")
        epoch = quals.get("epoch")
        if origin == "rpm" and epoch and ":" not in version:
            version = f"{epoch}:{version}"
        return Package(name=name.lower(), version=version, arch=arch, source="",
                       source_version=version, ecosystem=eco, purl=purl, origin=origin)

    # ── unknown type: best-effort, low fidelity (ecosystem unknown) ──
    return Package(name=name, version=version, arch=quals.get("arch", ""), source="",
                   source_version=version, ecosystem="", purl=purl, origin=typ)


def _eco_hint(purl: Optional[str]) -> str:
    if not purl:
        return ""
    pkg = parse_purl(purl)
    return pkg.ecosystem if pkg else ""


# ── SARIF 2.1.0 (FINDINGS lane) ──────────────────────────────────────────────
def _sarif_rule_for(res: dict, rules: List[dict], rule_by_id: Dict[str, dict]) -> dict:
    rid = res.get("ruleId")
    if rid is not None and rid in rule_by_id:
        return rule_by_id[rid]
    idx = res.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    return {}


def _sarif_locator(res: dict) -> Optional[str]:
    for loc in res.get("locations", []) or []:
        uri = (((loc.get("physicalLocation") or {}).get("artifactLocation") or {})
               .get("uri"))
        if uri:
            return uri
    return None


def _sarif_severity(res: dict, rule: dict) -> Tuple[str, Optional[float]]:
    props = (rule or {}).get("properties") or {}
    cvss: Optional[float] = None
    ss = props.get("security-severity")
    if ss not in (None, "", "undefined", "null"):
        try:
            cvss = float(ss)
        except (TypeError, ValueError):
            cvss = None
    if cvss is None:
        for k in ("cvssv3_baseScore", "cvssV3_baseScore", "cvssv40_baseScore"):
            v = props.get(k)
            if v is not None:
                try:
                    cvss = float(v)
                    break
                except (TypeError, ValueError):
                    pass
    if cvss is not None:
        return _band(cvss), cvss                          # numeric wins (spec R6)
    tags = [str(t).upper() for t in (props.get("tags") or [])]
    for t in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if t in tags:
            return t, None
    band = _LEVEL_BAND.get(str(res.get("level", "")).lower())
    return (band or "MEDIUM"), None


def _regex1(pattern: str, *texts: str) -> Optional[str]:
    for t in texts:
        m = re.search(pattern, t or "", re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _sarif_pkg_generic(res: dict, rule: dict) -> Tuple[str, str, Optional[str]]:
    """Trivy/Grype: package name + installed + fixed live only in free text."""
    msg = _text(res.get("message"))
    help_txt = _text((rule or {}).get("help"))
    full = _text((rule or {}).get("fullDescription"))
    blob = "\n".join((msg, help_txt, full))
    name = _regex1(r"Package:\s*([^\s,]+)", blob)
    installed = _regex1(r"Installed Version:\s*([^\s,]+)", blob)
    fixed = _regex1(r"Fixed Version:\s*([^\s,]+)", blob)
    # Grype message shape: "A <sev> vulnerability in <type> package: <name>, version <ver> ..."
    gm = re.search(r"package:\s*([^,]+),\s*version\s+(\S+)", msg, re.IGNORECASE)
    if gm:
        name = name or gm.group(1).strip()
        installed = installed or gm.group(2).strip()
    return (name or ""), (installed or ""), fixed


def _grype_vulnid(res: dict, rule: dict, pkg_name: str) -> str:
    """Grype ruleId == '{vulnID}-{artifactName}'. Recover vulnID by stripping the
    KNOWN package suffix (pkg names contain hyphens — never split on first '-')."""
    rid = res.get("ruleId") or (rule or {}).get("id") or ""
    if pkg_name and rid.endswith("-" + pkg_name):
        return rid[: -(len(pkg_name) + 1)]
    m = CVE_RE.search(rid) or ADVISORY_RE.search(rid)
    return m.group(0).upper() if m else rid


def _sarif_adapter(tool: str, res: dict, rule: dict, doc_id: str,
                   notes: List[str]) -> List[IngestedFinding]:
    rid = res.get("ruleId") or (rule or {}).get("id") or ""
    band, cvss = _sarif_severity(res, rule)
    locator = _sarif_locator(res) or ""

    if tool.startswith("snyk"):
        name, installed, fixed = "", "", None
        short = _text((rule or {}).get("shortDescription"))
        full = _text((rule or {}).get("fullDescription"))
        m = re.search(r"in\s+([^\s]+?)@([^\s)]+)", full)
        if m:
            name, installed = m.group(1), m.group(2)
        if not name:
            name = _regex1(r"in\s+([A-Za-z0-9_.\-/@]+)\s*$", short) or ""
        cves = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(full + " " +
                    _text((rule or {}).get("help")))))
        out = []
        for cve in (cves or [rid]):                       # keep SNYK id if no CVE
            out.append(IngestedFinding(
                cve=cve, osv_id=rid, source_tool="snyk", source_format="sarif",
                package=name, installed_version=installed, fixed_version=fixed,
                purl=None, ecosystem="", severity=band, cvss_base=cvss,
                raw_locator=locator, doc_id=doc_id))
        return out

    # Trivy / Grype / generic
    name, installed, fixed = _sarif_pkg_generic(res, rule)
    if tool.startswith("grype"):
        vulnid = _grype_vulnid(res, rule, name)
    else:                                                 # trivy + unknown
        vulnid = re.sub(r"^\[[A-Z]+\]\s*", "", rid).strip()   # strip old "[SEV] "
    m = CVE_RE.search(vulnid)
    cve = m.group(0).upper() if m else vulnid.upper()
    if not (CVE_RE.match(cve) or ADVISORY_RE.match(cve)):
        # No advisory identity recoverable (e.g. a CodeQL query id) → skip, note once.
        notes.append(f"sarif: skipped non-advisory result ruleId={rid!r}")
        return []
    return [IngestedFinding(
        cve=cve, osv_id=vulnid, source_tool=(tool or "sarif"), source_format="sarif",
        package=name, installed_version=installed, fixed_version=fixed,
        purl=None, ecosystem="", severity=band, cvss_base=cvss,
        raw_locator=locator, doc_id=doc_id)]


def parse_sarif(doc: dict, doc_id: str = "") -> ParsedDoc:
    findings: List[IngestedFinding] = []
    notes: List[str] = []
    subject: Optional[str] = None
    tools: List[str] = []
    for run in doc.get("runs", []) or []:
        if not isinstance(run, dict):
            notes.append("sarif: skipped malformed run (not an object)")
            continue
        driver = ((run.get("tool") or {}).get("driver")) or {}
        tool = (driver.get("name") or "").lower()
        tools.append(tool)
        rules = driver.get("rules") or []
        rule_by_id: Dict[str, dict] = {}
        for r in rules:
            if isinstance(r, dict) and r.get("id") is not None:
                rule_by_id.setdefault(r["id"], r)
        if tool.startswith("codeql"):
            notes.append("sarif: CodeQL run excluded (SAST, no CVE) — spec D7")
            continue
        for res in run.get("results", []) or []:
            if not isinstance(res, dict):
                notes.append("sarif: skipped malformed result (not an object)")
                continue
            rule = _sarif_rule_for(res, rules, rule_by_id)
            loc = _sarif_locator(res)
            if subject is None and loc:
                subject = loc
            try:
                findings.extend(_sarif_adapter(tool, res, rule, doc_id, notes))
            except Exception as e:                        # never let one bad row kill the doc
                notes.append(f"sarif: skipped malformed result: {e}")
    return ParsedDoc(lane="findings", findings=findings, subject_locator=subject,
                     source_tool=(tools[0] if tools else "sarif"),
                     source_format="sarif", notes=notes)


# ── CycloneDX 1.5/1.6 ────────────────────────────────────────────────────────
def _cdx_index(components: List[dict]) -> Dict[str, dict]:
    idx: Dict[str, dict] = {}

    def walk(clist):
        for c in clist or []:
            if not isinstance(c, dict):
                continue                                  # soft-fail on a malformed row
            ref = c.get("bom-ref")
            if ref:
                idx.setdefault(ref, c)
            walk(c.get("components"))
    walk(components)
    return idx


def _cdx_tool(meta: dict) -> str:
    tools = meta.get("tools")
    if isinstance(tools, dict):                           # 1.5+: {components:[...]}
        comps = tools.get("components") or []
        if comps:
            return (comps[0].get("name") or "").lower()
    if isinstance(tools, list) and tools:                 # 1.4: [{name:...}]
        return (tools[0].get("name") or "").lower()
    return "cyclonedx"


def _cdx_cvss(v: dict) -> Tuple[Optional[str], Optional[float]]:
    ratings = v.get("ratings") or []

    def rank(r: dict) -> int:
        src = ((r.get("source") or {}).get("name") or "").lower()
        method = (r.get("method") or "").upper().replace(":", "").replace(".", "")
        s = 0
        if "nvd" in src:
            s += 4
        if method in ("CVSSV31", "CVSSV3"):
            s += 2
        elif method.startswith("CVSS"):
            s += 1
        return s

    for r in sorted(ratings, key=rank, reverse=True):
        score = r.get("score")
        cvss: Optional[float] = None
        if isinstance(score, (int, float)):
            cvss = float(score)
        else:
            vec = r.get("vector")
            cvss = _cvss3_base_from_vector(str(vec)) if vec else None
        sev = (r.get("severity") or "").upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return sev, cvss
        if cvss is not None:
            return _band(cvss), cvss
    return None, None


def _cdx_fixed(v: dict, comp: dict) -> Optional[str]:
    for aff in v.get("affects", []) or []:
        for ver in aff.get("versions", []) or []:
            if ver.get("status") == "unaffected":
                rng = ver.get("range") or ver.get("version")
                if rng:
                    return str(rng)
    for p in (comp.get("properties") or []):
        if p.get("name") == "aquasecurity:trivy:FixedVersion" and p.get("value"):
            return str(p["value"])
    return v.get("recommendation") or None


def _cdx_component_fields(comp: dict) -> Tuple[str, str, Optional[str]]:
    name = comp.get("name") or ""
    version = comp.get("version") or ""
    purl = comp.get("purl")
    return name, version, purl


def _cdx_vuln(v: dict, idx: Dict[str, dict], doc_id: str, tool: str,
              notes: List[str]) -> List[IngestedFinding]:
    vid = v.get("id") or ""
    refs = [r.get("id") for r in (v.get("references") or []) if r.get("id")]
    cve = prefer_cve({"id": vid, "aliases": refs})
    band, cvss = _cdx_cvss(v)
    vex = ((v.get("analysis") or {}).get("state")) or None
    affects = v.get("affects") or []
    out: List[IngestedFinding] = []
    targets = affects or [{"ref": None}]
    for aff in targets:
        ref = aff.get("ref")
        comp = idx.get(ref, {}) if ref else {}
        name, version, purl = _cdx_component_fields(comp)
        if not name and ref and not comp:
            name = str(ref)                               # opaque ref we couldn't resolve
        out.append(IngestedFinding(
            cve=cve, osv_id=vid, source_tool=tool, source_format="cyclonedx",
            package=name, installed_version=version,
            fixed_version=_cdx_fixed(v, comp),
            purl=purl, ecosystem=_eco_hint(purl),
            severity=(band or _band(cvss)), cvss_base=cvss, vex_state=vex,
            raw_locator=(purl or str(ref or "")), doc_id=doc_id))
    return out


def _components_to_packages(components, notes: List[str]) -> List[Package]:
    out: List[Package] = []
    for c in components:
        if not isinstance(c, dict):
            continue
        purl = c.get("purl")
        if not purl:
            continue
        pkg = parse_purl(purl)
        if pkg is None:
            notes.append(f"inventory: unparseable purl {purl!r}")
            continue
        if pkg.origin in ("dpkg", "rpm", "apk") and not pkg.ecosystem:
            notes.append(f"inventory: low-fidelity-match (no ?distro=) for {purl!r}")
        out.append(pkg)
    return out


def parse_cyclonedx(doc: dict, doc_id: str = "") -> ParsedDoc:
    notes: List[str] = []
    components = doc.get("components") or []
    idx = _cdx_index(components)
    meta = doc.get("metadata") or {}
    subject = ((meta.get("component") or {}).get("purl")
               or (meta.get("component") or {}).get("bom-ref"))
    tool = _cdx_tool(meta)
    vulns = doc.get("vulnerabilities")
    # PRESENT vulnerabilities[] (even empty) = a vuln report → findings lane. An empty
    # list is a scanner's explicit CLEAN verdict and must NOT fall through to the
    # inventory lane (which would re-derive CVEs and overrule that verdict).
    if isinstance(vulns, list):
        findings: List[IngestedFinding] = []
        for v in vulns:
            try:
                if isinstance(v, dict):
                    findings.extend(_cdx_vuln(v, idx, doc_id, tool, notes))
            except Exception as e:
                notes.append(f"cyclonedx: skipped malformed vulnerability: {e}")
        return ParsedDoc(lane="findings", findings=findings, subject_locator=subject,
                         source_tool=tool, source_format="cyclonedx", notes=notes)
    packages = _components_to_packages(idx.values(), notes)
    return ParsedDoc(lane="inventory", packages=packages, subject_locator=subject,
                     source_tool=tool, source_format="cyclonedx", notes=notes)


# ── SPDX 2.3 (INVENTORY lane only — SPDX has no native vuln) ─────────────────
def _spdx_purl(p: dict) -> Optional[str]:
    for ref in p.get("externalRefs") or []:
        cat = str(ref.get("referenceCategory", "")).upper().replace("_", "-")
        if cat == "PACKAGE-MANAGER" and ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def _spdx_tool(creators) -> str:
    for c in creators or []:
        s = str(c)
        if s.lower().startswith("tool:"):
            tool = s.split(":", 1)[1].strip().lower()
            return tool.split("-")[0] or tool
    return "spdx"


def _spdx_subject(doc: dict) -> Optional[str]:
    described = list(doc.get("documentDescribes") or [])
    if not described:
        for rel in doc.get("relationships") or []:
            if rel.get("relationshipType") == "DESCRIBES":
                described.append(rel.get("relatedSpdxElement"))
    if not described:
        return None
    by_id = {p.get("SPDXID"): p for p in doc.get("packages") or [] if isinstance(p, dict)}
    root = by_id.get(described[0])
    return _spdx_purl(root) if root else None


def parse_spdx(doc: dict, doc_id: str = "") -> ParsedDoc:
    notes: List[str] = []
    creators = (doc.get("creationInfo") or {}).get("creators") or []
    tool = _spdx_tool(creators)
    # The DESCRIBES root is the scan SUBJECT (an image / app), not a matchable
    # component — skip it even when it carries an oci/generic purl.
    described = set(doc.get("documentDescribes") or [])
    for rel in doc.get("relationships") or []:
        if rel.get("relationshipType") == "DESCRIBES":
            described.add(rel.get("relatedSpdxElement"))
    packages: List[Package] = []
    for p in doc.get("packages") or []:
        if not isinstance(p, dict):
            continue                                      # soft-fail on a malformed package row
        if p.get("SPDXID") in described:
            continue
        purl = _spdx_purl(p)
        ver = p.get("versionInfo")
        if not purl and (not ver or ver == "NOASSERTION"):
            continue                                      # unversioned / describe-only node
        if not purl:
            notes.append(f"spdx: package {p.get('name')!r} has no purl — skipped")
            continue
        pkg = parse_purl(purl)
        if pkg is None:
            notes.append(f"spdx: unparseable purl {purl!r}")
            continue
        # prefer the explicit versionInfo (carries rpm epoch the purl may omit)
        if ver and ver != "NOASSERTION" and ver != pkg.version and ":" in ver:
            pkg = replace(pkg, version=ver, source_version=ver)
        if pkg.origin in ("dpkg", "rpm", "apk") and not pkg.ecosystem:
            notes.append(f"spdx: low-fidelity-match (no ?distro=) for {purl!r}")
        packages.append(pkg)
    subject = _spdx_subject(doc)
    return ParsedDoc(lane="inventory", packages=packages, subject_locator=subject,
                     source_tool=tool, source_format="spdx", notes=notes)


# ═════════════════════════════════════════════════════════════════════════════
# B3 — NORMALIZE / ENRICH / OWN
#   FINDINGS lane enriches against OverWatch's OWN {osv, epss, kev, exploits}
#   bundle so an ingested CVE gets byte-identical KEV/EPSS to a native match, and
#   (on a CVE the feed knows) native-parity severity/CVSS — never the doc's word.
# ═════════════════════════════════════════════════════════════════════════════

# CycloneDX analysis.state values that SUPPRESS-but-TRACK (owner VEX outranks a
# scanner "exploitable"; the row is retained + counted, never a silent hole).
VEX_SUPPRESS = frozenset({"not_affected", "false_positive",
                          "resolved", "resolved_with_pedigree"})


def vex_suppressed(state: Optional[str]) -> bool:
    return bool(state) and state.lower().strip() in VEX_SUPPRESS


def build_cve_index(records: List[dict]) -> Dict[str, dict]:
    """Index the bundle's raw OSV records by CVE identity: ``{prefer_cve(rec): rec}``
    unioned with ``{alias: rec}`` so a finding keyed by any CVE/GHSA alias resolves
    to the authoritative record. First writer wins (stable). No change to OSVFeed
    (which is (eco,name)/purl-indexed, not CVE-indexed)."""
    idx: Dict[str, dict] = {}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        cve = prefer_cve(rec)
        if cve:
            idx.setdefault(cve, rec)
        for a in [rec.get("id")] + list(rec.get("aliases", []) or []):
            if a:
                idx.setdefault(str(a).upper(), rec)
    return idx


def _finding_package(f: IngestedFinding) -> Package:
    """A minimal Package carrying only the fields enrich_match reads
    (name/version/ecosystem); origin/arch/source are irrelevant to enrichment."""
    return Package(name=f.package, version=f.installed_version, arch="", source="",
                   source_version=f.installed_version, ecosystem=f.ecosystem or "",
                   purl=f.purl or "", origin="")


def enrich_finding(f: IngestedFinding, cve_index: Dict[str, dict],
                   epss, kev, exploits) -> EnrichedMatch:
    """FINDINGS lane → EnrichedMatch, reusing aws_sidescan.enrich_match UNCHANGED.
    cve_index HIT → native-parity severity/CVSS from the OSV record. MISS →
    synthesize a rec from the doc's band/score (display fallback only). Either way
    KEV/EPSS/exploit come solely from the shared bundle (single-source)."""
    pkg = _finding_package(f)
    rec = cve_index.get(f.cve) or cve_index.get(f.osv_id.upper() if f.osv_id else "")
    if rec is None:
        sev_list = ([{"score": f.cvss_base}] if f.cvss_base is not None else [])
        rec = {"id": f.osv_id or f.cve, "aliases": [f.cve],
               "database_specific": {"severity": f.severity},
               "severity": sev_list}
    return enrich_match(rec, pkg, f.fixed_version, epss, kev, exploits)


# ── ownership resolver (pure; nothing silently dropped) ──────────────────────
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}", re.IGNORECASE)
_ARN_ACCT_RE = re.compile(r"^arn:[^:]*:[^:]*:[^:]*:([0-9]{12}):")


def _digest_of(s: Optional[str]) -> Optional[str]:
    m = _DIGEST_RE.search(s or "")
    return m.group(0).lower() if m else None


def _kind_from_arn(arn: str) -> str:
    if ":ec2:" in arn and ":instance/" in arn:
        return "EC2Instance"
    if ":lambda:" in arn and ":function:" in arn:
        return "LambdaFunction"
    if ":ecr:" in arn and ":repository/" in arn:
        return "ECRImage"
    if arn.startswith("arn:aws:s3:"):
        return "S3Bucket"
    return "Unknown"


def _image_repo_tag(s: Optional[str]) -> Optional[dict]:
    """Parse an image ref into {repo, tag}, preserving the FULL namespaced repo path
    (an ECR repositoryName may contain slashes, e.g. ``team/api``) — only the registry
    host and the tag are stripped, so it matches the native ECRImage node's
    ``repository`` prop for a namespaced repo."""
    if not s:
        return None
    s = re.sub(r"\s*\(.*\)\s*$", "", s).strip()          # strip Trivy " (debian 12)"
    if s.startswith("pkg:oci/"):
        body = s[len("pkg:oci/"):].split("?")[0].split("@")[0]
        return {"repo": body, "tag": None}
    body = s.split("@")[0]
    if "/" in body:                                      # drop a leading registry host
        head, rest = body.split("/", 1)
        if "." in head or ":" in head or head == "localhost":
            body = rest
    repo, tag = body, None
    last = body.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = body.rsplit(":", 1)
    return {"repo": repo, "tag": tag}


def resolve_owner(graph, account: str, target_resource: Optional[str] = None,
                  subject_locator: Optional[str] = None) -> Tuple[str, str, str]:
    """Resolve an ingested doc to the graph node that OWNS its findings, returning
    ``(node_id, node_kind, mapping_status)``. Order: explicit target_resource, then
    the doc's subject locator. Image refs bind by immutable DIGEST first, then
    repo:tag. Unresolvable → a synthetic unmapped ECRImage node (flagged, never
    dropped — invariant I6). Raises ValueError on a cross-account ARN target."""
    candidates = [c for c in (target_resource, subject_locator) if c]

    # 1. explicit / subject ARN — exact graph node, else infer kind from the ARN.
    for c in candidates:
        if c.startswith("arn:"):
            m = _ARN_ACCT_RE.match(c)
            if m and account and m.group(1) != account:
                raise ValueError(f"cross-account target ARN {c} != account {account}")
            nd = graph.node(c)
            if nd:
                return c, nd["kind"], "resolved"
            return c, _kind_from_arn(c), "resolved"

    # 2. image by DIGEST (immutable) — join whatever node id the native scan built.
    for c in candidates:
        dig = _digest_of(c)
        if dig:
            for n in graph.nodes("ECRImage"):
                props = n.get("props") or {}
                if dig in n["id"].lower() or str(props.get("digest", "")).lower() == dig:
                    return n["id"], "ECRImage", "resolved"

    # 3. image by repo:tag.
    for c in candidates:
        ref = _image_repo_tag(c)
        if ref and ref.get("repo"):
            for n in graph.nodes("ECRImage"):
                props = n.get("props") or {}
                if props.get("repository") == ref["repo"] and (
                        not ref.get("tag") or f":{ref['tag']}" in n["id"]):
                    return n["id"], "ECRImage", "resolved"

    # 4. fallback: synthetic unmapped node (exploitability retained, no reach earned).
    key = _digest_of(" ".join(candidates)) or (candidates[0] if candidates else "unknown")
    return f"ingest:image:{key}", "ECRImage", "unmapped"


def emit_ingested_edges(graph, node_id: str, node_kind: str,
                        matches: List[EnrichedMatch], doc_id: str, tool: str) -> int:
    """Attach owned matches as HAS_VULN edges tagged ``ingest:<tool>`` provenance.
    MERGE-idempotent against native edges (aws_graph MERGE on (node, cve))."""
    return emit_node_vuln_edges(graph, node_id, node_kind, matches,
                                snapshot_id=f"ingest:{doc_id}",
                                scan_source=f"ingest:{tool}")


# ═════════════════════════════════════════════════════════════════════════════
# B5 — REACHABILITY RE-RUN (rank by ACTUAL attack-path reachability, not CVSS)
#   Rebuild the graph from stored graph_full, emit the ingested HAS_VULN edges,
#   then RE-RUN the native enumerate_paths with the same pure predicates. A
#   membership check on the STORED paths would structurally miss the path an
#   ingested KEV newly reveals — so we re-run and reuse the whole scoring stack.
# ═════════════════════════════════════════════════════════════════════════════
from aws_graph import SecurityGraph                        # noqa: E402  (kept near use)
import aws_correlate                                       # noqa: E402
import aws_deepplane                                       # noqa: E402


def _exploitability_only_score(m: EnrichedMatch) -> int:
    """A CVE that reaches NO attack path is ranked by intrinsic exploitability
    ONLY, capped well below the reachability bands so an isolated high-CVSS CVE
    ranks among the noise (THE thesis: reachability outranks CVSS)."""
    if m.kev:
        return 45                                          # MEDIUM — notable but not reachable
    if str(m.exploit_available or "").upper() == "YES":
        return 40
    if isinstance(m.epss, (int, float)) and m.epss >= aws_deepplane.EPSS_HIGH:
        return 35
    c = m.cvss_base or 0.0
    return 30 if c >= 9 else 25 if c >= 7 else 15 if c >= 4 else 8


def _ingest_predicates(g):
    admin_id = next((n["id"] for n in g.nodes("AdminCapability")), None)
    crown_ids = aws_correlate.crown_nodes(g)
    threatened = {e["dst"] for e in g.edges("THREAT_ON")}
    is_uncond = (lambda e: not e["props"].get("conditioned")
                 and not e["props"].get("has_condition"))
    return admin_id, crown_ids, is_uncond, (lambda nid: nid in threatened)


def compute_reachability_verdicts(graph_dict: Optional[dict], owned: List[dict]
                                  ) -> Tuple[Dict[Tuple[str, str], dict], "SecurityGraph"]:
    """Rebuild ``graph_dict`` → emit each non-suppressed owned match as a HAS_VULN
    edge → re-run ``enumerate_paths`` → per-(node,cve) reachability verdict.

    ``owned`` items: ``{"node_id","node_kind","match":EnrichedMatch,"suppressed":bool,
    "tool":str,"doc_id":str}``. Returns ``({(node_id,cve): verdict}, graph)``. When
    the graph has no ``internet`` node (no scan yet), verdicts collapse to an
    exploitability-only band (reachability unknown, surfaced honestly)."""
    g = SecurityGraph.from_dict(graph_dict or {})
    for o in owned:
        if not o.get("suppressed"):
            emit_ingested_edges(g, o["node_id"], o["node_kind"], [o["match"]],
                                o.get("doc_id", ""), o.get("tool", ""))

    paths: List = []
    reach_internet: set = set()
    if g.node("internet") is not None:
        admin_id, crown_ids, is_uncond, node_has_threat = _ingest_predicates(g)
        paths = aws_correlate.enumerate_paths(
            g, {"internet"}, admin_id, crown_ids, is_uncond,
            aws_deepplane.is_exploitable, node_has_threat)
        reach_internet = set(g.reachable("internet", aws_correlate.E_PATH,
                                         max_hops=64).keys())

    from collections import defaultdict
    node_paths: Dict[str, list] = defaultdict(list)
    for p in paths:
        for nid in p.nodes:
            node_paths[nid].append(p)
    # Reverse RUNS_IMAGE: an ECRImage is never itself a path hop, but the workload
    # that RUNS_IMAGE it inherits the image's HAS_VULN exploit signal (mirrors
    # aws_correlate._iter_vuln_edges). So a CVE owned BY an image is on-path iff any
    # workload running that image is on-path.
    img_runners: Dict[str, list] = defaultdict(list)
    for e in g.edges("RUNS_IMAGE"):
        img_runners[e["dst"]].append(e["src"])

    verdicts: Dict[Tuple[str, str], dict] = {}
    for o in owned:
        m = o["match"]
        key = (o["node_id"], m.cve)
        if key in verdicts:
            continue
        # A VEX-suppressed CVE emitted no edge and must never earn reachability —
        # it is retained + counted but ranked off-path (invariant I11), even when a
        # non-suppressed sibling CVE (or an admin path) puts its owning node on a path.
        if o.get("suppressed"):
            ps: list = []
        else:
            attribution = [o["node_id"]] + img_runners.get(o["node_id"], [])
            seen_p, ps = set(), []
            for n in attribution:
                for p in node_paths.get(n, []):
                    if id(p) not in seen_p:
                        seen_p.add(id(p))
                        ps.append(p)
        term_kinds = sorted({p.terminal_kind for p in ps})
        if ps:
            best = max(ps, key=lambda p: p.score)
            score = int(best.score)
            driving = " -> ".join(best.nodes)
        else:
            score = _exploitability_only_score(m)
            driving = None
        verdicts[key] = {
            "on_attack_path": bool(ps),
            "reaches_crown": "data" in term_kinds,
            "terminal_kinds": term_kinds,
            "reachable_from_internet": o["node_id"] in reach_internet,
            "priority_score": score,
            "priority_band": aws_correlate._severity(score),
            "driving_path": driving,
            "suppressed": bool(o.get("suppressed")),
        }
    return verdicts, g


def diff_reachability(old_rows: List[dict], verdicts: Dict[Tuple[str, str], dict]
                      ) -> Tuple[List[dict], List[dict]]:
    """Compare a prior verdict snapshot to the fresh one → the per-CVE deltas that
    drive the drift digest's ``newly_on_path`` signal (a newly-REACHABLE KEV) and
    its inverse. ``old_rows`` are stored ``ingested_vulns`` dicts."""
    old = {(r["node_id"], r["cve"]): r for r in old_rows}
    became_reachable, became_unreachable = [], []
    for (node, cve), v in verdicts.items():
        # A suppressed CVE is never a reachability signal (I11) — compute_reachability_verdicts
        # already forces it off-path, but guard here too so a stale prior row can't leak it.
        if v.get("suppressed") or old.get((node, cve), {}).get("suppressed"):
            continue
        was = bool(old.get((node, cve), {}).get("on_attack_path"))
        now = bool(v.get("on_attack_path"))
        item = {"node_id": node, "cve": cve, **v}
        if now and not was:
            became_reachable.append(item)
        elif was and not now:
            became_unreachable.append(item)
    return became_reachable, became_unreachable
