#!/usr/bin/env python3
"""aws_sbom_diff.py — pure set-diff of two SBOM snapshots of the same subject.

Given two immutable snapshots (component set + CVE set), compute what changed between
them: components added / removed / version-changed / license-changed, and the CVE delta
(new / fixed). PURE — no I/O, no state, no boto. The CVE delta is a set-diff of the two
*immutable* per-snapshot CVE sets, so it never touches the mutable ingested_vulns merge.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ComponentDelta:
    purl_identity: str
    name: str
    change: str                             # added | removed | version_changed | license_changed
    from_version: Optional[str] = None
    to_version: Optional[str] = None
    from_license: Optional[str] = None
    to_license: Optional[str] = None


@dataclass(frozen=True)
class SbomDiff:
    account: str
    subject_key: str
    from_snapshot: str
    to_snapshot: str
    from_epoch: int
    to_epoch: int
    added: List[ComponentDelta]
    removed: List[ComponentDelta]
    changed: List[ComponentDelta]
    cve_delta: Dict[str, List[str]]         # {"new": [...], "fixed": [...]}


def _delta(c: dict, change: str, **kw) -> ComponentDelta:
    return ComponentDelta(purl_identity=c.get("purl_identity") or "", name=c.get("name") or "",
                          change=change, **kw)


def diff_snapshots(a_components: List[dict], a_cves: List[dict],
                   b_components: List[dict], b_cves: List[dict], *,
                   account: str = "", subject_key: str = "",
                   from_snapshot: str = "", to_snapshot: str = "",
                   from_epoch: int = 0, to_epoch: int = 0) -> SbomDiff:
    """Diff snapshot A (from/older) → snapshot B (to/newer). Components key on
    ``purl_identity`` (version-independent), so a version bump is a *change*, not an
    add+remove pair."""
    a_map = {c["purl_identity"]: c for c in a_components}
    b_map = {c["purl_identity"]: c for c in b_components}

    added = [_delta(b_map[k], "added", to_version=b_map[k].get("version"),
                    to_license=b_map[k].get("license_spdx")) for k in b_map if k not in a_map]
    removed = [_delta(a_map[k], "removed", from_version=a_map[k].get("version"),
                      from_license=a_map[k].get("license_spdx")) for k in a_map if k not in b_map]
    changed: List[ComponentDelta] = []
    for k, av in a_map.items():
        bv = b_map.get(k)
        if bv is None:
            continue
        vchanged = (av.get("version") or "") != (bv.get("version") or "")
        lchanged = (av.get("license_spdx") or "") != (bv.get("license_spdx") or "")
        if not vchanged and not lchanged:
            continue
        changed.append(_delta(
            bv, "version_changed" if vchanged else "license_changed",
            from_version=av.get("version"), to_version=bv.get("version"),
            from_license=av.get("license_spdx"), to_license=bv.get("license_spdx")))

    a_cve = {c["cve"] for c in a_cves}
    b_cve = {c["cve"] for c in b_cves}
    cve_delta = {"new": sorted(b_cve - a_cve), "fixed": sorted(a_cve - b_cve)}

    def key(d: ComponentDelta):
        return (d.name.lower(), d.purl_identity)

    return SbomDiff(
        account=account, subject_key=subject_key, from_snapshot=from_snapshot,
        to_snapshot=to_snapshot, from_epoch=int(from_epoch), to_epoch=int(to_epoch),
        added=sorted(added, key=key), removed=sorted(removed, key=key),
        changed=sorted(changed, key=key), cve_delta=cve_delta)


def to_dict(d: SbomDiff) -> dict:
    out = asdict(d)
    return out
