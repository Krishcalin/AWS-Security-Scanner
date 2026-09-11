#!/usr/bin/env python3
"""Generate the three CSA CCM matrix files under ``compliance/ccm/``.

WHY THIS IS A GENERATOR AND NOT THREE HAND-EDITED FILES
-------------------------------------------------------
The three matrix tabs are keyed by the same control-id sequence, so the id
appears 18 times across the set (3 + 6 + 9 sections).  Hand-editing them lets
the three drift apart with nothing detecting it, which is the defect
``tests/test_ccm_matrix.py`` exists to prevent.  The id universe is declared
once here, every section is rendered from it, and drift becomes unrepresentable.

The per-section data is held as EXCEPTION LISTS over a documented default,
because that is what the data actually is: "Shared" covers 83-89% of the
ownership matrix and ``true`` covers most of the two relevance matrices.
Storing 3,726 rows to express ~600 decisions hides the decisions.

WHAT THIS CORRECTS RELATIVE TO THE SOURCE SPREADSHEET EXPORT
------------------------------------------------------------
1. ``I&S`` -> ``IVS``.  There is no ``I&S`` domain in the CCM.  The source used
   it for Infrastructure & Virtualization Security: it carries 9 controls (IVS
   has 9) and sorts between IPY and LOG, which is exactly where IVS belongs.
   ``compliance/crosswalk.json`` already cites IVS-03/04/06/09, so the source
   spelling silently failed to join on 162 rows (9 controls x 18 sections).

2. ``IAM-16`` restored to the id universe.  The source stopped at IAM-15.  IAM
   is the only domain in the export that is SHORT of the published CCM; every
   other divergence is a surplus, which points at a dropped row rather than a
   version difference.  ``compliance/crosswalk.json`` cites IAM-16 today.

   Its value is NOT invented.  Every IAM-16 row is emitted as ``null`` and the
   id is named in the ``unresolved`` block of each file's header, so the gap is
   visible IN the data rather than absent from it.  A guessed value here would
   be indistinguishable from an authored one, which is the whole failure mode.

3. A provenance header on every file: framework, version, source, retrieval
   date, licence, and the value vocabulary as an explicit enum.  The source
   export carried none of this -- see ``version_status`` below, which is
   ``unverified`` on purpose and must not be stamped with a guess.

Run:  python scripts/gen_ccm_matrix.py [--check]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "compliance", "ccm")

# --------------------------------------------------------------------------
# The control-id universe, declared once.
#
# Domain -> highest index.  The numbering is dense: every domain runs 01..n
# with no gaps.  IAM is 16 here because IAM-16 is restored (see note 2 above);
# the source export carried 15.
# --------------------------------------------------------------------------
DOMAINS: list[tuple[str, int]] = [
    ("A&A", 6),
    ("AIS", 8),
    ("BCR", 11),
    ("CCC", 9),
    ("CEK", 21),
    ("DCS", 18),
    ("DSP", 19),
    ("GRC", 8),
    ("HRS", 13),
    ("IAM", 16),
    ("IPY", 4),
    ("IVS", 9),
    ("LOG", 14),
    ("SEF", 10),
    ("STA", 16),
    ("TVM", 12),
    ("UEM", 14),
]

# Ids present in the id universe but carrying no value in the source export.
# Emitted as null rather than guessed, and named in every file header.
UNRESOLVED: dict[str, str] = {
    "IAM-16": (
        "absent from the source export (which ended at IAM-15) but cited by "
        "compliance/crosswalk.json; value must be authored, never inferred"
    ),
}

CONTROL_IDS: list[str] = [
    f"{dom}-{i:02d}" for dom, n in DOMAINS for i in range(1, n + 1)
]


def _ids(spec: str) -> list[str]:
    """Expand "DCS-02..03 DCS-06 HRS-08..13" into explicit control ids."""
    out: list[str] = []
    for token in spec.split():
        if ".." in token:
            head, hi = token.split("..")
            dom, lo = head.rsplit("-", 1)
            for i in range(int(lo), int(hi) + 1):
                out.append(f"{dom}-{i:02d}")
        else:
            out.append(token)
    for cid in out:
        if cid not in CONTROL_IDS:
            raise SystemExit(f"unknown control id in exception list: {cid}")
    return out


# --------------------------------------------------------------------------
# ownership.yaml -- default "Shared", exceptions below.
# --------------------------------------------------------------------------
_DCS_PROVIDER = "DCS-01..05 DCS-08..18"

OWNERSHIP_DEFAULT = "Shared"
OWNERSHIP: list[tuple[str, dict[str, str]]] = [
    ("IaaS", {
        "CSP-Owned": f"BCR-11 {_DCS_PROVIDER} DSP-17..18 IVS-02 LOG-13 STA-04..05",
    }),
    ("PaaS", {
        "CSP-Owned": f"BCR-11 {_DCS_PROVIDER} DSP-17..18 IVS-01..02 IVS-04 "
                     f"LOG-06 LOG-13 STA-04..05",
    }),
    ("SaaS", {
        "CSP-Owned": f"AIS-04 AIS-06 BCR-11 CEK-05 {_DCS_PROVIDER} DSP-18 "
                     f"IVS-01..04 IVS-06 IVS-08..09 LOG-06 LOG-13 "
                     f"STA-04..05 TVM-06..07",
        "CSC-Owned": "DSP-17",
    }),
]

# --------------------------------------------------------------------------
# architectural-relevance.yaml -- default true, false-list below.
# --------------------------------------------------------------------------
ARCHITECTURAL_DEFAULT = True
ARCHITECTURAL: list[tuple[str, str]] = [
    ("Phys",
     "AIS-08 BCR-08 DCS-02..03 DCS-06 DCS-08..10 DSP-04 DSP-06 DSP-09..11 "
     "DSP-14..18 HRS-01 HRS-08..13 IVS-05 IVS-09 UEM-02..14"),
    ("Network",
     "A&A-01 BCR-08 DCS-03 DCS-06 DCS-08..10 DCS-12 DSP-04 DSP-06 DSP-09 "
     "DSP-11 DSP-14..18 HRS-03 HRS-05..13 IVS-05"),
    ("Compute",
     "A&A-01 BCR-08 DCS-02..03 DCS-06 DCS-08..10 DCS-12..13 DSP-04 DSP-06 "
     "DSP-09 DSP-11 DSP-14..18 HRS-01 HRS-03 HRS-05..13 IVS-03 IVS-05 IVS-09"),
    ("Storage",
     "A&A-01 AIS-08 DCS-02..03 DCS-06 DCS-08..10 DCS-12..13 DSP-04 DSP-06 "
     "DSP-09..11 DSP-14..15 DSP-17..18 HRS-03 HRS-08..13 IVS-03 IVS-05 "
     "IVS-09 UEM-02"),
    ("App",
     "BCR-08 BCR-11 DCS-02..03 DCS-06 DCS-08..14 DSP-04 DSP-06 DSP-09..11 "
     "DSP-14..18 HRS-03 HRS-08..13 IVS-01..04 IVS-06 IVS-09"),
    ("Data",
     "BCR-11 DCS-02..03 DCS-06 DCS-09..14 HRS-03 HRS-08..13 IVS-01..06 "
     "IVS-08..09 UEM-03 UEM-06..07"),
]

# --------------------------------------------------------------------------
# organizational-relevance.yaml -- default true, false-list below.
# --------------------------------------------------------------------------
ORGANIZATIONAL_DEFAULT = True
ORGANIZATIONAL: list[tuple[str, str]] = [
    ("Cybersecurity",
     "A&A-01..04 CCC-01 CCC-05 CCC-08 DCS-01 DCS-04..06 DCS-08 DCS-10..13 "
     "DSP-01..09 DSP-11..19 IPY-01..04 IVS-01..02 IVS-04..06 IVS-08 "
     "STA-08 STA-12..13"),
    ("Internal Audit",
     "A&A-01 DCS-07..13 DSP-03..19 IVS-01..09 LOG-09 LOG-11 SEF-01..10 "
     "TVM-08..09 TVM-11"),
    ("Architecture Team",
     "A&A-01..04 DCS-05 DCS-07..08 DCS-10..14 DSP-18 HRS-05..10 IPY-02 "
     "SEF-01..10 STA-04 STA-08..16 TVM-12"),
    ("SW Development",
     "A&A-02..04 BCR-11 CCC-01 CCC-05 CCC-08..09 DCS-01..08 DCS-10..18 "
     "DSP-01..06 DSP-09..11 DSP-16 DSP-18..19 HRS-05..10 IPY-02 IPY-04 "
     "IVS-01..02 IVS-08..09 SEF-01..10 STA-01..16 TVM-07..12"),
    ("Operations",
     "A&A-02..04 CCC-01 CCC-05 CCC-08..09 DSP-01..02 DSP-05 DSP-07..08 "
     "DSP-12..13 DSP-18 IPY-01..04 IVS-01 IVS-08 SEF-08 STA-04..06 STA-08 "
     "STA-10 STA-12..13 STA-15..16"),
    ("Legal/Privacy",
     "A&A-02..04 A&A-06 AIS-02..06 AIS-08 CCC-01 CCC-03..04 CCC-07..09 "
     "DCS-01 DCS-07..15 DSP-01..02 DSP-04..07 DSP-10 DSP-15 DSP-17 DSP-19 "
     "HRS-05..06 IPY-02..03 IVS-01..09 LOG-05 LOG-07 LOG-10..13 STA-03 "
     "STA-07..10 STA-13 STA-15..16 TVM-08..09 UEM-02..05 UEM-07..13"),
    ("GRC Team",
     "A&A-06 CCC-04 CCC-07 DCS-07..11 DCS-13 DCS-17..18 DSP-03 DSP-05..09 "
     "DSP-11 DSP-15 DSP-17..19 IPY-02..03 IVS-02 IVS-04..06 IVS-08..09 "
     "SEF-03 SEF-06 STA-08..09 STA-12 STA-14 STA-16"),
    ("Supply Chain Management",
     "A&A-02..04 CCC-01 CCC-03 CCC-05 CCC-08..09 DCS-01..07 DCS-09 DCS-12 "
     "DCS-16 DSP-03..12 DSP-15..19 GRC-07..08 HRS-05..10 IPY-01..02 IPY-04 "
     "IVS-01..02 IVS-04..05 IVS-08..09 LOG-02..14 SEF-01..10 TVM-07..12 "
     "UEM-02..04 UEM-08..14"),
    ("HR",
     "A&A-01..04 A&A-06 AIS-02..03 AIS-05..06 AIS-08 BCR-11 CCC-01 CCC-03..05 "
     "CCC-07..09 DCS-01..05 DCS-07..11 DCS-13..18 DSP-01..19 GRC-08 "
     "IPY-02..04 IVS-01..09 LOG-03..14 SEF-01..10 STA-03..16 TVM-03..12 "
     "UEM-01..14"),
]

# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
SOURCE_NOTE = (
    "transcribed from a CSA Cloud Controls Matrix spreadsheet export; the "
    "export carried no version marker, so version_status is 'unverified'"
)

HEADER_BANNER = """\
# GENERATED FILE - DO NOT EDIT BY HAND.
#   Produced by scripts/gen_ccm_matrix.py
#   Guarded by tests/test_ccm_matrix.py
#   Contract:  compliance/ccm/ccm-matrix.schema.json
#
# Edit the exception lists in the generator, not the rows below. The three
# matrix files share one control-id universe; editing one file by hand is how
# they drift apart.
"""


def _quote(key: str) -> str:
    """YAML-quote a control id. A&A-01 and Legal/Privacy are plain-safe, but
    quoting every key removes the question permanently."""
    return '"' + key.replace('"', '\\"') + '"'


def _fmt(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return _quote(str(value))


def _render(*, name, description, value_type, enum, default, sections,
            axis) -> str:
    today = _dt.date.today().isoformat()
    out: list[str] = [HEADER_BANNER]
    out.append(f"name: {_quote(name)}")
    out.append(f"description: {_quote(description)}")
    out.append("framework: CSA-CCM")
    out.append("version: null")
    out.append("version_status: unverified")
    out.append(
        "version_note: >-\n"
        "  The source export declared no version. Its id universe is 207\n"
        "  controls across 17 domains, which does not match the 197 published\n"
        "  for CCM v4.0.x, and compliance/crosswalk.json pins CSA-CCM-4 at\n"
        "  4.0. Resolve against the authoritative CCM release and record the\n"
        "  per-domain deltas here before any consumer cites these rows.")
    out.append(f"source: {_quote(SOURCE_NOTE)}")
    out.append(f"generated: {_quote(today)}")
    out.append(
        "licence: >-\n"
        "  CSA Cloud Controls Matrix is published by the Cloud Security\n"
        "  Alliance under its own terms. This file carries control IDENTIFIERS\n"
        "  and this project's own applicability judgements only; it reproduces\n"
        "  no CCM control titles, specifications or implementation guidance.")
    out.append(f"axis: {_quote(axis)}")
    out.append(f"value_type: {_quote(value_type)}")
    out.append("value_enum:")
    for v in enum:
        out.append(f"  - {_fmt(v)}")
    out.append(f"default: {_fmt(default)}")
    out.append("unresolved:")
    for cid, why in sorted(UNRESOLVED.items()):
        out.append(f"  - control_id: {_quote(cid)}")
        out.append(f"    reason: {_quote(why)}")
    out.append("control_count: %d" % len(CONTROL_IDS))
    out.append("section_count: %d" % len(sections))
    out.append("content:")

    for title, section_id, values in sections:
        out.append(f"- title: {_quote(title)}")
        out.append(f"  id: {_quote(section_id)}")
        out.append("  content:")
        for cid in CONTROL_IDS:
            v = None if cid in UNRESOLVED else values[cid]
            out.append(f"  - control_id: {_quote(cid)}")
            out.append(f"    value: {_fmt(v)}")
    return "\n".join(out) + "\n"


def _section_id(title: str) -> str:
    """Stable key derived from the display title, so renaming the label does
    not silently break consumers that joined on it."""
    out = []
    for ch in title.lower():
        out.append(ch if ch.isalnum() else "-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-")


def build_ownership() -> str:
    sections = []
    for title, exceptions in OWNERSHIP:
        values = {cid: OWNERSHIP_DEFAULT for cid in CONTROL_IDS}
        for value, spec in exceptions.items():
            for cid in _ids(spec):
                values[cid] = value
        sections.append((title, _section_id(title), values))
    return _render(
        name="Typical Control Applicability and Ownership",
        description=("Which party typically owns each CCM control for a given "
                     "cloud service model."),
        value_type="string",
        enum=["CSP-Owned", "CSC-Owned", "Shared"],
        default=OWNERSHIP_DEFAULT,
        sections=sections,
        axis="service_model",
    )


def _bool_file(name, description, axis, spec_list, default) -> str:
    sections = []
    for title, false_spec in spec_list:
        values = {cid: default for cid in CONTROL_IDS}
        for cid in _ids(false_spec):
            values[cid] = not default
        sections.append((title, _section_id(title), values))
    return _render(
        name=name,
        description=description,
        value_type="boolean",
        enum=[True, False],
        default=default,
        sections=sections,
        axis=axis,
    )


def build_architectural() -> str:
    return _bool_file(
        "Architectural Relevance - Cloud Stack Components",
        ("Whether each CCM control is in scope for a given layer of the cloud "
         "stack. true = the control applies to that layer."),
        "cloud_stack_component",
        ARCHITECTURAL,
        ARCHITECTURAL_DEFAULT,
    )


def build_organizational() -> str:
    return _bool_file(
        "Organizational Relevance",
        ("Whether each CCM control is in scope for a given internal function. "
         "true = that function has a stake in the control."),
        "organizational_function",
        ORGANIZATIONAL,
        ORGANIZATIONAL_DEFAULT,
    )


FILES = {
    "ownership.yaml": build_ownership,
    "architectural-relevance.yaml": build_architectural,
    "organizational-relevance.yaml": build_organizational,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the files on disk differ from what this "
                         "generator would write (for CI)")
    args = ap.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    stale = []
    for fname, builder in FILES.items():
        path = os.path.join(OUT_DIR, fname)
        rendered = builder()
        if args.check:
            existing = None
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as fh:
                    existing = fh.read()
            if existing != rendered:
                stale.append(fname)
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(rendered)
        print(f"wrote {os.path.relpath(path, ROOT)} "
              f"({len(CONTROL_IDS)} ids x {rendered.count('- title:')} sections)")

    if args.check:
        if stale:
            print("STALE (regenerate with scripts/gen_ccm_matrix.py): "
                  + ", ".join(stale), file=sys.stderr)
            return 1
        print("all three CCM matrix files are up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
