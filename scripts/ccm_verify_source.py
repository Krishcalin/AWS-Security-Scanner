#!/usr/bin/env python3
"""Check the generated CCM matrix files against the original spreadsheet exports.

WHY THIS EXISTS
---------------
``compliance/ccm/*.yaml`` is rendered by ``scripts/gen_ccm_matrix.py`` from
exception lists that were TRANSCRIBED from a spreadsheet export.  A
transcription is exactly the kind of step that is right until it is quietly
wrong, and the whole point of the corrected files is that they can be trusted.

So: point this at the original exports and it compares every single
(section, control_id) -> value cell.  It applies only the corrections that are
documented in the generator, and reports anything else as a mismatch.

    python scripts/ccm_verify_source.py --source path/to/original/exports

It expects the three original files by their export names:
    ownership.yaml
    architectural-relevance.yaml
    organizational-relevance.yaml

Exit 0 = every cell agrees.  Exit 1 = mismatches, listed.  Exit 2 = the source
files could not be read.
"""
from __future__ import annotations

import argparse
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("PyYAML is required", file=sys.stderr)
    raise SystemExit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATED_DIR = os.path.join(ROOT, "compliance", "ccm")

FILES = (
    "ownership.yaml",
    "architectural-relevance.yaml",
    "organizational-relevance.yaml",
)

# The corrections the generator applies. Anything NOT on this list that
# differs between source and generated is a transcription error.
DOCUMENTED_CORRECTIONS = {
    "domain_rename": ("I&S", "IVS"),
    "restored_ids": ("IAM-16",),
}


def _norm_id(control_id: str) -> str:
    old, new = DOCUMENTED_CORRECTIONS["domain_rename"]
    if control_id.startswith(old + "-"):
        return new + control_id[len(old):]
    return control_id


def _slug(title: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in title.lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")


def _cells(doc, *, from_source: bool):
    """{(section_slug, control_id): value} for either file shape."""
    cells = {}
    for section in doc["content"]:
        sid = section["id"] if not from_source else _slug(section["title"])
        for row in section["content"]:
            cid = _norm_id(row["control_id"]) if from_source else row["control_id"]
            key = (sid, cid)
            if key in cells:
                raise SystemExit(f"duplicate cell in input: {key}")
            value = row["value"]
            if isinstance(value, str):
                value = value.strip()  # the export had trailing whitespace
            cells[key] = value
    return cells


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", required=True,
                    help="directory holding the three original export YAMLs")
    args = ap.parse_args()

    total = mismatches = 0
    restored = set(DOCUMENTED_CORRECTIONS["restored_ids"])

    for fname in FILES:
        src_path = os.path.join(args.source, fname)
        gen_path = os.path.join(GENERATED_DIR, fname)
        if not os.path.isfile(src_path):
            print(f"source file not found: {src_path}", file=sys.stderr)
            return 2
        with open(src_path, encoding="utf-8") as fh:
            src = _cells(yaml.safe_load(fh), from_source=True)
        with open(gen_path, encoding="utf-8") as fh:
            gen = _cells(yaml.safe_load(fh), from_source=False)

        # Restored ids exist only in the generated files, and only as null.
        gen_comparable = {
            k: v for k, v in gen.items() if k[1] not in restored
        }
        for key in sorted(set(gen.keys()) - set(gen_comparable.keys())):
            if gen[key] is not None:
                print(f"{fname}: restored id {key[1]} in {key[0]} carries "
                      f"{gen[key]!r}; it must stay null until authored")
                mismatches += 1

        only_src = sorted(set(src) - set(gen_comparable))
        only_gen = sorted(set(gen_comparable) - set(src))
        if only_src:
            print(f"{fname}: {len(only_src)} cells in source but not "
                  f"generated, e.g. {only_src[:5]}")
            mismatches += len(only_src)
        if only_gen:
            print(f"{fname}: {len(only_gen)} cells generated but not in "
                  f"source, e.g. {only_gen[:5]}")
            mismatches += len(only_gen)

        bad = []
        for key in sorted(set(src) & set(gen_comparable)):
            total += 1
            if src[key] != gen_comparable[key]:
                bad.append((key, src[key], gen_comparable[key]))
        for (sid, cid), s, g in bad:
            print(f"{fname}: {sid}/{cid}  source={s!r}  generated={g!r}")
        mismatches += len(bad)

        status = "OK" if not (bad or only_src or only_gen) else "MISMATCH"
        print(f"{status:9} {fname}: compared "
              f"{len(set(src) & set(gen_comparable)):,} cells")

    print()
    if mismatches:
        print(f"{mismatches:,} mismatched cells out of {total:,} compared")
        return 1
    print(f"all {total:,} cells agree; the only differences are the "
          f"documented corrections "
          f"({DOCUMENTED_CORRECTIONS['domain_rename'][0]} -> "
          f"{DOCUMENTED_CORRECTIONS['domain_rename'][1]}, "
          f"restored {', '.join(sorted(restored))})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
