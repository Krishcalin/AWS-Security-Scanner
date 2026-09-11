"""Guards for the three CSA CCM matrix files under ``compliance/ccm/``.

The source spreadsheet exports had no schema, no version marker and no
cross-file check, and carried two id defects that nothing could have caught:
``I&S`` where the CCM says ``IVS`` (162 rows that silently failed to join) and
a missing ``IAM-16`` (cited by ``compliance/crosswalk.json`` today).

These tests exist so that class of defect cannot return quietly.  The
expensive ones are the parity checks: three files keyed by the same universe
will drift apart, and drift is invisible without an assertion.

`jsonschema` is not in the wheelhouse, so the schema is enforced by the small
structural validator below rather than by a library.  The published
``ccm-matrix.schema.json`` remains the contract for outside consumers;
``test_schema_and_validator_agree`` keeps the two from diverging.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest

yaml = pytest.importorskip("yaml")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CCM_DIR = os.path.join(ROOT, "compliance", "ccm")
SCHEMA_PATH = os.path.join(CCM_DIR, "ccm-matrix.schema.json")
GENERATOR = os.path.join(ROOT, "scripts", "gen_ccm_matrix.py")

FILES = (
    "ownership.yaml",
    "architectural-relevance.yaml",
    "organizational-relevance.yaml",
)

# The 17 CCM domain codes. IVS is the real code for Infrastructure &
# Virtualization Security; I&S is not a CCM domain and must never reappear.
DOMAINS = (
    "A&A", "AIS", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS",
    "IAM", "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM",
)
CONTROL_ID_RE = re.compile(r"^(%s)-[0-9]{2}$" % "|".join(
    re.escape(d) for d in DOMAINS))
SECTION_ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Ownership is monotone toward the provider as the service model rises:
# whatever the customer runs on IaaS, they run less of on SaaS. Exactly one
# row in the source moves the other way, and it is named here so that it stays
# a deliberate, visible exception and a SECOND one fails this test.
OWNERSHIP_RANK = {"CSC-Owned": 0, "Shared": 1, "CSP-Owned": 2}
MONOTONICITY_EXCEPTIONS = {
    "DSP-17": (
        "SaaS flips to CSC-Owned while IaaS/PaaS are CSP-Owned. The only "
        "reversal in 621 rows; carried from the source export and NOT yet "
        "confirmed against the published CCM."
    ),
}


@pytest.fixture(scope="module")
def docs():
    loaded = {}
    for fname in FILES:
        path = os.path.join(CCM_DIR, fname)
        assert os.path.isfile(path), f"missing matrix file: {fname}"
        with open(path, encoding="utf-8") as fh:
            loaded[fname] = yaml.safe_load(fh)
    return loaded


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _ids(doc, section):
    return [row["control_id"] for row in section["content"]]


# ---------------------------------------------------------------- structure

@pytest.mark.parametrize("fname", FILES)
def test_header_is_complete(docs, fname):
    doc = docs[fname]
    for key in ("name", "description", "framework", "version",
                "version_status", "source", "licence", "axis",
                "value_type", "value_enum", "default",
                "control_count", "section_count", "content"):
        assert key in doc, f"{fname}: header is missing {key!r}"
    assert doc["framework"] == "CSA-CCM"
    assert doc["version_status"] in ("verified", "unverified")


@pytest.mark.parametrize("fname", FILES)
def test_an_unverified_version_is_null_and_a_verified_one_is_not(docs, fname):
    """A guessed version is worse than an absent one: it is indistinguishable
    from a checked one. This forbids stamping a version without doing the work.
    """
    doc = docs[fname]
    if doc["version_status"] == "unverified":
        assert doc["version"] is None, (
            f"{fname}: version_status is 'unverified' but a version is "
            f"stamped ({doc['version']!r}). Reconcile the id universe against "
            f"the published CCM release first, then set version_status.")
    else:
        assert isinstance(doc["version"], str) and doc["version"], (
            f"{fname}: version_status is 'verified' but no version is named")


@pytest.mark.parametrize("fname", FILES)
def test_counts_match_the_rows(docs, fname):
    doc = docs[fname]
    assert len(doc["content"]) == doc["section_count"]
    for section in doc["content"]:
        assert len(section["content"]) == doc["control_count"], (
            f"{fname}/{section['id']}: {len(section['content'])} rows but "
            f"control_count is {doc['control_count']}")


@pytest.mark.parametrize("fname", FILES)
def test_section_ids_are_stable_slugs_and_unique(docs, fname):
    doc = docs[fname]
    seen = set()
    for section in doc["content"]:
        sid = section["id"]
        assert SECTION_ID_RE.match(sid), f"{fname}: bad section id {sid!r}"
        assert sid not in seen, f"{fname}: duplicate section id {sid!r}"
        seen.add(sid)
        assert section["title"].strip() == section["title"], (
            f"{fname}: title {section['title']!r} has stray whitespace")


# ---------------------------------------------------------------- id parity

@pytest.mark.parametrize("fname", FILES)
def test_every_section_carries_the_same_ids_in_the_same_order(docs, fname):
    doc = docs[fname]
    reference = _ids(doc, doc["content"][0])
    for section in doc["content"][1:]:
        assert _ids(doc, section) == reference, (
            f"{fname}/{section['id']} diverges from "
            f"{doc['content'][0]['id']}")


def test_all_three_files_share_one_control_id_universe(docs):
    """The defect this whole test module exists for: three files keyed by the
    same ids, edited independently, with nothing detecting a divergence."""
    universes = {
        fname: _ids(doc, doc["content"][0]) for fname, doc in docs.items()
    }
    reference_name, reference = next(iter(universes.items()))
    for fname, ids in universes.items():
        assert ids == reference, (
            f"{fname} and {reference_name} disagree on the control-id "
            f"universe: only in {fname}={sorted(set(ids)-set(reference))}, "
            f"only in {reference_name}={sorted(set(reference)-set(ids))}")


@pytest.mark.parametrize("fname", FILES)
def test_ids_are_well_formed_unique_and_dense(docs, fname):
    doc = docs[fname]
    ids = _ids(doc, doc["content"][0])
    assert len(ids) == len(set(ids)), f"{fname}: duplicate control ids"
    by_domain = {}
    for cid in ids:
        assert CONTROL_ID_RE.match(cid), f"{fname}: malformed id {cid!r}"
        dom, num = cid.rsplit("-", 1)
        by_domain.setdefault(dom, []).append(int(num))
    for dom, nums in by_domain.items():
        assert nums == list(range(1, len(nums) + 1)), (
            f"{fname}: {dom} numbering is not dense from 01: {nums}")


def test_the_i_and_s_misspelling_never_returns(docs):
    """`I&S` is not a CCM domain. The source export used it for IVS, which cost
    162 rows that could not join against compliance/crosswalk.json."""
    for fname, doc in docs.items():
        for cid in _ids(doc, doc["content"][0]):
            assert not cid.startswith("I&S"), (
                f"{fname}: {cid} uses the non-existent I&S domain; "
                f"the CCM code is IVS")


def test_ids_cited_by_the_crosswalk_all_resolve(docs):
    """The join that motivated the corrections. Any CCM id OverWatch already
    cites must exist here, or a consumer silently loses those rows."""
    path = os.path.join(ROOT, "compliance", "crosswalk.json")
    if not os.path.isfile(path):
        pytest.skip("crosswalk.json not present")
    with open(path, encoding="utf-8") as fh:
        crosswalk = json.load(fh)
    cited = set()
    for _nist, frameworks in crosswalk.get("crosswalk", {}).items():
        edge = frameworks.get("CSA-CCM-4")
        if edge:
            cited.update(edge.get("targets", []))
    if not cited:
        pytest.skip("no CSA-CCM-4 edges in the crosswalk")
    universe = set(_ids(docs[FILES[0]], docs[FILES[0]]["content"][0]))
    missing = sorted(cited - universe)
    assert not missing, (
        f"crosswalk.json cites CCM ids absent from the matrix: {missing}")


# ------------------------------------------------------------------- values

@pytest.mark.parametrize("fname", FILES)
def test_values_are_enum_members_and_typed_consistently(docs, fname):
    doc = docs[fname]
    allowed = set()
    for v in doc["value_enum"]:
        allowed.add(v if isinstance(v, bool) else str(v))
    want_bool = doc["value_type"] == "boolean"
    for section in doc["content"]:
        for row in section["content"]:
            v = row["value"]
            if v is None:
                continue
            assert isinstance(v, bool) == want_bool, (
                f"{fname}/{section['id']}/{row['control_id']}: value {v!r} "
                f"is not the declared value_type {doc['value_type']!r}")
            assert v in allowed, (
                f"{fname}/{section['id']}/{row['control_id']}: {v!r} is not "
                f"in value_enum {sorted(map(str, allowed))}")
    assert doc["default"] in allowed, f"{fname}: default is not an enum member"


@pytest.mark.parametrize("fname", FILES)
def test_null_appears_exactly_where_unresolved_says(docs, fname):
    """A null that is not declared is an unnoticed hole; a declaration with no
    null is a stale waiver. Both fail."""
    doc = docs[fname]
    declared = {u["control_id"] for u in doc.get("unresolved", [])}
    actual = {
        row["control_id"]
        for section in doc["content"]
        for row in section["content"]
        if row["value"] is None
    }
    assert actual == declared, (
        f"{fname}: null values {sorted(actual)} but `unresolved` declares "
        f"{sorted(declared)}")
    for section in doc["content"]:
        nulls = {r["control_id"] for r in section["content"]
                 if r["value"] is None}
        assert nulls == declared, (
            f"{fname}/{section['id']}: an unresolved id must be null in EVERY "
            f"section, else it is resolved in some and not others")


def test_ownership_is_monotone_toward_the_provider(docs):
    """IaaS -> PaaS -> SaaS hands responsibility to the provider, never back.
    Exactly one row in the source breaks this and it is named; a second one
    fails here rather than passing unnoticed."""
    doc = docs["ownership.yaml"]
    by_section = {
        s["id"]: {r["control_id"]: r["value"] for r in s["content"]}
        for s in doc["content"]
    }
    order = ["iaas", "paas", "saas"]
    assert set(order) <= set(by_section), by_section.keys()

    reversals = []
    for cid in _ids(doc, doc["content"][0]):
        ranks = []
        for sid in order:
            v = by_section[sid][cid]
            if v is None:
                break
            ranks.append(OWNERSHIP_RANK[v])
        else:
            if any(b < a for a, b in zip(ranks, ranks[1:])):
                reversals.append(cid)

    unexpected = sorted(set(reversals) - set(MONOTONICITY_EXCEPTIONS))
    assert not unexpected, (
        f"ownership moves away from the provider at {unexpected}, which the "
        f"service-model gradient does not do. Either the row is wrong or it "
        f"belongs in MONOTONICITY_EXCEPTIONS with a written reason.")

    stale = sorted(set(MONOTONICITY_EXCEPTIONS) - set(reversals))
    assert not stale, (
        f"MONOTONICITY_EXCEPTIONS names {stale}, which no longer reverses. "
        f"Remove the exception rather than leaving a waiver that guards "
        f"nothing.")


# ------------------------------------------------------------------- schema

def _validate(doc, schema, path="$"):
    """Structural subset of JSON Schema draft 2020-12, enough for this
    contract: type, const, enum, required, additionalProperties, pattern,
    minLength/minItems, uniqueItems, $ref into $defs."""
    errors: list[str] = []

    def resolve(node):
        ref = node.get("$ref")
        if not ref:
            return node
        assert ref.startswith("#/$defs/"), ref
        return schema["$defs"][ref.split("/")[-1]]

    def check(value, node, where):
        node = resolve(node)
        if "const" in node and value != node["const"]:
            errors.append(f"{where}: expected const {node['const']!r}")
            return
        if "enum" in node and value not in node["enum"]:
            errors.append(f"{where}: {value!r} not in enum {node['enum']}")
            return
        types = node.get("type")
        if types:
            types = [types] if isinstance(types, str) else types
            ok = any(
                (t == "object" and isinstance(value, dict))
                or (t == "array" and isinstance(value, list))
                or (t == "string" and isinstance(value, str))
                or (t == "boolean" and isinstance(value, bool))
                or (t == "integer" and isinstance(value, int)
                    and not isinstance(value, bool))
                or (t == "null" and value is None)
                for t in types
            )
            if not ok:
                errors.append(f"{where}: {value!r} is not {types}")
                return
        if isinstance(value, str):
            if "pattern" in node and not re.match(node["pattern"], value):
                errors.append(f"{where}: {value!r} fails {node['pattern']}")
            if len(value) < node.get("minLength", 0):
                errors.append(f"{where}: shorter than minLength")
        if isinstance(value, int) and not isinstance(value, bool):
            if "minimum" in node and value < node["minimum"]:
                errors.append(f"{where}: below minimum")
        if isinstance(value, list):
            if len(value) < node.get("minItems", 0):
                errors.append(f"{where}: fewer than minItems")
            if node.get("uniqueItems") and len(
                    {repr(v) for v in value}) != len(value):
                errors.append(f"{where}: items are not unique")
            if "items" in node:
                for i, item in enumerate(value):
                    check(item, node["items"], f"{where}[{i}]")
        if isinstance(value, dict):
            for key in node.get("required", []):
                if key not in value:
                    errors.append(f"{where}: missing required {key!r}")
            props = node.get("properties", {})
            if node.get("additionalProperties") is False:
                for key in value:
                    if key not in props:
                        errors.append(f"{where}: unexpected key {key!r}")
            for key, sub in props.items():
                if key in value:
                    check(value[key], sub, f"{where}.{key}")

    check(doc, schema, path)
    return errors


@pytest.mark.parametrize("fname", FILES)
def test_matches_the_published_schema(docs, schema, fname):
    errors = _validate(docs[fname], schema)
    assert not errors, f"{fname} violates the schema:\n  " + "\n  ".join(errors)


def test_schema_and_validator_agree_on_the_domain_list(schema):
    """The schema's controlId pattern and this module's DOMAINS are two copies
    of one fact. Pin them together so an added domain cannot land in one."""
    pattern = schema["$defs"]["controlId"]["pattern"]
    in_schema = set(pattern[pattern.index("(") + 1:pattern.index(")")].split("|"))
    assert in_schema == set(DOMAINS), (
        f"schema pattern domains {sorted(in_schema)} != test DOMAINS "
        f"{sorted(DOMAINS)}")
    assert "I&S" not in in_schema, "the schema must not admit the I&S misspelling"


# ---------------------------------------------------------------- generator

def test_the_files_on_disk_match_the_generator():
    """These files are generated. A hand edit is how the three drift apart, so
    a hand edit fails here."""
    proc = subprocess.run(
        [sys.executable, GENERATOR, "--check"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, (
        "compliance/ccm/*.yaml is out of date with scripts/gen_ccm_matrix.py. "
        "Edit the generator's exception lists and re-run it.\n"
        f"{proc.stdout}\n{proc.stderr}")
