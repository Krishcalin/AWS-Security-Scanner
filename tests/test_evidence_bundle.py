"""The signed evidence bundle, and the tampering it is supposed to survive.

WHY THIS EXISTS
---------------
`aws_evidence.build_pack` produces the artifact this product's compliance story rests on:
a control-by-control record that includes **what the scan could not reach**. Until now it
left this machine as a JSON file, i.e. as a printout — it asserted things about a scan and
nothing about it could be checked.

The tests below are mostly ADVERSARIAL, because the value of a signature is entirely in
what it refuses. In particular:

* **Removing the coverage section must break verification.** That is the attack this
  design exists to stop: strip "these controls were never assessed" and an incomplete scan
  reads as a clean one. If signing made that easier rather than harder, it would be worse
  than not signing.
* **An unsigned bundle must never look signed.** `signature: null` plus a stated reason,
  never an omitted field — an absent key reads as an old format or an oversight.
* **Verification must name what changed.** "Invalid" is not actionable for an auditor;
  the three failure classes (edited content / edited manifest / different signer) mean
  different things and must stay distinguishable.
* **A correct signature from the WRONG key must not pass a pinned check.** Otherwise a
  forger signs with their own key and the bundle verifies.
"""
from __future__ import annotations

import base64
import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ed25519  # noqa: E402
import aws_evidence_bundle as eb  # noqa: E402

SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
AT = "2026-08-26T12:00:00Z"

PACK = {"NIST-AI-RMF-1.0": {"controls": [
    {"id": "GOVERN-1.1", "status": "ASSESSED_PASS", "checks": ["AISPM-01"]},
    {"id": "MAP-2.3", "status": "NOT_ASSESSED", "checks": []},
]}}
COVERAGE = {"not_evaluated": {"BDR-04": "AccessDenied on bedrock:GetGuardrail"},
            "regions_skipped": ["ap-south-1"]}
PERMS = {"forfeited": ["bedrock:GetGuardrail"]}
SCOPE = {"account": "123456789012", "scan_id": "scan-1"}
PRODUCER = {"scanner": "OverWatch", "version": "2.36.0"}


def _make(seed, **kw):
    args = dict(coverage=COVERAGE, permissions=PERMS, scope=SCOPE,
                producer=PRODUCER, generated_at=AT, seed=seed)
    args.update(kw)
    return eb.build_bundle(PACK, **args)


# The vendored Ed25519 is pure Python and a sign/verify pair costs ~1s. Building the
# three fixed bundles ONCE and handing out deep copies keeps this file near-instant
# without weakening anything: every mutation test still gets its own object to corrupt,
# and the determinism test below re-derives from scratch rather than from the cache.
_CACHE = {}


def build(seed=SEED, **kw):
    if kw:
        return _make(seed, **kw)
    key = seed
    if key not in _CACHE:
        _CACHE[key] = _make(seed)
    return copy.deepcopy(_CACHE[key])


# ── canonical form ──────────────────────────────────────────────────────────
def test_key_order_does_not_change_the_digest():
    """A bundle round-tripped through any JSON tool must still verify. Without this,
    verification fails cosmetically and readers learn to ignore it."""
    assert eb.digest({"b": 1, "a": 2}) == eb.digest({"a": 2, "b": 1})


def test_the_digest_names_its_algorithm():
    """A bare hex string is ambiguous the moment a second algorithm exists."""
    assert eb.digest({}).startswith("sha256:")


def test_non_ascii_resource_names_survive_as_themselves():
    b = eb.canonical({"name": "bucket-café"})
    assert "café".encode("utf-8") in b


def test_nan_is_refused_rather_than_serialized():
    """NaN is not JSON. Emitting it produces bytes other parsers reject, so the bundle
    would verify here and fail everywhere else."""
    with pytest.raises(eb.BundleError):
        eb.canonical({"x": float("nan")})


def test_unserializable_content_is_a_clear_error():
    with pytest.raises(eb.BundleError):
        eb.canonical({"x": object()})


# ── keys ────────────────────────────────────────────────────────────────────
def test_no_key_configured_yields_no_seed_not_an_error():
    for empty in (None, "", "   "):
        assert eb.seed_from_text(empty) is None


def test_a_malformed_key_is_an_ERROR_not_a_silent_fallback_to_unsigned():
    """THE important one. An operator who configured a key and got an unsigned bundle
    would believe their evidence was signed. Fail loudly instead."""
    with pytest.raises(eb.BundleError) as e:
        eb.seed_from_text("this is not base64!!")
    assert "base64" in str(e.value)


def test_a_wrong_length_key_is_refused():
    short = base64.b64encode(b"tooshort").decode()
    with pytest.raises(eb.BundleError) as e:
        eb.seed_from_text(short)
    assert "32 bytes" in str(e.value)


def test_a_valid_key_decodes():
    assert eb.seed_from_text(base64.b64encode(SEED).decode()) == SEED


def test_the_seed_never_appears_in_the_bundle():
    """The private half must not leak into an artifact designed to be emailed."""
    blob = eb.canonical(build())
    assert base64.b64encode(SEED) not in blob
    assert SEED not in blob


# ── build ───────────────────────────────────────────────────────────────────
def test_a_signed_bundle_verifies():
    r = eb.verify_bundle(build())
    assert r["ok"] and r["signed"] and not r["problems"]


def test_building_is_deterministic():
    """Pure function of its inputs -- generated_at is injected, not read from a clock.
    Built twice from scratch on purpose: comparing two copies of one cached object
    would pass no matter how non-deterministic the builder was."""
    assert eb.canonical(_make(SEED)) == eb.canonical(_make(SEED))


def test_an_unsigned_bundle_says_so_explicitly_with_a_reason():
    """Never an omitted field: absence reads as an old format or an oversight."""
    b = build(seed=None)
    assert "signature" in b and b["signature"] is None
    assert b["unsigned_reason"] and "no proof of origin" in b["unsigned_reason"]


def test_an_unsigned_bundle_still_verifies_its_own_integrity():
    """Digests without a signature is a legitimate state -- it proves the content is
    internally consistent, just not who made it."""
    r = eb.verify_bundle(build(seed=None))
    assert r["ok"] is True and r["signed"] is False


def test_a_signed_bundle_clears_the_unsigned_reason():
    assert build()["unsigned_reason"] is None


def test_the_attestation_travels_inside_the_bundle():
    """An artifact that overstates what its signature means is worse than an unsigned
    one, because the reader stops asking."""
    b = build()
    assert b["attestation"] == eb.ATTESTATION
    assert "does NOT attest" in b["attestation"]
    assert "not a trusted timestamp" in b["attestation"]


def test_the_attestation_is_covered_by_the_signature():
    """Otherwise the limits could be edited out of a validly-signed bundle."""
    b = build()
    b["attestation"] = "This bundle proves the estate is compliant."
    r = eb.verify_bundle(b)
    assert not r["ok"] and not r["signed"]


def test_every_declared_section_is_digested():
    b = build()
    assert set(b["digests"]) == set(eb.SIGNED_SECTIONS)


# ── tampering: the whole point ──────────────────────────────────────────────
def test_removing_the_coverage_section_breaks_verification():
    """THE attack this design exists to stop. Stripping 'these controls were never
    assessed' must not leave a bundle that still verifies."""
    b = build()
    del b["sections"]["coverage"]
    r = eb.verify_bundle(b)
    assert not r["ok"]
    assert "coverage" in r["tampered_sections"]


def test_emptying_the_coverage_section_breaks_verification():
    """The subtler version: keep the key, drop the contents."""
    b = build()
    b["sections"]["coverage"] = {}
    r = eb.verify_bundle(b)
    assert not r["ok"] and "coverage" in r["tampered_sections"]


def test_flipping_a_control_from_not_assessed_to_pass_is_caught():
    b = build()
    b["sections"]["pack"]["NIST-AI-RMF-1.0"]["controls"][1]["status"] = "ASSESSED_PASS"
    r = eb.verify_bundle(b)
    assert not r["ok"] and r["tampered_sections"] == ["pack"]


def test_verification_names_WHICH_section_changed():
    """'Invalid' is not actionable for an auditor."""
    b = build()
    b["sections"]["permissions"]["forfeited"] = []
    r = eb.verify_bundle(b)
    assert r["tampered_sections"] == ["permissions"]
    assert any("permissions" in p for p in r["problems"])


def test_editing_a_section_AND_its_digest_still_fails_at_the_root():
    """A tamperer who recomputes the digest has to forge the signature too -- that is
    the whole point of the digest tree sitting under the signature."""
    b = build()
    b["sections"]["pack"] = {"everything": "fine"}
    b["digests"]["pack"] = eb.digest(b["sections"]["pack"])
    r = eb.verify_bundle(b)
    assert not r["ok"] and not r["signed"]
    assert r["tampered_sections"] == []          # content now matches its digest...
    assert any("signature" in p for p in r["problems"])   # ...but the signature does not


def test_backdating_the_bundle_breaks_the_signature():
    b = build()
    b["generated_at"] = "2020-01-01T00:00:00Z"
    assert not eb.verify_bundle(b)["signed"]


def test_an_added_digest_entry_is_rejected():
    b = build()
    b["digests"]["extra"] = eb.digest({})
    r = eb.verify_bundle(b)
    assert not r["ok"] and any("unexpected digest" in p for p in r["problems"])


# ── signer identity ─────────────────────────────────────────────────────────
def test_a_valid_signature_from_the_WRONG_key_fails_a_pinned_check():
    """Without pinning, a forger simply signs with their own key and the bundle
    verifies. This is the difference between 'internally consistent' and 'from whom
    I expect'."""
    b = build(seed=OTHER_SEED)
    expected = eb.public_key_for(SEED)
    r = eb.verify_bundle(b, expect_public_key=expected)
    assert not r["ok"] and not r["signed"]
    assert any("different key" in p for p in r["problems"])


def test_the_same_bundle_verifies_unpinned():
    """...and this is why the docstring warns that unpinned verification proves less."""
    assert eb.verify_bundle(build(seed=OTHER_SEED))["ok"] is True


def test_pinning_against_an_unsigned_bundle_is_a_problem():
    r = eb.verify_bundle(build(seed=None), expect_public_key=eb.public_key_for(SEED))
    assert not r["ok"] and any("unsigned" in p for p in r["problems"])


def test_signed_by_reports_the_public_key():
    assert eb.verify_bundle(build())["signed_by"] == eb.public_key_for(SEED)


def test_the_public_key_matches_the_vendored_primitive():
    """Guards against this module and aws_ed25519 drifting on encoding."""
    assert base64.b64decode(eb.public_key_for(SEED)) == aws_ed25519.publickey(SEED)


# ── malformed input ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", [None, "x", 7, []])
def test_verifying_a_non_bundle_is_a_clean_failure(bad):
    r = eb.verify_bundle(bad)
    assert r["ok"] is False and r["problems"]


def test_a_foreign_kind_is_rejected():
    b = build()
    b["kind"] = "some-other-artifact"
    assert not eb.verify_bundle(b)["ok"]


def test_a_future_bundle_version_is_rejected_rather_than_guessed():
    """A verifier that shrugs at an unknown version is a downgrade waiting to happen."""
    b = build()
    b["bundle_version"] = 99
    r = eb.verify_bundle(b)
    assert not r["ok"] and any("bundle_version" in p for p in r["problems"])


def test_a_malformed_signature_object_does_not_raise():
    b = build()
    b["signature"] = "not-an-object"
    r = eb.verify_bundle(b)
    assert not r["ok"] and not r["signed"]


def test_an_unknown_signature_algorithm_is_refused():
    b = build()
    b["signature"]["alg"] = "rot13"
    r = eb.verify_bundle(b)
    assert not r["ok"] and any("algorithm" in p for p in r["problems"])


def test_garbage_base64_in_the_signature_does_not_raise():
    b = build()
    b["signature"]["value"] = "!!!not base64!!!"
    r = eb.verify_bundle(b)
    assert not r["ok"] and not r["signed"]


def test_an_empty_pack_still_produces_a_valid_bundle():
    """An account with nothing assessed must still be able to produce evidence OF that."""
    b = eb.build_bundle(None, generated_at=AT, seed=SEED)
    assert eb.verify_bundle(b)["ok"] is True


# ── the CLI's exit codes carry meaning an auditor's script depends on ────────
def _cli(tmp_path, *argv):
    """Run the verifier the way an auditor would, in-process."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ow_evidence",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "scripts", "overwatch_evidence.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.main(list(argv))


def _write(tmp_path, name, obj):
    import json as _j
    p = tmp_path / name
    p.write_text(_j.dumps(obj), encoding="utf-8")
    return str(p)


def test_cli_exit_0_ONLY_when_the_signer_was_actually_checked(tmp_path):
    """THE distinction a CI gate depends on. Verifying without --pub proves only that
    SOME key signed it -- a forger signing their own edited bundle satisfies exactly
    that. Exit 0 must mean 'signed by the key I named', never merely 'signed'."""
    bundle = _write(tmp_path, "b.json", build())
    pub = tmp_path / "k.pub"
    pub.write_text(eb.public_key_for(SEED), encoding="utf-8")

    assert _cli(tmp_path, "verify", "--in", bundle, "--pub", str(pub), "--quiet") == 0
    assert _cli(tmp_path, "verify", "--in", bundle, "--quiet") == 2   # unauthenticated


def test_cli_exit_1_on_tampering(tmp_path):
    b = build()
    del b["sections"]["coverage"]
    path = _write(tmp_path, "t.json", b)
    assert _cli(tmp_path, "verify", "--in", path, "--quiet") == 1


def test_cli_exit_2_on_an_unsigned_bundle(tmp_path):
    path = _write(tmp_path, "u.json", build(seed=None))
    assert _cli(tmp_path, "verify", "--in", path, "--quiet") == 2


def test_cli_rejects_a_forgery_when_the_key_is_pinned(tmp_path):
    """The forged-bundle case, end to end: an attacker edits the pack, strips coverage,
    and signs it with their own key. Pinned verification is what catches it."""
    forged = build(seed=OTHER_SEED)
    path = _write(tmp_path, "f.json", forged)
    pub = tmp_path / "real.pub"
    pub.write_text(eb.public_key_for(SEED), encoding="utf-8")
    assert _cli(tmp_path, "verify", "--in", path, "--pub", str(pub), "--quiet") == 1


def test_cli_console_output_is_ascii_only():
    """A Windows codepage must not be able to turn a verification result into mojibake.

    Scoped to STRING LITERALS -- the only text that can reach stdout. Comments and the
    module docstring may use the repo's box-drawing dividers and typographic dashes
    freely, because neither is ever printed. An earlier version of this test flagged
    those and would have forced a pointless style change on the whole file."""
    import ast
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "scripts", "overwatch_evidence.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    # Identify the docstring by NODE, not by value: ast.get_docstring returns a cleaned,
    # dedented copy that never equals the raw literal, so comparing strings silently
    # failed to exempt it -- which is how the first version of this test "found" a
    # problem that was only the docstring's own em-dash.
    doc_node = None
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)):
        doc_node = tree.body[0].value
    bad = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node is doc_node:
                continue                      # module docstring: never printed
            bad |= {c for c in node.value if ord(c) > 127}
    assert not bad, f"non-ASCII in a printable string literal: {sorted(bad)}"
