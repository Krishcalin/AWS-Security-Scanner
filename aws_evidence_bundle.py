#!/usr/bin/env python3
"""aws_evidence_bundle.py — turn an evidence pack into a signed, verifiable artifact.

`aws_evidence.build_pack` already produces the thing no competitor produces: a
control-by-control record that includes **what the scan could not reach**. What it did not
produce was an artifact an auditor can rely on after it leaves this machine. A JSON file
in an email attachment is a printout — it asserts things about a scan, and nothing about
it can be checked. Orca's own customers describe their audit workflow as exporting a
report and pasting screenshots into evidence.

This module closes that: a canonical serialization, a per-section digest tree, and a
detached Ed25519 signature over the whole manifest.

WHAT THE SIGNATURE PROVES, AND WHAT IT DOES NOT
------------------------------------------------
It proves two things: the bundle was produced by a holder of the corresponding private
key, and **not one byte has changed since**. It proves nothing about whether the scan was
complete, whether the role could see everything, or whether the mappings are right. Those
questions are answered by the pack's own contents — the coverage manifest and the
per-control provenance — which is exactly why the coverage section is inside the signed
root. Stripping "these controls were never assessed" from a bundle must break the
signature, or signing would be a way to launder an incomplete scan into a clean one.

The attestation text saying so is emitted INSIDE the bundle. An artifact that overstates
what its own signature means is worse than an unsigned one, because the reader stops
asking.

WHY NOT A TRUSTED TIMESTAMP
----------------------------
`generated_at` is the generating host's clock. It is not an RFC 3161 timestamp and this
module will not pretend otherwise: a TSA is a network call to a third party, which is
precisely what an air-gapped deployment cannot make and what zero-telemetry forbids. An
operator who needs notarised time can counter-sign the bundle's root digest with whatever
their regime accepts — the root is published for that purpose.

KEY HANDLING
------------
The scanner never holds a signing key; signing happens here, at export, from a seed the
operator supplies. The seed is read, used, and never returned, never logged, and never
placed in the bundle — only the public key is. This mirrors `overwatch_vulndb`, except
inverted: there the publisher signs and the runtime verifies, here the operator signs
their own evidence and their auditor verifies.

Pure stdlib. No boto3, no network, no I/O.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Dict, Mapping, Optional, Tuple

import aws_ed25519

__all__ = [
    "BUNDLE_KIND", "BUNDLE_VERSION", "ATTESTATION", "SIGNED_SECTIONS",
    "BundleError", "canonical", "digest", "build_bundle", "verify_bundle",
    "public_key_for", "seed_from_text",
]

BUNDLE_KIND = "overwatch-evidence-bundle"
BUNDLE_VERSION = 1

#: The sections that go under the digest tree, in a fixed order. `coverage` is here for
#: the reason in the module docstring: an evidence bundle whose "what we could not see"
#: half can be removed without breaking the signature would be actively misleading.
SIGNED_SECTIONS: Tuple[str, ...] = ("pack", "coverage", "permissions", "scope", "producer")

#: Emitted verbatim inside every bundle, signed or not. Deliberately states the limits
#: first -- a reader who only skims should come away with the constraint, not the comfort.
ATTESTATION = (
    "This signature proves only that the bundle was produced by a holder of the named "
    "public key and has not been altered since. It does NOT attest that the scan was "
    "complete, that the scanning role could reach every resource, or that the control "
    "mappings are correct. Those questions are answered by the coverage manifest and the "
    "per-control provenance inside this bundle, both of which are covered by this "
    "signature. generated_at is the generating host's clock, not a trusted timestamp "
    "authority; an air-gapped deployment cannot reach one."
)


class BundleError(ValueError):
    """A bundle that cannot be built or verified, with a reason meant for a human."""


# ── canonical form ──────────────────────────────────────────────────────────
def canonical(obj) -> bytes:
    """The exact bytes that get digested and signed.

    Sorted keys and no incidental whitespace, so a bundle that is pretty-printed, reordered
    by a JSON library, or round-tripped through a different tool still verifies. Without
    this, verification would fail for cosmetic reasons and an auditor would learn to
    ignore the failure -- which is worse than not signing at all.

    `ensure_ascii=False` keeps non-ASCII resource names as themselves rather than escapes,
    so the signed bytes match what a reader sees. `allow_nan=False` refuses NaN/Infinity,
    which are not JSON and would serialize to something no other parser accepts.
    """
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise BundleError(f"bundle content is not canonically serializable: {e}") from e


def digest(obj) -> str:
    """SHA-256 over the canonical form, prefixed with its algorithm.

    The `sha256:` prefix is not decoration: a bare hex string in a security artifact is
    ambiguous the moment a second algorithm ever exists, and a verifier that assumes is a
    verifier that can be fooled by a downgrade."""
    return "sha256:" + hashlib.sha256(canonical(obj)).hexdigest()


# ── keys ────────────────────────────────────────────────────────────────────
def seed_from_text(text: Optional[str]) -> Optional[bytes]:
    """Decode a base64 32-byte Ed25519 seed supplied by the operator.

    Returns None for an absent/empty value -- an operator who has not configured signing
    gets an honest unsigned bundle, not an error. Anything present but malformed IS an
    error: silently falling back to unsigned when a key was configured would leave the
    operator believing their evidence is signed when it is not."""
    if text is None:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as e:
        raise BundleError(
            "signing key is not valid base64. Expected a base64-encoded 32-byte Ed25519 "
            f"seed: {e}") from e
    if len(raw) != 32:
        raise BundleError(
            f"signing key must decode to exactly 32 bytes, got {len(raw)}")
    return raw


def public_key_for(seed: bytes) -> str:
    """The base64 public key an auditor needs to verify. The seed never leaves here."""
    return base64.b64encode(aws_ed25519.publickey(seed)).decode("ascii")


#: Emitted when the caller had no coverage manifest to supply. An EMPTY coverage section
#: would be read as "nothing was missed" -- the exact phantom pass this whole artifact
#: exists to prevent -- so absence has to be stated rather than represented as {}.
COVERAGE_UNAVAILABLE = (
    "No coverage manifest was supplied to this bundle, so it records nothing about which "
    "checks were skipped, which regions went unread, or which reads were denied. This is "
    "NOT a statement that the scan was complete. A bundle built from the scanner's own "
    "evidence pack carries the manifest; one assembled from stored scan results may not, "
    "because the manifest is produced at scan time.")


def _coverage_section(coverage: Optional[Mapping]) -> dict:
    """Coverage, or an explicit statement that there is none.

    The distinction between "the scan found no gaps" and "we do not know what the scan
    missed" is the single most important one in a compliance artifact, and `{}` collapses
    them. Callers with real coverage get it verbatim; callers without get a section whose
    contents say so, and which is covered by the signature like everything else."""
    cov = dict(coverage or {})
    if cov:
        return {"available": True, **cov}
    return {"available": False, "note": COVERAGE_UNAVAILABLE}


# ── build ───────────────────────────────────────────────────────────────────
def build_bundle(pack: Optional[Mapping],
                 *,
                 coverage: Optional[Mapping] = None,
                 permissions: Optional[Mapping] = None,
                 scope: Optional[Mapping] = None,
                 producer: Optional[Mapping] = None,
                 generated_at: str,
                 seed: Optional[bytes] = None) -> dict:
    """Assemble the bundle and, if a seed is supplied, sign it.

    `generated_at` is required and injected rather than read from the clock here, so the
    output is a pure function of its inputs and a test can assert byte-for-byte stability.

    When `seed` is None the bundle is emitted with `signature: null` AND an
    `unsigned_reason` -- never with the field omitted. An absent field reads as an older
    format or an oversight; an explicit null with a reason reads as what it is.
    """
    sections = {
        "pack": dict(pack or {}),
        "coverage": _coverage_section(coverage),
        "permissions": dict(permissions or {}),
        "scope": dict(scope or {}),
        "producer": dict(producer or {}),
    }
    digests = {name: digest(sections[name]) for name in SIGNED_SECTIONS}

    # The manifest is what gets signed. It deliberately EXCLUDES the section bodies and
    # includes their digests instead: the signature then covers the content transitively,
    # and a verifier can report WHICH section changed rather than only that something did.
    manifest = {
        "kind": BUNDLE_KIND,
        "bundle_version": BUNDLE_VERSION,
        "generated_at": generated_at,
        "digests": digests,
        "attestation": ATTESTATION,
    }
    root = digest(manifest)

    bundle = {
        "kind": BUNDLE_KIND,
        "bundle_version": BUNDLE_VERSION,
        "generated_at": generated_at,
        "attestation": ATTESTATION,
        "sections": sections,
        "digests": digests,
        "root": root,
        "signature": None,
        "unsigned_reason": None,
    }

    if seed is None:
        bundle["unsigned_reason"] = (
            "No signing key was configured, so this bundle carries integrity digests but "
            "no proof of origin. Anyone can recompute the digests; nobody can show who "
            "produced it. Configure a signing key to make it verifiable.")
        return bundle

    signature = aws_ed25519.sign(seed, canonical(manifest))
    bundle["signature"] = {
        "alg": "ed25519",
        "public_key": public_key_for(seed),
        "value": base64.b64encode(signature).decode("ascii"),
        "signed": "root manifest (kind, bundle_version, generated_at, digests, attestation)",
    }
    bundle["unsigned_reason"] = None
    return bundle


# ── verify ──────────────────────────────────────────────────────────────────
def verify_bundle(bundle: Optional[Mapping],
                  *, expect_public_key: Optional[str] = None) -> dict:
    """Check a bundle end to end and report precisely what is wrong.

    Returns a dict rather than a bool because "invalid" is not an actionable answer for an
    auditor. The three failures mean completely different things and must be
    distinguishable: a section digest mismatch means the CONTENT was edited and names
    which part; a root mismatch means the manifest was edited; a signature failure means
    the bundle came from a different key. A verifier that collapses those into False
    invites the reader to shrug.

    `expect_public_key` pins the expected signer. Without it, verification proves internal
    consistency and that *some* key signed it -- which a forger also satisfies by signing
    with their own key. Pass the key you trust, or treat `signed_by` as unauthenticated.
    """
    problems = []
    if not isinstance(bundle, Mapping):
        return {"ok": False, "signed": False, "problems": ["bundle is not an object"],
                "tampered_sections": [], "signed_by": None}

    if bundle.get("kind") != BUNDLE_KIND:
        problems.append(f"not an {BUNDLE_KIND} (kind={bundle.get('kind')!r})")
    if bundle.get("bundle_version") != BUNDLE_VERSION:
        problems.append(
            f"unsupported bundle_version {bundle.get('bundle_version')!r}; "
            f"this verifier understands {BUNDLE_VERSION}")

    sections = bundle.get("sections")
    declared = bundle.get("digests")
    tampered = []
    if not isinstance(sections, Mapping) or not isinstance(declared, Mapping):
        problems.append("bundle is missing its sections or digests")
    else:
        for name in SIGNED_SECTIONS:
            if name not in sections:
                # A REMOVED section is the attack this whole design exists to stop --
                # dropping `coverage` would turn "we never looked" into silence.
                problems.append(f"section {name!r} is missing")
                tampered.append(name)
                continue
            if digest(sections[name]) != declared.get(name):
                problems.append(f"section {name!r} does not match its digest")
                tampered.append(name)
        for name in declared:
            if name not in SIGNED_SECTIONS:
                problems.append(f"unexpected digest entry {name!r}")

    manifest = {
        "kind": bundle.get("kind"),
        "bundle_version": bundle.get("bundle_version"),
        "generated_at": bundle.get("generated_at"),
        "digests": dict(declared) if isinstance(declared, Mapping) else declared,
        "attestation": bundle.get("attestation"),
    }
    try:
        root_ok = digest(manifest) == bundle.get("root")
    except BundleError as e:
        root_ok = False
        problems.append(str(e))
    if not root_ok:
        problems.append("root digest does not match the manifest")

    sig = bundle.get("signature")
    signed = False
    signed_by = None
    if sig is None:
        # Not a problem in itself -- an unsigned bundle is a legitimate state. It is only
        # a problem if the caller pinned a key, i.e. expected one.
        if expect_public_key:
            problems.append("bundle is unsigned but a signer was expected")
    elif not isinstance(sig, Mapping):
        problems.append("signature is present but malformed")
    elif sig.get("alg") != "ed25519":
        problems.append(f"unsupported signature algorithm {sig.get('alg')!r}")
    else:
        try:
            pub = base64.b64decode(sig.get("public_key") or "", validate=True)
            raw = base64.b64decode(sig.get("value") or "", validate=True)
            signed = aws_ed25519.verify(pub, canonical(manifest), raw)
        except (binascii.Error, ValueError, TypeError):
            signed = False
        if not signed:
            problems.append("signature does not verify against the manifest")
        else:
            signed_by = sig.get("public_key")
            if expect_public_key and signed_by != expect_public_key:
                problems.append(
                    "bundle is correctly signed, but by a different key than expected")
                signed = False

    return {
        "ok": not problems,
        "signed": signed,
        "signed_by": signed_by,
        "tampered_sections": sorted(set(tampered)),
        "problems": problems,
    }
