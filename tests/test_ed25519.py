"""Vendored Ed25519 (aws_ed25519) — the signer for the offline vuln-feed bundle. Validated
against a published known-answer vector (the canonical 00..1f seed) plus round-trip, tamper-
rejection, determinism, and fail-closed malformed-input handling. Pure stdlib; no boto."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ed25519 as ed

# KAT: the well-known Ed25519 test seed 000102…1f maps to this public key (documented in the
# NaCl/ref10 test suite and reproducible from RFC 8032). A wrong curve constant fails this.
KAT_SEED = bytes(range(32))
KAT_PUB = bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")


def test_public_key_known_answer():
    assert ed.publickey(KAT_SEED) == KAT_PUB


def test_sign_verify_round_trip():
    seed = bytes.fromhex("aa" * 32)
    pub = ed.publickey(seed)
    for msg in (b"", b"the feed", b"\x00\x01\x02", b"x" * 1000):
        sig = ed.sign(seed, msg)
        assert len(sig) == 64
        assert ed.verify(pub, msg, sig) is True


def test_signature_is_deterministic():
    seed = bytes.fromhex("bb" * 32)
    assert ed.sign(seed, b"feed") == ed.sign(seed, b"feed")


def test_tampered_message_rejected():
    seed = bytes.fromhex("cc" * 32)
    pub = ed.publickey(seed)
    sig = ed.sign(seed, b"authentic feed")
    assert ed.verify(pub, b"authentic feeX", sig) is False


def test_tampered_signature_rejected():
    seed = bytes.fromhex("dd" * 32)
    pub = ed.publickey(seed)
    sig = bytearray(ed.sign(seed, b"feed"))
    sig[10] ^= 0x01
    assert ed.verify(pub, b"feed", bytes(sig)) is False


def test_wrong_public_key_rejected():
    sig = ed.sign(bytes.fromhex("ee" * 32), b"feed")
    other_pub = ed.publickey(bytes.fromhex("ff" * 32))
    assert ed.verify(other_pub, b"feed", sig) is False


def test_malformed_inputs_fail_closed_no_raise():
    seed = bytes.fromhex("11" * 32)
    pub = ed.publickey(seed)
    assert ed.verify(pub, b"m", b"tooshort") is False
    assert ed.verify(b"shortkey", b"m", ed.sign(seed, b"m")) is False
    assert ed.verify(b"\x00" * 32, b"m", b"\x00" * 64) is False   # bogus but well-formed


def test_non_canonical_S_rejected():
    # S must be reduced mod L; a signature with S >= L is non-canonical and rejected.
    seed = bytes.fromhex("22" * 32)
    pub = ed.publickey(seed)
    sig = bytearray(ed.sign(seed, b"feed"))
    sig[32:64] = (b"\xff" * 32)                    # S = 2^256-1 >> L
    assert ed.verify(pub, b"feed", bytes(sig)) is False
