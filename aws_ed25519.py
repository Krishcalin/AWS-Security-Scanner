#!/usr/bin/env python3
"""aws_ed25519.py — vendored, dependency-free Ed25519 (RFC 8032) sign/verify.

Why vendored: the offline vuln-feed bundle (``overwatch-vulndb``) is signed by the feed
publisher and VERIFIED inside the air-gapped runtime. A true asymmetric detached signature
means the runtime ships only a PUBLIC key and can never forge a feed, yet ``requirements-core``
stays boto3-only — no ``cryptography``/``pynacl`` binary wheel in the arch-portable, air-gap
wheelhouse. Pure ``hashlib`` (SHA-512) + integer math; the runtime calls only :func:`verify`.

This is a straightforward RFC 8032 reference implementation. It is constant-time-agnostic
(fine — it verifies PUBLIC feed data with a PUBLIC key; there is no secret to leak on the
verify path), and validated against RFC 8032 §7.1 known-answer vectors + round-trip/tamper
tests in tests/test_ed25519.py.
"""
from __future__ import annotations

import hashlib

_b = 256
_q = (1 << 255) - 19
_L = (1 << 252) + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + denom) % _q
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - denom) % _q
    return (x3, y3)


def _scalarmult(P, e: int):
    """Iterative double-and-add (no recursion — a 512-bit scalar in verify is fine)."""
    result = (0, 1)          # the identity element
    addend = P
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _encodepoint(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << (_b - 1))).to_bytes(_b // 8, "little")


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s: bytes):
    val = int.from_bytes(s, "little")
    y = val & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != ((val >> (_b - 1)) & 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoded point is not on the curve")
    return P


def _clamp_scalar(h32: bytes) -> int:
    a = int.from_bytes(h32, "little")
    return (a & ((1 << 254) - 8)) | (1 << 254)   # clear bits 0-2 & 255, set bit 254


def publickey(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte secret seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    a = _clamp_scalar(_H(seed)[:32])
    return _encodepoint(_scalarmult(_B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    """Ed25519-sign ``msg`` with a 32-byte secret ``seed`` → a 64-byte detached signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _clamp_scalar(h[:32])
    A = _encodepoint(_scalarmult(_B, a))
    r = int.from_bytes(_H(h[32:64] + msg), "little")
    R = _encodepoint(_scalarmult(_B, r))
    k = int.from_bytes(_H(R + A + msg), "little")
    S = (r + k * a) % _L
    return R + S.to_bytes(_b // 8, "little")


def verify(public_key: bytes, msg: bytes, signature: bytes) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature of ``msg`` under ``public_key``.
    Never raises — a malformed key/signature returns False (the runtime fails closed)."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
        S = int.from_bytes(signature[32:64], "little")
        if S >= _L:                       # non-canonical S — reject
            return False
        k = int.from_bytes(_H(signature[:32] + public_key + msg), "little")
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, k))
    except Exception:
        return False


def keypair(seed: bytes) -> tuple:
    """(seed, public_key) — the seed IS the private key material; keep it offline."""
    return seed, publickey(seed)
