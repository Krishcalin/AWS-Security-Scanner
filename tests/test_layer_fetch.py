"""Phase-4 Slice-5 · B4 + hardening — the aws_layer_fetch.http_get egress guard.

Security-critical rejects (non-https / non-AWS host / non-AWS redirect) raise; success,
byte-cap, and short-read (truncated body) paths mock the opener so no socket is touched.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_layer_fetch as LF


class _Resp:
    def __init__(self, data, headers=None):
        self._d = data
        self.headers = headers or {}

    def read(self, n):
        return self._d[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    def __init__(self, resp=None, err=None):
        self._r, self._e = resp, err

    def open(self, req, timeout=None):
        if self._e:
            raise self._e
        return self._r


def _mock(monkeypatch, *, data=b"", headers=None, err=None):
    monkeypatch.setattr(LF.urllib.request, "build_opener",
                        lambda *h: _Opener(_Resp(data, headers), err))


# ── pre-flight rejects (raise before any network) ────────────────────────────
def test_rejects_non_https():
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("http://bucket.s3.us-east-1.amazonaws.com/blob")


def test_rejects_non_aws_host():
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("https://evil.example.com/layer")


def test_rejects_empty_url():
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("")


# ── redirect guard: a 3xx to a non-AWS / downgraded target is refused ─────────
def test_redirect_to_non_aws_or_downgrade_is_blocked():
    h = LF._AwsOnlyRedirect()
    assert h.redirect_request(None, None, 302, "", {}, "https://evil.com/x") is None
    assert h.redirect_request(None, None, 302, "", {}, "http://b.s3.us-east-1.amazonaws.com/x") is None
    assert h.redirect_request(None, None, 302, "", {}, "https://169.254.169.254/latest") is None


# ── success + byte-cap + short-read (truncation) ─────────────────────────────
def test_success_reads_amazonaws_blob(monkeypatch):
    _mock(monkeypatch, data=b"LAYERBYTES", headers={"Content-Length": "10"})
    assert LF.http_get("https://prod-starport.s3.us-east-1.amazonaws.com/x") == b"LAYERBYTES"


def test_success_without_content_length_header(monkeypatch):
    _mock(monkeypatch, data=b"LAYERBYTES")            # no Content-Length -> no truncation check
    assert LF.http_get("https://b.s3.us-east-1.amazonaws.com/x") == b"LAYERBYTES"


def test_enforces_byte_cap(monkeypatch):
    _mock(monkeypatch, data=b"X" * 100)
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("https://b.s3.us-east-1.amazonaws.com/x", max_bytes=10)


def test_truncated_body_below_content_length_fails_closed(monkeypatch):
    _mock(monkeypatch, data=b"12345", headers={"Content-Length": "10"})   # got 5 of 10
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("https://b.s3.us-east-1.amazonaws.com/x")


def test_network_error_fails_closed(monkeypatch):
    _mock(monkeypatch, err=OSError("connection reset"))
    with pytest.raises(LF.LayerFetchError):
        LF.http_get("https://b.s3.us-east-1.amazonaws.com/x")
