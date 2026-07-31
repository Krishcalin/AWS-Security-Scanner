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


# ── per-call allowlist is PORT-AWARE (a self-hosted registry on a non-443 port works) ──
def test_host_allowlist_is_port_aware():
    # a port-qualified registry host must be allowed for its own URL (urlparse strips the port)
    assert LF._host_allowed("https://harbor.corp:5000/v2/", {"harbor.corp:5000"})
    # a bare-host allowlist entry matches any port on that host
    assert LF._host_allowed("https://harbor.corp:5000/v2/", {"harbor.corp"})
    assert LF._host_allowed("https://ghcr.io/v2/", {"ghcr.io"})
    # a DIFFERENT host is still refused, port-qualified or not
    assert not LF._host_allowed("https://evil.com:5000/v2/", {"harbor.corp:5000"})
    assert not LF._host_allowed("https://harbor.evil.com/v2/", {"harbor.corp"})


# ── redirect guard: a 3xx to a non-AWS / downgraded target is refused (ECR default) ──
def test_redirect_to_non_aws_or_downgrade_is_blocked():
    h = LF._AllowlistRedirect(None)                   # None -> the ECR .amazonaws.com default
    assert h.redirect_request(None, None, 302, "", {}, "https://evil.com/x") is None
    assert h.redirect_request(None, None, 302, "", {}, "http://b.s3.us-east-1.amazonaws.com/x") is None
    assert h.redirect_request(None, None, 302, "", {}, "https://169.254.169.254/latest") is None


# ── blob redirect: SSRF-target refused; cross-host hop STRIPS the Bearer, same-host keeps it ──
def test_blob_redirect_refuses_ssrf_and_downgrade():
    h = LF._BlobRedirect()
    req = LF.urllib.request.Request("https://reg.example.com/v2/app/blobs/sha256:x")
    assert h.redirect_request(req, None, 302, "", {}, "http://blobs.example.com/x") is None   # downgrade
    assert h.redirect_request(req, None, 302, "", {}, "https://169.254.169.254/x") is None    # IMDS
    assert h.redirect_request(req, None, 302, "", {}, "https://metadata.google.internal/x") is None


# ── SSRF blocklist must survive IP-encoding evasions (IPv4-mapped IPv6 / integer / hex / :: ) ──
def test_is_ssrf_target_catches_encoded_forms():
    for bad in ("169.254.169.254", "127.0.0.1", "::1", "localhost", "100.100.100.200",
                "::ffff:169.254.169.254", "::ffff:127.0.0.1", "0.0.0.0", "::",
                "2130706433", "0x7f000001", "10.0.0.5", "192.168.1.1", "[::ffff:127.0.0.1]"):
        assert LF._is_ssrf_target(bad), bad
    for ok in ("harbor.corp.internal", "ghcr.io", "blobs.example.net", "8.8.8.8"):
        assert not LF._is_ssrf_target(ok), ok


def test_blob_redirect_refuses_encoded_ssrf_targets():
    h = LF._BlobRedirect()
    req = LF.urllib.request.Request("https://reg.example.com/v2/app/blobs/sha256:x")
    for bad in ("https://[::ffff:169.254.169.254]/latest/meta-data/",
                "https://[::ffff:127.0.0.1]/admin", "https://0.0.0.0/", "https://[::]/"):
        assert h.redirect_request(req, None, 302, "", {}, bad) is None, bad


def test_blob_redirect_strips_bearer_cross_host_keeps_same_host():
    h = LF._BlobRedirect()
    req = LF.urllib.request.Request("https://reg.example.com/v2/app/blobs/sha256:x",
                                    headers={"Authorization": "Bearer SECRET"})
    # cross-host redirect to the blob store: the Bearer must NOT travel with it
    cross = h.redirect_request(req, None, 302, "", {}, "https://blobs.example.net/obj?sig=abc")
    assert cross is not None and cross.get_header("Authorization") is None
    # a same-host redirect legitimately keeps the credential
    same = h.redirect_request(req, None, 302, "", {}, "https://reg.example.com/v2/app/blobs/other")
    assert same is not None and same.get_header("Authorization") == "Bearer SECRET"


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
