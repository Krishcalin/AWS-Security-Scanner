"""Phase-4 Slice-2 · B1 — the zero-telemetry TRIPWIRE.

OverWatch makes ZERO telemetry / analytics / phone-home / update-check calls. Every
egress is either an AWS API (boto3) or an operator-configured, opt-in, injected seam
pointed at the operator's OWN resources (see NETWORK.md). This test locks that in: it
fails the moment someone adds a telemetry SDK, a network primitive outside the two
allowlisted files, a hardcoded non-AWS/non-connector egress host, or loosens the SSRF/
TLS guards. Pure stdlib + pytest; reads source, touches no network.
"""
import ast
import glob
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# trees that are not shipped application code (or are the test/build tooling itself)
_EXCLUDE_DIRS = ("tests", "frontend", "deploy", "docs", "scratchpad", "reports",
                 "evidence", "__pycache__", ".venv", ".git", ".pytest_cache")


def _app_modules():
    """Every application module OverWatch ships — recursively, so a telemetry call cannot
    hide in a subpackage (e.g. scripts/) or a future package layout. Only genuinely non-app
    trees are excluded."""
    out = []
    for f in glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True):
        rel = os.path.relpath(f, ROOT)
        if rel.split(os.sep)[0] in _EXCLUDE_DIRS:
            continue
        out.append(f)
    return sorted(out)


def _src(path):
    return open(path, encoding="utf-8").read()


# ── A. no telemetry / analytics / crash-reporter SDKs ─────────────────────────
_TELEMETRY_SDKS = ("sentry_sdk", "sentry", "posthog", "mixpanel", "segment",
                   "amplitude", "datadog", "ddtrace", "newrelic", "bugsnag",
                   "rollbar", "opentelemetry", "analytics", "statsd")


def test_no_telemetry_sdk_imports():
    offenders = []
    for f in _app_modules():
        for node in ast.walk(ast.parse(_src(f), f)):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for n in names:
                if n in _TELEMETRY_SDKS:
                    offenders.append(f"{os.path.basename(f)}: import {n}")
    assert offenders == [], f"telemetry/analytics SDK imported: {offenders}"


# ── B. network primitives are confined to the two allowlisted egress files ────
# The ONLY files permitted to import a socket-touching primitive. Adding a new file to
# this set is the signal that forces a security review (update NETWORK.md too).
EGRESS_ALLOWLIST = {"aws_kube.py", "cnapp_connectors.py"}
# urllib.parse / urllib.error are NOT network I/O (string ops / exception types) and are
# allowed anywhere; the real egress primitives are these (client + server + mail/ftp/rpc +
# 3rd-party http + shell-out via subprocess):
_EGRESS_MODULES = {"urllib.request", "http.client", "http.server", "socket", "ssl",
                   "requests", "httpx", "aiohttp", "urllib3", "websockets",
                   "smtplib", "ftplib", "poplib", "telnetlib", "xmlrpc.client",
                   "subprocess"}


def _imported_modules(node):
    """The dotted module names a node imports. Reconstructs the child for the
    ``from urllib import request`` form (node.module='urllib' + name='request' ->
    'urllib.request') so it can't slip past a dotted-name allowlist."""
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module] + [f"{node.module}.{a.name}" for a in node.names]
    return []


def test_network_primitives_are_allowlisted():
    for f in _app_modules():
        base = os.path.basename(f)
        for node in ast.walk(ast.parse(_src(f), f)):
            for m in _imported_modules(node):
                if m in _EGRESS_MODULES and base not in EGRESS_ALLOWLIST:
                    pytest.fail(f"{base} imports the network primitive {m!r} but is not in "
                                f"EGRESS_ALLOWLIST {sorted(EGRESS_ALLOWLIST)} — every egress "
                                f"must be an operator-opt-in injected seam (see NETWORK.md)")


def test_no_shell_out_egress():
    """No module shells out (os.system / os.popen) — a curl/wget subprocess would be an
    egress the import-allowlist can't see. (subprocess imports are caught above.)"""
    for f in _app_modules():
        for node in ast.walk(ast.parse(_src(f), f)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os" and node.func.attr in ("system", "popen")):
                pytest.fail(f"{os.path.basename(f)} calls os.{node.func.attr} — a shell-out is a "
                            f"potential egress the guard cannot inspect")


# ── C. no hardcoded non-AWS / non-connector egress host ───────────────────────
# Every hardcoded host that appears in a URL literal, each justified. A NEW host here
# fails the test until it is reviewed + added (a CDN / update-check / analytics endpoint
# would trip this). AWS suffixes cover regional endpoints (sts.<region>.amazonaws.com …).
_AWS_SUFFIXES = ("amazonaws.com", "aws.amazon.com")
_ALLOWED_HOSTS = {
    # AWS console / sign-in (onboarding launch URLs) + STS endpoint prefix
    "console.aws.amazon.com", "signin.aws.amazon.com", "sts.",
    # operator opt-in connector renderer targets (only hit when that connector is enabled)
    "slack.com", "events.pagerduty.com", "events.eu.pagerduty.com",
    # defensive literal (BLOCKED by the SSRF guard), placeholders, and self-references
    "169.254.169.254",          # IMDS — blocked in _is_blocked_host, never a destination
    "overwatch.local",          # sample/placeholder host
    "json.schemastore.org",     # SARIF $schema IDENTIFIER written into output, never fetched
    "github.com",               # this tool's own repo URL in SARIF helpUri/informationUri
}


def _host_ok(host):
    return (host in _ALLOWED_HOSTS or host.endswith(_AWS_SUFFIXES)
            or host in ("", "...") or host.startswith(("127.", "localhost")))


def test_no_hardcoded_foreign_egress_host():
    found = {}
    for f in _app_modules():
        for m in re.finditer(r"https?://([A-Za-z0-9._\-]+)", _src(f)):
            found.setdefault(m.group(1), os.path.basename(f))
    foreign = {h: v for h, v in found.items() if not _host_ok(h)}
    assert foreign == {}, (f"hardcoded non-AWS/non-connector host(s): {foreign} — if this is a "
                           f"legitimate operator seam, add it to _ALLOWED_HOSTS + NETWORK.md; "
                           f"a telemetry/CDN/update endpoint must never appear")


# ── D. the SSRF / TLS guards on the two egress seams stay tight ───────────────
def test_connector_ssrf_guard_pinned():
    import cnapp_connectors as cc
    assert cc._is_blocked_host("169.254.169.254")           # IMDS blocked
    assert cc._is_blocked_host("metadata.google.internal")  # cloud-metadata blocked
    src = _src(os.path.join(ROOT, "cnapp_connectors.py"))
    # https-only + no cross-host redirect must remain in default_http_post's neighborhood
    assert 'scheme' in src and '"https"' in src
    assert "_NoCrossHost" in src


def test_kube_seam_is_ca_pinned_and_readonly():
    src = _src(os.path.join(ROOT, "aws_kube.py"))
    assert "create_default_context(cadata=" in src          # TLS pinned to the cluster CA
    assert 'method="GET"' in src                            # read-only
