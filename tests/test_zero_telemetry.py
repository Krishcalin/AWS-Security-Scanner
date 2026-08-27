"""Phase-4 Slice-2 · B1 — the zero-telemetry TRIPWIRE.

OverWatch makes ZERO telemetry / analytics / phone-home / update-check calls. Every
egress is either an AWS API (boto3) or an operator-configured, opt-in, injected seam
pointed at the operator's OWN resources (see NETWORK.md). This test locks that in: it
fails the moment someone adds a telemetry SDK, a network primitive outside the two
allowlisted files, a hardcoded non-AWS/non-connector egress host, or loosens the SSRF/
TLS guards. Pure stdlib + pytest; reads source, touches no network.

Sections A-E are about EGRESS: what OverWatch sends. Section F is about INGEST: what
OverWatch is allowed to absorb in the first place. That distinction was invisible
while every ingest source was a config API, and it stops being invisible the moment
an AI detection plane exists, because the interesting fields in that plane are the
customer's prompts. A guard that only watches the exit is satisfied by a product that
reads prompt text into its own graph and then hands it to a customer-configured Jira
connector -- egress the operator asked for, carrying content they never agreed to
share. Sections A-E would pass that build green. Section F is why they no longer do.
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
# aws_layer_fetch.py: the ECR layer-blob GET seam (HTTPS + *.amazonaws.com only, byte-capped,
# opt-in behind --side-scan-images + the CnappImageLayerPull grant). See test_layer_fetch.py.
# Batch 6 GENERALIZED this same file to non-AWS OCI registries (registry_request / registry_blob_get,
# per-call host allowlist) — the allowlist does NOT grow: all registry egress stays in this one file.
# The pull ADAPTERS (aws_registry_oci / aws_registry_connectors) are PURE — they take injected seams
# and must NEVER appear here (test_registry_modules_are_pure pins that).
EGRESS_ALLOWLIST = {"aws_kube.py", "cnapp_connectors.py", "aws_layer_fetch.py"}
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


#: XML namespace URIs are IDENTIFIERS, not endpoints — nothing dereferences them, and
#: an SVG without its namespace does not render. Matched on the FULL URI rather than
#: the host, so `www.w3.org` remains forbidden as an egress target while
#: `http://www.w3.org/2000/svg` is understood for what it is.
#:
#: The distinction has to live here rather than in _ALLOWED_HOSTS: putting w3.org
#: there would assert "we may connect to this", which is exactly the claim this test
#: exists to prevent anyone making by accident.
_XML_NAMESPACES = (
    "http://www.w3.org/2000/svg",            # aws_qr.to_svg
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/XML/1998/namespace",
)


def test_no_hardcoded_foreign_egress_host():
    found = {}
    for f in _app_modules():
        src = _src(f)
        for m in re.finditer(r"https?://([A-Za-z0-9._\-]+)[^\s\"'<>)]*", src):
            if m.group(0).rstrip("\"'") in _XML_NAMESPACES:
                continue
            found.setdefault(m.group(1), os.path.basename(f))
    foreign = {h: v for h, v in found.items() if not _host_ok(h)}
    assert foreign == {}, (f"hardcoded non-AWS/non-connector host(s): {foreign} — if this is a "
                           f"legitimate operator seam, add it to _ALLOWED_HOSTS + NETWORK.md; "
                           f"a telemetry/CDN/update endpoint must never appear")


# ── D. the SSRF / TLS guards on the two egress seams stay tight ───────────────
def test_connector_ssrf_guard_pinned():
    from hub import cnapp_connectors as cc
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


# ── E. Batch 6: the non-AWS registry pull adapters are PURE; the egress stays tight ──
def test_registry_modules_are_pure():
    """aws_registry_oci + aws_registry_connectors are the non-AWS registry PULL adapters. They must
    take the http seams by INJECTION (from aws_layer_fetch) and never hold a network primitive of
    their own — so they are outside EGRESS_ALLOWLIST. (The generic sweep in
    test_network_primitives_are_allowlisted also enforces this; this pins the intent by name.)"""
    for mod in ("aws_registry_oci.py", "aws_registry_connectors.py"):
        assert mod not in EGRESS_ALLOWLIST                  # they are NOT egress files
        for node in ast.walk(ast.parse(_src(os.path.join(ROOT, mod)), mod)):
            for m in _imported_modules(node):
                assert m not in _EGRESS_MODULES, f"{mod} imported the network primitive {m!r}"


def test_registry_egress_guard_pinned():
    """The Batch-6 generalization of aws_layer_fetch keeps the SSRF/TLS posture: https-only, a
    per-call host allowlist (NO 'any https'), SSRF targets (IMDS / cloud-metadata / loopback)
    refused on a blob redirect, TLS verified, and NO hardcoded FOREIGN registry host (only the ECR
    .amazonaws.com default) — the registry host arrives from operator config + the auth challenge."""
    from engine import aws_layer_fetch as LF
    # SSRF targets a blob redirect must never reach
    for h in ("169.254.169.254", "metadata.google.internal", "127.0.0.1", "localhost",
              "100.100.100.200", "::1"):
        assert LF._is_ssrf_target(h), h
    assert not LF._is_ssrf_target("harbor.corp.internal")   # a legit self-hosted registry is allowed
    # per-call allowlist: an off-allowlist host is refused (no 'any https')
    assert not LF._host_allowed("https://evil.example.com/x", {"ghcr.io"})
    assert LF._host_allowed("https://ghcr.io/v2/", {"ghcr.io"})
    assert not LF._host_allowed("http://ghcr.io/v2/", {"ghcr.io"})   # https-only
    src = _src(os.path.join(ROOT, "aws_layer_fetch.py"))
    assert "create_default_context()" in src                # TLS verified against the system store
    assert "_AllowlistRedirect" in src and "_BlobRedirect" in src
    # no hardcoded FOREIGN registry host literal in the egress file (only the AWS suffix constant)
    for m in re.finditer(r'"([a-z0-9\-]+\.(?:io|com|net|azurecr\.io))"', src):
        host = m.group(1)
        assert host.endswith("amazonaws.com"), f"unexpected host literal in egress file: {host!r}"


# ══════════════════════════════════════════════════════════════════════════════
# F. INGEST-side containment — what may ENTER the product
#
# Sections A-E prove OverWatch does not phone home. They say nothing about what it
# absorbs. These assertions are the other half: the ingest plane may take STRUCTURE
# and IDENTIFIERS off a third-party event, never model conversation content, and it
# must do so field-by-field so that a reviewer reading a diff can see every field
# that just entered the product.
#
# On the deliberate narrowness of _CONTENT_KEYS: it names keys that can only be
# conversation payloads. It does NOT include "text", "message" or "content", which
# the spec suggested, because aws_ingest.py:190 reads SARIF `text`/`markdown` (a
# scanner's own finding description) and normalize_falco reads `output` (a rule
# message) -- both legitimate, both pre-existing. A denylist that fires on correct
# code is a denylist someone deletes, and a deleted tripwire protects nothing. The
# general case is caught structurally instead, by F2: content cannot arrive under
# ANY key name if evidence dicts must be written out key by key.
# ══════════════════════════════════════════════════════════════════════════════

# Every module that turns a THIRD-PARTY payload into something OverWatch stores.
# aws_ingest_pentest.py is here because its INPUT is the most content-dense of any
# ingest OverWatch performs: a garak report contains the attack prompts and the
# model's responses verbatim. The module reads verdict rows only, and this is what
# keeps that true rather than taking its word for it.
# aws_ingest_aidr.py joins for the same reason aws_ingest_pentest.py did, only more
# so: an AI runtime detector SITS IN THE REQUEST PATH, so its natural output is the
# most content-dense payload any ingest here will ever be offered. It is the one place
# D2 is most tempting to lose.
_INGEST_MODULES = ("aws_cdr.py", "aws_edr.py", "aws_ingest.py", "aws_airules.py",
                   "aws_ingest_pentest.py", "aws_ingest_aidr.py")

# Keys whose value is model input/output. Reading one of these is reading a prompt.
_CONTENT_KEYS = frozenset({
    "prompt", "prompts", "completion", "completions",
    "input_body", "output_body", "inputbodyjson", "outputbodyjson",
    "inputbody", "outputbody", "prompttext", "completiontext",
    "model_input", "model_output", "modelinput", "modeloutput",
    "invocationinput", "invocationoutput", "inputtext", "outputtext",
    "messages", "arguments", "tool_input", "toolinput",
    "systemprompt", "system_prompt", "user_message", "assistant_message",
})

# Helpers a normalizer may route an evidence dict through. Each must take a dict
# LITERAL as its first argument, so the fields are still written out one by one.
_EVIDENCE_WRAPPERS = ("_wrap_identity", "_wrap_blast_radius")


def _ingest_sources():
    for name in _INGEST_MODULES:
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            yield name, _src(path)


def _dict_keys_read(src):
    """Every string literal used to pull a value out of a mapping: obj.get("K"),
    obj["K"], and the keys of dict literals the module builds."""
    tree = ast.parse(src)
    keys = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            keys.add(node.args[0].value)
        elif (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)):
            keys.add(node.slice.value)
        elif isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    return keys


def content_keys_in(src):
    """The model-content keys a source touches. Public: the poisoned fixture calls it."""
    return {k for k in _dict_keys_read(src) if k.lower().replace("-", "_") in _CONTENT_KEYS
            or k.lower() in _CONTENT_KEYS}


def _dict_is_written_out(node):
    """True iff a dict literal names every key — no ``**other`` laundering a payload."""
    return isinstance(node, ast.Dict) and all(k is not None for k in node.keys)


def evidence_violations_in(src):
    """Every `evidence=` argument that is not written out field by field.

    Returns a list of human-readable violations. Public: the poisoned fixture and the
    real modules are both checked through this one function, so the guard and the
    proof that the guard works cannot drift apart."""
    tree = ast.parse(src)
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg != "evidence":
                continue
            v = kw.value
            if _dict_is_written_out(v):
                continue
            if (isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                    and v.func.id in _EVIDENCE_WRAPPERS
                    and v.args and _dict_is_written_out(v.args[0])):
                continue
            bad.append(f"line {getattr(v, 'lineno', '?')}: "
                       f"evidence={ast.dump(v)[:80]}")
    return bad


def _annotated_fields(src, class_name):
    """The annotated field names of a dataclass, read statically."""
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return [b.target.id for b in node.body
                    if isinstance(b, ast.AnnAssign) and isinstance(b.target, ast.Name)]
    raise AssertionError(f"{class_name} not found")


# ── F1. the ingest plane never reads model conversation content ──────────────
def test_no_ingest_module_reads_model_conversation_content():
    """A normalizer that reads a prompt has already made OverWatch a processor of
    the customer's model traffic, whatever it does with the value afterwards."""
    offenders = {}
    for name, src in _ingest_sources():
        found = content_keys_in(src)
        if found:
            offenders[name] = sorted(found)
    assert not offenders, (
        f"ingest modules read model conversation content: {offenders}. "
        "OverWatch is sold on reading CONFIG, not data. If this is deliberate it "
        "needs the FLOW-00 shape (separate opt-in policy, off by default, "
        "resource-scoped, failing open to a numbered note) and an explicit entry "
        "here — not a silent key read.")


# ── F2. evidence is written out field by field, never splatted ───────────────
def test_evidence_dicts_are_written_out_not_splatted():
    """`evidence` is a free-form dict on NormalizedDetection, which makes it the one
    place arbitrary third-party payload can enter without changing a signature.
    Requiring a literal means every field that enters is visible in the diff."""
    offenders = {}
    for name, src in _ingest_sources():
        bad = evidence_violations_in(src)
        if bad:
            offenders[name] = bad
    assert not offenders, (
        f"evidence dict built from an unenumerated source: {offenders}. "
        "Write the fields out by name so a reviewer can see what enters.")


# ── F3/F4. the two contracts that carry data onward are closed sets ──────────
def test_normalized_detection_is_a_closed_set_of_fields():
    """Adding a content-bearing field to the ingest contract must be a conscious
    diff against this list, not an incidental one."""
    fields = _annotated_fields(_src(os.path.join(ROOT, "aws_cdr.py")),
                               "NormalizedDetection")
    assert fields == ["id", "source", "type", "title", "severity", "band",
                      "node_kind", "node_key", "resource_arn", "first_seen",
                      "evidence"], (
        f"NormalizedDetection fields changed: {fields}. If a field was added, "
        "confirm it cannot carry model input/output, then update this list.")


def test_enriched_finding_is_a_closed_set_of_fields():
    """The connector plane is where an ingest leak becomes a headline: it is the only
    surface that sends finding content to a third party the operator configured."""
    fields = _annotated_fields(_src(os.path.join(ROOT, "cnapp_connectors.py")),
                               "EnrichedFinding")
    assert fields == ["check_id", "section", "severity", "status", "compliance",
                      "remediation_cmd", "risk", "impact", "steps", "affected",
                      "count", "distinct", "account", "on_attack_path"], (
        f"EnrichedFinding fields changed: {fields}. Everything here is rendered into "
        "Jira/Slack/PagerDuty/Splunk payloads. A field added here leaves the estate.")


# ── F5. the tripwire is PROVEN to fire ───────────────────────────────────────
_POISONED = os.path.join(ROOT, "tests", "fixtures", "poisoned_normalizer.py")


def test_the_poisoned_fixture_exists():
    assert os.path.isfile(_POISONED), (
        "the fixture that proves Section F fires has been deleted; without it these "
        "assertions have never been observed to reject anything")


def test_f1_rejects_the_poisoned_fixture():
    found = content_keys_in(_src(_POISONED))
    assert "prompt" in found and "outputBodyJson" in found, (
        f"F1 did not catch the deliberately poisoned normalizer (saw {sorted(found)})")


def test_f2_rejects_the_poisoned_fixture():
    bad = evidence_violations_in(_src(_POISONED))
    assert len(bad) >= 2, (
        f"F2 must reject BOTH the splatted dict and the bare raw event, got {bad}")


def test_the_poisoned_fixture_is_not_shipped():
    """It lives under tests/ and must never be reachable from application code."""
    assert _POISONED not in _app_modules()
    for path in _app_modules():
        assert "poisoned_normalizer" not in _src(path), f"{path} imports the fixture"


# ── G. the MCP seam: what we CAN pin, and an honest note on what we cannot ────
# Slice 1.5 / decision D6. This section is different in kind from A-F, and the
# difference is worth stating rather than glossing.
#
# A-F constrain OUR code and, between them, prove that OverWatch does not send data
# anywhere. Section G cannot make that claim, because an MCP server's whole purpose is
# to hand data to a client process we did not write, running on the operator's machine,
# configured with a model we cannot see. A local stdio server passes every assertion in
# A-F trivially while being the largest data-egress DECISION in the product.
#
# So this section pins the three things that are actually ours to pin:
#   G1  the server cannot start without an explicit operator acknowledgement,
#   G2  it never imports the scanner (which would let it reach AWS, and would put one
#       stray coloured print between us and a corrupted protocol stream),
#   G3  redaction is the DEFAULT construction, not an option somebody remembers.
#
# What it does NOT prove, and what no test here could: that the client kept the data
# inside the boundary. That is documented in docs/MCP.md and stated in the server's own
# initialize instructions, and it is the reason the gate exists at all.
_MCP = os.path.join(ROOT, "cnapp_mcp.py")


def test_g1_the_mcp_server_is_fail_closed(monkeypatch, capsys):
    """The gate is the boundary. If this ever defaults to open, the zero-telemetry
    story quietly stops covering the largest egress in the product.

    monkeypatch.delenv is load-bearing, not tidiness. Without it, a developer working on
    this feature with the acknowledgement exported would have main() start the server and
    block forever on stdin — and an earlier draft guarded that with an `or` clause which
    turned the whole assertion vacuous on exactly that machine."""
    from hub import cnapp_mcp
    monkeypatch.delenv(cnapp_mcp.ACK_ENV, raising=False)
    assert cnapp_mcp.gate({}) == (False, False)
    assert cnapp_mcp.gate({cnapp_mcp.ACK_ENV: "1"}) == (True, False), (
        "acknowledging the client boundary must NOT also enable identifiers")
    assert cnapp_mcp.main([]) != 0, "the server started without an acknowledgement"
    assert capsys.readouterr().out == "", "the refusal must not reach stdout"


def test_g2_the_mcp_server_never_imports_the_scanner():
    """Read-only over a finished report, by construction rather than by intention.
    Importing the scanner would give the server a path to AWS and put its stdout prints
    in the middle of a protocol stream the spec says must carry MCP messages only."""
    forbidden = {"aws_live_scanner", "boto3", "botocore", "cnapp_service", "cnapp_store"}
    for node in ast.walk(ast.parse(_src(_MCP), _MCP)):
        for m in _imported_modules(node):
            root = m.split(".")[0]
            assert root not in forbidden, (
                f"cnapp_mcp.py imports {m!r} — it must read a finished report and "
                f"nothing else")


def test_g3_redaction_is_the_default_construction():
    from hub import cnapp_mcp
    assert cnapp_mcp.Redactor().enabled is True, (
        "a redactor that defaults to off makes every call site the security control")
    r = cnapp_mcp.Redactor()
    assert "123456789012" not in r.text("account 123456789012")
    assert "10.0.0.4" not in r.text("host 10.0.0.4")
    assert "secret-bucket" not in r.text("arn:aws:s3:::secret-bucket")


def test_g4_the_server_writes_diagnostics_to_stderr_only():
    """The MCP spec: "The server MUST NOT write anything to its stdout that is not a
    valid MCP message." A print() added for debugging would break every client, and
    silently — the client just sees a parse error."""
    tree = ast.parse(_src(_MCP), _MCP)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "print":
            pytest.fail("cnapp_mcp.py calls print() — stdout carries MCP messages only; "
                        "use _log() which writes to stderr")
        if isinstance(node, ast.Attribute) and node.attr in ("stdout",) \
                and isinstance(node.value, ast.Name) and node.value.id == "sys":
            pass    # sys.stdout is legitimately the transport; print() is not
