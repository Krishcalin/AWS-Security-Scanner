"""Phase-4 Slice-4 · B7 — the CI/CD image-scan Action's contract: shell-only (no committed
Python under .github/), SSRF-safe single POST, fail-closed on an empty token, and a body the
hub's inventory lane actually accepts."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aws_ingest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTION = os.path.join(ROOT, ".github", "actions", "overwatch-image-scan")
ENTRY = open(os.path.join(ACTION, "entrypoint.sh"), encoding="utf-8").read()
YML = open(os.path.join(ACTION, "action.yml"), encoding="utf-8").read()


def test_action_dir_has_no_python():
    # zero-telemetry: the tripwire scans **/*.py and does NOT exclude .github/ — the Action
    # is shell-only so it carries no importable network primitive.
    pys = [f for _d, _s, fs in os.walk(ACTION) for f in fs if f.endswith(".py")]
    assert pys == []


def test_entrypoint_is_ssrf_safe_and_fail_closed():
    assert "--proto '=https'" in ENTRY and "--max-redirs 0" in ENTRY   # https-only, no redirect
    assert ':?' in ENTRY and "OW_TOKEN" in ENTRY                       # fail closed on empty token
    assert 'case "$OW_HUB_URL" in' in ENTRY and "https://*)" in ENTRY  # hub must be https
    assert "/api/accounts/${OW_ACCOUNT}/ingest" in ENTRY               # the ingest endpoint
    assert "set -euo pipefail" in ENTRY


def test_action_yml_is_composite_and_takes_hub_from_input():
    assert "using: composite" in YML
    for inp in ("image:", "account-id:", "hub-url:", "token:"):
        assert inp in YML
    # hub-url comes from an input, never a hardcoded host — the executable builds the URL
    # from the env var, so the destination is always the operator's own hub.
    assert "OW_HUB_URL: ${{ inputs.hub-url }}" in YML
    assert "${OW_HUB_URL%/}/api/accounts/" in ENTRY


def test_hub_accepts_the_trivy_cyclonedx_the_action_posts():
    # a Trivy CycloneDX SBOM (no vulnerabilities[]) → the hub's INVENTORY lane (snapshot +
    # own-CVE derivation), which is exactly what the Action emits with --format cyclonedx.
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
           "metadata": {"component": {"purl": "pkg:oci/app"}, "tools": {"components": [{"name": "trivy"}]}},
           "components": [{"bom-ref": "c1", "name": "log4j-core", "version": "2.14.1",
                           "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                           "licenses": [{"license": {"id": "Apache-2.0"}}]}]}
    parsed = aws_ingest.parse_document(doc)
    assert parsed.lane == "inventory" and len(parsed.components) == 1
    assert parsed.components[0].license_raw == "Apache-2.0"
