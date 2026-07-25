#!/usr/bin/env bash
# OverWatch CI/CD image scan → hub ingest. SHELL-ONLY (no committed Python under .github/
# so the repo's zero-telemetry tripwire has nothing to inspect) + READ-ONLY + zero-telemetry:
#   * scans an ALREADY-BUILT image — never builds, pushes, or mutates anything;
#   * calls NO cloud/AWS API — owner-binding is done hub-side from the account's stored graph;
#   * posts ONCE to the operator's OWN hub over HTTPS with no redirects (mirrors the hub's
#     SSRF guard); fails closed if the token is empty; never echoes the token.
# Trivy's own vuln-DB fetch is the TOOL's egress (documented + `offline`-suppressible), not
# OverWatch's telemetry.
set -euo pipefail

: "${OW_IMAGE:?image input required}"
: "${OW_ACCOUNT:?account-id input required}"
: "${OW_HUB_URL:?hub-url input required}"
: "${OW_TOKEN:?token input required — fail closed}"

if ! printf '%s' "$OW_ACCOUNT" | grep -Eq '^[0-9]{12}$'; then
  echo "::error::account-id must be exactly 12 digits"; exit 1
fi
case "$OW_HUB_URL" in
  https://*) : ;;
  *) echo "::error::hub-url must be https://"; exit 1 ;;
esac

# Install Trivy (single static binary) if it isn't already available.
if ! command -v trivy >/dev/null 2>&1; then
  echo "Installing Trivy v${OW_TRIVY_VERSION}…"
  curl -sSfL --proto '=https' --max-redirs 3 \
    https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin "v${OW_TRIVY_VERSION}"
fi

# Scan the already-built image → one CycloneDX doc (components + Trivy's CVEs). Posted to
# the inventory lane, the hub owns the SBOM snapshot AND re-derives its own reachable CVEs.
SBOM="$(mktemp)"; BODY="$(mktemp)"; RESP="$(mktemp)"
trap 'rm -f "$SBOM" "$BODY" "$RESP"' EXIT
TRIVY_ARGS=(image --quiet --format cyclonedx --scanners vuln,license --output "$SBOM")
if [ "${OW_OFFLINE}" = "true" ]; then
  TRIVY_ARGS+=(--skip-db-update --skip-java-db-update --offline-scan)
fi
trivy "${TRIVY_ARGS[@]}" "$OW_IMAGE"

# Assemble the ingest envelope { doc, source_tool, target_resource }.
if command -v jq >/dev/null 2>&1; then
  jq -n --slurpfile doc "$SBOM" --arg tr "$OW_TARGET" \
    '{doc: $doc[0], source_tool: "trivy", target_resource: (if $tr == "" then null else $tr end)}' > "$BODY"
else
  { printf '{"doc":'; cat "$SBOM"; printf ',"source_tool":"trivy","target_resource":'; \
    if [ -z "$OW_TARGET" ]; then printf 'null'; else printf '"%s"' "$OW_TARGET"; fi; \
    printf '}'; } > "$BODY"
fi

# POST once — https only, NO redirects (a redirect could exfiltrate the bearer token).
HDRS=(-H "Authorization: Bearer ${OW_TOKEN}" -H "Content-Type: application/json")
if [ -n "${OW_WORKSPACE}" ]; then HDRS+=(-H "X-Workspace-Id: ${OW_WORKSPACE}"); fi
HTTP_CODE="$(curl -sS --proto '=https' --max-redirs 0 -o "$RESP" -w '%{http_code}' \
  "${HDRS[@]}" -X POST "${OW_HUB_URL%/}/api/accounts/${OW_ACCOUNT}/ingest" --data @"$BODY")"

cat "$RESP"; echo
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
  echo "OverWatch ingest OK (HTTP ${HTTP_CODE})"
else
  echo "::error::OverWatch ingest failed (HTTP ${HTTP_CODE})"; exit 1
fi
