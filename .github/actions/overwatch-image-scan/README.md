# OverWatch Image Scan — GitHub Action

Scan an already-built container image with **Trivy** and post its **CycloneDX SBOM**
(components + CVEs) to your self-hosted **OverWatch** hub. The hub owns the SBOM as a
durable, diffable snapshot, re-derives its own attack-path-reachable CVEs, and evaluates
your license policy — so a build that adds a vulnerable or wrongly-licensed dependency
shows up as SBOM drift the next time you look.

## Security posture

- **Read-only** — scans an image that already exists; never builds, pushes, or mutates
  anything, and makes **no cloud/AWS API calls** (owner-binding happens hub-side from the
  account's stored graph).
- **Zero-telemetry** — the Action is **shell only** (no Python), posts **once** to *your*
  hub over HTTPS with **no redirects** (mirroring the hub's SSRF guard), and fails closed if
  the token is empty. Trivy's own vulnerability-DB fetch is the tool's egress (documented,
  and suppressible with `offline: true`).
- **Least privilege** — the `token` is an **ingest-scoped** bearer credential (the hub's
  below-admin `ingest` RBAC tier). It can post SBOMs but **cannot** onboard or delete
  accounts, or run scans — so a leaked CI token can't compromise the account. Prefer a
  short-lived token minted from GitHub OIDC over a long-lived secret.

## Inputs

| Input | Required | Description |
|---|---|---|
| `image` | yes | Image ref to scan (e.g. `ghcr.io/acme/app:${{ github.sha }}`). |
| `account-id` | yes | The 12-digit AWS account id the image belongs to. |
| `hub-url` | yes | Base URL of your OverWatch hub. Pass from **`vars`**, never hardcode. |
| `token` | yes | Ingest-scoped bearer token. Pass from **`secrets`**. |
| `target-resource` | no | ECR image ref / ARN to bind the SBOM to a graph node. |
| `workspace-id` | no | Sent as `X-Workspace-Id` (multi-tenant / MSSP hubs). |
| `trivy-version` | no | Trivy version to install if not on PATH (default `0.58.1`). |
| `offline` | no | Air-gapped mode: skip Trivy's DB refresh (`true`/`false`). |

## Usage

```yaml
jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build image
        run: docker build -t ghcr.io/acme/app:${{ github.sha }} .
      - name: OverWatch image scan
        uses: ./.github/actions/overwatch-image-scan
        with:
          image: ghcr.io/acme/app:${{ github.sha }}
          account-id: "123456789012"
          hub-url: ${{ vars.OVERWATCH_HUB_URL }}
          token: ${{ secrets.OVERWATCH_INGEST_TOKEN }}
          target-resource: 123456789012.dkr.ecr.us-east-1.amazonaws.com/app:${{ github.sha }}
```

The Action POSTs to `POST {hub-url}/api/accounts/{account-id}/ingest` with body
`{ "doc": <trivy cyclonedx>, "source_tool": "trivy", "target_resource": <optional> }`.

**Alternative scanners.** Trivy is the default (one CycloneDX POST owns both the SBOM and
the CVEs). Syft (SBOM only) and Grype (CVEs only) also work — produce CycloneDX/SPDX/SARIF
and POST the same envelope; the hub sniffs the format automatically.
