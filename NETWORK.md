# NETWORK.md — OverWatch egress inventory (zero-telemetry)

**OverWatch makes ZERO telemetry, analytics, phone-home, crash-reporting, or
update-check calls.** There is no Sentry / PostHog / Mixpanel / Segment / Datadog /
usage beacon anywhere in the codebase — enforced by `tests/test_zero_telemetry.py`
(the tripwire fails CI the moment such a call is added).

Every outbound connection made by OverWatch falls into exactly one of two classes:

1. **AWS APIs (boto3)** — the read-only-of-config scan itself, to the AWS accounts you
   onboard and the hub's own AWS. In an air-gapped deployment these are reached
   **exclusively via VPC endpoints** (no public internet).
2. **Operator-configured, opt-in, injected seams** — each is a callable you supply (or
   enable), pointed at **your own** resources, and **off/`None` by default**.

## Egress table

| Class | What | Where (file:line) | Destination | Default | Air-gapped hub |
|-------|------|-------------------|-------------|---------|----------------|
| AWS | The scan (describe/list/get + read-only CloudTrail `LookupEvents` + CloudWatch Logs Insights) | `aws_live_scanner.py` (lazy `import boto3`), `trail_reader`/`flow_read` seams | AWS service endpoints | on (the product) | **via VPC endpoints only** |
| Seam | Outbound connector notifications (Jira / Slack / PagerDuty / Splunk / webhook) | `cnapp_connectors.default_http_post` (`cnapp_connectors.py`) | operator's ticketing/SIEM host | **connectors `enabled=0`** | unused (leave disabled) |
| Seam | Kubernetes API reads for KSPM/KIEM (Layer B) | `aws_kube.default_k8s_get` (`aws_kube.py`) | operator's EKS API endpoint | **opt-in** | unused, or in-VPC EKS |
| Seam | Container-image layer fetch (agentless image side-scan) | `aws_sidescan_image.fetch_ecr_layers` (injected `http_get`) | operator's ECR | **opt-in** | in-VPC ECR endpoint |
| Seam | Lambda artifact fetch | `aws_sidescan_lambda.fetch_lambda_artifact` (injected `http_get`) | operator's AWS | **opt-in** | in-VPC |
| Seam | Grounded copilot LLM | `PlatformService(copilot_llm=…)` (`cnapp_service.py`) | operator's LLM endpoint | **`None` → offline extractive** | unused, or in-VPC model |
| Seam | AWS Marketplace metering (optional) | `cnapp_marketplace_metering` → `marketplacemetering:MeterUsage` | AWS (metering) | **opt-in, off by default** | unused (use a contract/private-offer SKU) |
| Data | OSV / EPSS / KEV vulnerability bundle | `--vuln-db <path>` / injected `vuln_bundle` (`aws_live_scanner.py`, `cnapp_service.py`) | **local file — NEVER internet-fetched** | `None` → enrichment empty (honest) | mounted read-only from disk |

## Security guarantees (pinned by `tests/test_zero_telemetry.py`)

- **Connector egress (`default_http_post`)**: **HTTPS-only** (a non-`https` URL raises),
  cloud-metadata blocked (`_is_blocked_host` rejects `169.254.169.254`,
  `metadata.google.internal`, link-local), and **no cross-host redirects**
  (`_NoCrossHost`) — an SSRF-hardened, operator-pointed sink.
- **Kubernetes egress (`default_k8s_get`)**: TLS **pinned to the cluster's own CA**
  (`ssl.create_default_context(cadata=…)`), **read-only GET**, fails open (returns
  `None`) on any error.
- **Network primitives** (`urllib.request`, `ssl`, `socket`, `http.client`, …) may be
  imported by **only two files** — `aws_kube.py` and `cnapp_connectors.py`. Every other
  module is stdlib/boto3 only. (`urllib.parse` — URL string encoding — is not network
  I/O and is used freely.)

## Air-gapped posture

An air-gapped hub runs with **no public-internet egress**: AWS via VPC endpoints, the
vuln bundle mounted from disk, dependencies installed from a pre-downloaded wheelhouse
(`scripts/build_offline_bundle.sh`, `--no-index`), the console served from the prebuilt
SPA. All optional seams stay at their safe defaults, so nothing reaches out. See
[`docs/AIRGAP_RUNBOOK.md`](docs/AIRGAP_RUNBOOK.md).
