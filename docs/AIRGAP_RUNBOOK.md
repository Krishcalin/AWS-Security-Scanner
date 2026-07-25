# Air-gapped deployment runbook

OverWatch runs fully **air-gapped** — no public-internet egress, no telemetry, no
build-time or run-time package fetch. This runbook takes you from a connected build host
to a sealed hub scanning your accounts over AWS VPC endpoints.

See [`NETWORK.md`](../NETWORK.md) for the complete egress inventory (the zero-telemetry
guarantee is enforced by `tests/test_zero_telemetry.py`).

## What crosses the air-gap

Exactly one file, produced on a **connected** build host:

```bash
scripts/build_offline_bundle.sh            # -> overwatch-airgap-<version>.tar.gz
```

It contains: the Docker image (`docker save`), the pinned wheelhouse, the prebuilt SPA
(`frontend/dist`), the deploy artifacts (`deploy/`, Terraform + CFN), and this runbook.
Nothing in the bundle needs the internet on the sealed side.

## On the air-gapped hub

1. **Load the image**

   ```bash
   tar xzf overwatch-airgap-<version>.tar.gz
   docker load -i overwatch-airgap-<version>-image.tar
   ```

2. **Provision AWS VPC endpoints** (Interface, in the hub's private subnet) so the hub
   reaches AWS with no internet: `sts`, `ec2`, `iam` (global — via the `iam` interface
   endpoint or an egress-controlled NAT to the IAM global endpoint), `s3` (Gateway),
   `logs`, `secretsmanager`, `ssm`, `cloudtrail`, `guardduty`, `securityhub`,
   `access-analyzer`, `eks`, `config`, and `kms`. Add `marketplacemetering` **only** if
   you use the metered Marketplace SKU (the air-gap SKU is contract-based — no metering
   egress; see `deploy/marketplace/`).

3. **Mount the vuln bundle** (optional; enrichment is honest-empty without it) read-only:

   ```
   -v /secure/vuln/osv-epss-kev.json:/data/vuln/osv-epss-kev.json:ro
   -e CNAPP_VULN_DB=/data/vuln/osv-epss-kev.json
   ```

4. **Run the hub** (sqlite single-node shown; point `CNAPP_DB_URL` at an in-VPC Postgres
   for HA). **Wire real auth + a secret store before exposing it** — the image ships
   fail-closed (every route 403) and refuses onboarding until `current_principal` and a
   Secrets-Manager/SSM resolver are injected (see `cnapp_server.py`).

   ```bash
   docker run -d --name overwatch-hub \
     -p 8080:8080 \
     -v overwatch-data:/data \
     -e CNAPP_DB_URL=sqlite:////data/overwatch.db \
     -e CNAPP_HUB_ROLE_ARN=arn:aws:iam::<HUB_ACCT>:role/CnappHubRole \
     -e CNAPP_CFN_TEMPLATE_URL=https://<your-internal-s3-vpce>/cnapp-scanner-role.yaml \
     -e OVERWATCH_AIRGAP=1 \
     overwatch-hub:<version>
   ```

5. **Onboard spokes** with Terraform (`deploy/terraform/scanner-role/`) or the CFN role
   (`deploy/cnapp-scanner-role.yaml`) — both produce the identical read-only
   `CnappScannerRole` (SecurityAudit + ViewOnlyAccess under your ExternalId). In air-gap,
   pre-seed the Terraform provider mirror (`terraform providers mirror ./tf-mirror`) so
   `terraform init` needs no registry.

## Verify (no `curl` needed)

```bash
# SQLite >= 3.24 (ON CONFLICT floor the backend pre-flights)
docker run --rm overwatch-hub:<version> python -c "import sqlite3; print(sqlite3.sqlite_version); assert sqlite3.sqlite_version_info >= (3,24,0)"
# app imports + wires with no network
docker run --rm -e CNAPP_DB_URL=:memory: overwatch-hub:<version> python -c "import cnapp_server; cnapp_server.build_service(); print('ok')"
# zero-telemetry tripwire (if you shipped the tests)
docker run --rm overwatch-hub:<version> python -m pytest tests/test_zero_telemetry.py -q  || true
```

## The sealed posture (enforced by defaults, not a code branch)

- AWS reached **only** via VPC endpoints.
- Every optional egress seam (connectors, copilot LLM, K8s, image/Lambda fetch) is left at
  its safe default (`enabled=0` / `None`) → nothing reaches out.
- The vuln bundle is a local file — never fetched.
- Dependencies come from the wheelhouse (`--no-index`); the SPA from the prebuilt dist.

`OVERWATCH_AIRGAP=1` is a documentation/assertion flag — there is deliberately no
`if AIRGAPPED` branch in the scan logic; air-gap is a deployment mode of the same code.
