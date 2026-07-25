# AWS Marketplace — OverWatch (container product)

OverWatch is listed as a **self-hosted container product**: the buyer runs the hub in
their **own** dedicated security account/VPC and OverWatch assumes a read-only role in each
onboarded spoke. The vendor never hosts customer data — which is exactly what makes it
**air-gappable and zero-telemetry** (see [`../../NETWORK.md`](../../NETWORK.md)).

Artifacts in this folder:

| File | Purpose |
|------|---------|
| `listing.yaml` | Listing metadata (title, categories, highlights, pricing dimensions) for the Marketplace Management Portal. |
| `hub-deploy.yaml` | The CloudFormation the buyer launches to run the hub (EC2 + `CnappHubInstanceProfile` + KMS-encrypted state + egress-restricted SG). |
| (repo) `deploy/cnapp-hub-role.yaml` | The hub role — deploy first. |
| (repo) `deploy/cnapp-scanner-role.yaml` / `deploy/terraform/scanner-role/` | Per-spoke onboarding (CFN or Terraform — identical role). |

## Buyer flow

1. **Subscribe** in AWS Marketplace → pull the hub container image.
2. **Deploy the hub role** (`deploy/cnapp-hub-role.yaml`) in the security account.
3. **Deploy the hub** (`hub-deploy.yaml`) into a private subnet. **Wire real auth + a
   secret store before exposing it** — the image ships fail-closed (every route 403) until
   `current_principal` (IdP/JWT) and a Secrets-Manager/SSM resolver are injected.
4. **Onboard spokes** via CFN or Terraform (both mint the same `CnappScannerRole` under
   your per-tenant ExternalId).
5. **Usage flows to billing** — see pricing below.

## Pricing (tied to the backend metering)

The billable unit is **accounts under management**, which the backend already emits
(Phase-4 Slice-1 metering: the `account.active` monthly gauge). Two dimensions map to that
same unit, so the ledger (`cnapp_metering.usage_rollup_all`) is the authoritative source
for any reconciliation:

- **Metered (`accounts_under_mgmt`, usage)** — the running hub reports hourly via
  `cnapp_marketplace_metering.meter_hourly` → `marketplacemetering:MeterUsage`. **Opt-in**;
  needs a `marketplacemetering` VPC endpoint. Default off.
- **Annual committed (`annual_committed_accounts`, contract / private offer)** — a flat
  annual commitment sized by declared account count, with **no metering egress**. This is
  the SKU for **air-gapped** buyers who cannot (or will not) reach the metering endpoint.

The metered emitter is optional code (`cnapp_marketplace_metering.py`, boto3-injected,
offline-tested) — an air-gapped install simply never wires it and uses the contract SKU.

> **Not in this slice:** live Marketplace product registration (a product code + entitlement
> checks via `aws-marketplace:` APIs). The emitter is a ready hook; wire it once the listing
> is provisioned.
