# Org-wide onboarding — CloudFormation StackSet (auto-enroll)

Onboard an entire AWS Organization once. A **service-managed StackSet** deploys
`CnappScannerRole` (from [`cnapp-scanner-role.yaml`](./cnapp-scanner-role.yaml)) to
every current member account, and **AutoDeployment** enrolls every *future*
account that joins a targeted OU — no per-account clicks.

This is the org equivalent of the single-account Launch-Stack flow, and matches
how Wiz/Orca "connect organization" works.

## Prerequisites (management account, once)

Service-managed StackSets require Organizations trusted access, and running the
StackSet from the CNAPP hub (rather than the management account) requires
registering the hub as a **delegated administrator**:

```bash
# 1. Enable trusted access for StackSets across the org
aws organizations enable-aws-service-access \
  --service-principal stacksets.cloudformation.amazonaws.com

# 2. Delegate StackSet administration to the CNAPP hub account
aws organizations register-delegated-administrator \
  --service-principal member.org.stacksets.cloudformation.amazonaws.com \
  --account-id HUB_ACCOUNT_ID
```

## Create the StackSet (from the hub / delegated admin)

```bash
aws cloudformation create-stack-set \
  --stack-set-name CnappScannerRole \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --call-as DELEGATED_ADMIN \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=HubRoleArn,ParameterValue=arn:aws:iam::HUB_ACCOUNT_ID:role/CnappHubRole \
               ParameterKey=ExternalId,ParameterValue=EXTERNAL_ID \
  --template-body file://cnapp-scanner-role.yaml
```

Then create stack instances against the OU(s) — or the org **root** if every
new-anywhere account must onboard:

```bash
aws cloudformation create-stack-instances \
  --stack-set-name CnappScannerRole \
  --call-as DELEGATED_ADMIN \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --regions us-east-1              # IAM is global -> exactly ONE region
```

## Notes / gotchas

- **One region only.** `CnappScannerRole` is a global IAM resource; targeting a
  second region errors on the duplicate role.
- **AutoDeployment scope.** New accounts auto-enroll **only** when they enter a
  *targeted* OU. Target the org root to catch new-anywhere accounts.
- **`RetainStacksOnAccountRemoval=false`.** When an account leaves the org, its
  scanner role is removed with it (no orphaned trust to the hub).
- **The hub then discovers accounts** via `organizations:ListAccounts`
  (`aws_live_scanner.list_org_accounts`) and scans each by assuming
  `CnappScannerRole` with that account's ExternalId — one scan job per account, so
  each stays well under the 1-hour STS session TTL.
- **One ExternalId for the org, or one per account?** For an org StackSet a single
  ExternalId is applied to every account (it is a StackSet parameter). Per-account
  ExternalIds require per-account stack instances with parameter overrides; prefer
  that only if your threat model needs to revoke one account without re-issuing
  the whole org. The hub secret store keys the value per account either way.
