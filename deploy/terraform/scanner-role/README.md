# Terraform: `CnappScannerRole` onboarding module

The IaC alternative to the CloudFormation Launch-Stack flow
([`deploy/cnapp-scanner-role.yaml`](../../cnapp-scanner-role.yaml)). `terraform apply`
creates a role **byte-equivalent in effect** to the CFN: the read-only cross-account
`CnappScannerRole`, assumable only by the CNAPP hub role under your per-tenant
`sts:ExternalId`. A structural parity test (`tests/test_terraform_parity.py`) asserts the
two stay in lock-step.

## Usage

```hcl
module "cnapp_scanner_role" {
  source       = "github.com/Krishcalin/AWS-Security-Scanner//deploy/terraform/scanner-role"
  external_id  = var.cnapp_external_id            # from the onboarding screen (>= 16 chars)
  hub_role_arn = "arn:aws:iam::<HUB_ACCT>:role/CnappHubRole"

  # optional read-only extensions (default off); enable only what you use:
  # enable_dspm_surfaces = true
  # enable_cdr_forensics = true
  # enable_flowlog_insights = true
  # flow_log_group_arns    = ["arn:aws:logs:us-east-1:<ACCT>:log-group:/vpc/flowlogs:*"]
  # enable_eks_kspm        = true
  # eks_cluster_names      = ["prod-cluster"]
  # enable_sidescan        = true                 # WRITES (snapshot lifecycle), tag-scoped
}

output "cnapp_role_arn" { value = module.cnapp_scanner_role.role_arn }
```

## Notes

- **IAM is global** — apply in exactly **one region per account** (a second region errors
  on the duplicate global role), matching the CFN's `CAPABILITY_NAMED_IAM` caveat.
- **Never `ReadOnlyAccess`.** Only `SecurityAudit` + `ViewOnlyAccess` are attached — the
  same tighter list/describe surface as the CFN; `ReadOnlyAccess` would grant workload
  DATA reads and is deliberately excluded.
- **Org-wide onboarding.** For a whole AWS Organization, drive this module from a
  StackSet-equivalent (`for_each` over accounts with per-account provider aliases, or an
  `aws_cloudformation_stack_set` wrapping [`deploy/cnapp-stackset.md`](../../cnapp-stackset.md)).
- **Air-gap.** Pre-seed the provider mirror (see `versions.tf`) so `terraform init` needs
  no registry.
- **Partition.** ARNs hardcode the `aws` partition for parity with the CFN; GovCloud/China
  (`aws-us-gov`/`aws-cn`) support is a follow-up.
