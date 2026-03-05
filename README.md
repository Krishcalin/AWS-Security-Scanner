# AWS-Security-Scanner

Automated security audit scripts for AWS cloud environments, aligned to the **CIS AWS Foundations Benchmark v3.0**. Produces color-coded terminal output with PASS/FAIL/WARN verdicts and saves evidence files to a timestamped output directory.

**License:** GPL-3.0
**Author:** Krishnendu De

---

## Repository Structure

```
AWS-Security-Scanner/
├── aws_security_audit_scripts.sh   # Base audit script (8 sections, 20 checks, ~420 lines)
├── aws_security_audit_enhanced.sh  # Enhanced audit script (16 sections, 57 checks, ~1,434 lines)
├── README.md
└── LICENSE                         # GPL-3.0
```

---

## Scripts at a Glance

| Script | Sections | Checks | Lines | Scope |
|--------|----------|--------|-------|-------|
| `aws_security_audit_scripts.sh` | 8 | 20 | ~420 | IAM, S3, VPC, Logging, KMS, EC2, ECR, Backup |
| `aws_security_audit_enhanced.sh` | 16 | 57 | ~1,434 | Everything above + RDS, Glacier, SNS, SQS, CloudFront, Route 53, Bedrock, Bedrock Agents |

Sections 1–8 are identical across both scripts. Use the enhanced script for comprehensive audits.

---

## Prerequisites

- **AWS CLI v2** — configured with valid credentials (`aws configure` or IAM role/instance profile)
- **Python 3.8+** with `boto3` installed (`pip install boto3`)
- **IAM permissions** — the executing identity needs the `SecurityAudit` AWS-managed policy (read-only)
- **Default region** — `eu-west-1`; override via `AWS_DEFAULT_REGION` environment variable

---

## Usage

```bash
# Run the base audit (Sections 1–8)
bash aws_security_audit_scripts.sh

# Run the enhanced audit (Sections 1–16)
bash aws_security_audit_enhanced.sh

# Target a specific region
AWS_DEFAULT_REGION=us-east-1 bash aws_security_audit_enhanced.sh
```

Output is written to `aws_audit_<ACCOUNT_ID>_<YYYYMMDD_HHMMSS>/` in the current working directory. The directory contains evidence CSV/JSON files for each check and a final `AUDIT_MANIFEST.txt`.

---

## Security Checks Coverage

### Sections 1–8 (both scripts)

| Section | Check IDs | Description |
|---------|-----------|-------------|
| **1: IAM** | IAM-01/02, IAM-04, IAM-05, IAM-06, IAM-10 | Root MFA + access keys, console users without MFA, password policy, stale access keys (>90 days), IAM Access Analyzer |
| **2: S3** | S3-01, S3-03, S3-05 | Account-level Block Public Access, per-bucket public access + ACLs + encryption |
| **3: VPC / Network** | VPC-01, VPC-03 | Security groups with risky ports open to `0.0.0.0/0`, VPC Flow Logs enabled |
| **4: Logging & Monitoring** | LOG-01, LOG-03, LOG-04, LOG-05 | CloudTrail multi-region + validation, AWS Config recorder, GuardDuty, Security Hub standards |
| **5: Encryption & KMS** | ENC-03 | KMS customer-managed key automatic rotation status |
| **6: Compute / EC2** | EC2-04, EC2-05, EC2-06 | IMDSv2 enforcement, public IP check on instances, EBS volume encryption |
| **7: Containers** | CNT-01 | ECR scan-on-push enabled per repository |
| **8: Backup & DR** | BCK-01 | AWS Backup vaults existence and resource assignments |

### Sections 9–16 (enhanced script only)

| Section | Check IDs | Description |
|---------|-----------|-------------|
| **9: RDS** | RDS-01 to RDS-06 | Encryption at rest, publicly accessible instances, automated backups + retention ≥7 days, deletion protection + minor version auto-upgrade, enhanced monitoring + audit logging, public snapshot visibility |
| **10: S3 Glacier** | GLC-01 to GLC-03 | Vault access policies + public access, vault lock (WORM) status, SNS notifications configured |
| **11: SNS** | SNS-01 to SNS-04 | SSE-KMS encryption, wildcard Principal in access policy, HTTPS delivery enforcement (no HTTP), cross-account subscriptions |
| **12: SQS** | SQS-01 to SQS-04 | SSE-KMS / SSE-SQS encryption, unauthenticated public access in queue policy, Dead Letter Queue configured, message retention + visibility timeout |
| **13: CloudFront** | CFN-01 to CFN-05 | HTTPS-only viewer protocol, minimum TLS version, WAF Web ACL association, access logging, HTTPS origin protocol policy |
| **14: Route 53** | R53-01 to R53-05 | Hosted zone query logging, DNSSEC signing on public zones, domain transfer lock + auto-renewal, health checks on critical records, Route 53 Resolver DNS firewall + logging |
| **15: Bedrock** | BDR-01 to BDR-05 | Model invocation logging, Guardrails configured, custom model KMS encryption, VPC endpoint (PrivateLink) for data plane, IAM permissions least privilege |
| **16: Bedrock Agents** | AGT-01 to AGT-05 | Agent resource KMS encryption, execution role least privilege, Knowledge Base encryption + data source security, Action Group Lambda function security, prompt injection + session isolation controls |

---

## Script Architecture

Both scripts use the same internal structure:

1. **Shell setup** — `set -euo pipefail`, region/account resolution, timestamped output directory creation
2. **Helper functions** — `log()`, `pass()`, `fail()`, `warn()` with ANSI color output and automatic counters
3. **Sectioned checks** — labeled blocks (`SECTION N: SERVICE NAME`) with a consistent header format
4. **Hybrid Bash + Python** — simple checks use the AWS CLI directly; complex multi-resource checks use inline Python heredocs (`python3 - <<'PYEOF'`) with `boto3`
5. **Summary** — final PASS/FAIL/WARN tallies and evidence directory manifest

### Output Colors

| Color | Meaning |
|-------|---------|
| `[PASS]` (green) | Check passed — no issue found |
| `[FAIL]` (red) | Check failed — misconfiguration or missing control |
| `[WARN]` (yellow) | Check raised a warning — review recommended |
| `[INFO]` (blue) | Informational output — no verdict |

### Check ID Convention

| Prefix | Service Domain |
|--------|---------------|
| `IAM-XX` | Identity & Access Management |
| `S3-XX` | S3 Object Storage |
| `VPC-XX` | Network / VPC |
| `LOG-XX` | Logging & Monitoring |
| `ENC-XX` | Encryption & KMS |
| `EC2-XX` | Compute (EC2) |
| `CNT-XX` | Containers (ECR) |
| `BCK-XX` | Backup & DR |
| `RDS-XX` | RDS Databases |
| `GLC-XX` | S3 Glacier |
| `SNS-XX` | SNS Topics |
| `SQS-XX` | SQS Queues |
| `CFN-XX` | CloudFront Distributions |
| `R53-XX` | Route 53 DNS |
| `BDR-XX` | AWS Bedrock |
| `AGT-XX` | Bedrock Agents |

---

## Adding New Checks

1. Add a new numbered section block at the end of the script (before the summary block):

```bash
# ─────────────────────────────────────────────────────────────────────────────
# SECTION N: SERVICE NAME
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SERVICE NAME CHECKS ══${NC}"

log "SVC-01: Description of check"
python3 - <<'PYEOF'
import boto3, os

client = boto3.client('service-name')
output_dir = os.environ.get('OUTPUT_DIR', '.')

# ... check logic ...
# Output format:
#   print(f"\033[0;32m[PASS]\033[0m Description")   — passing
#   print(f"\033[0;31m[FAIL]\033[0m Description")   — failing
#   print(f"\033[1;33m[WARN]\033[0m Description")   — warning
#   print(f"\033[0;34m[INFO]\033[0m Description")   — info
PYEOF
```

2. Define a new check ID prefix (e.g., `DDB-XX` for DynamoDB) and add it to the table above.
3. Update the evidence manifest block in `AUDIT_MANIFEST.txt` generation at the bottom of the enhanced script.
4. If the check applies to base scope (Sections 1–8), apply it to both scripts; otherwise add only to the enhanced script.

### Important Conventions

- **Read-only by design** — all API calls must be `describe` / `get` / `list` operations. Never modify AWS resources.
- **No credentials in code** — scripts rely on the ambient AWS CLI profile or IAM role. Never hardcode keys or secrets.
- **Python blocks print ANSI output directly** but do NOT increment the shell `PASS`/`FAIL`/`WARN` counters (known limitation — counters reflect only checks run natively in Bash).
- **Sections 1–8 are duplicated** across both scripts. Changes to shared sections must be applied to both files.
- **Evidence files** (CSV, JSON) are written to `OUTPUT_DIR`. The manifest at the end of each run catalogs them.
- **Broad exception handling is intentional** — a single check failure must never crash the entire audit run.

---

## Testing

No automated test suite is included. To validate changes:

```bash
# Syntax check without executing
bash -n aws_security_audit_enhanced.sh

# Full run against a test AWS account
AWS_DEFAULT_REGION=us-east-1 bash aws_security_audit_enhanced.sh

# Verify output directory is created and populated
ls aws_audit_*/
```

Run against an account with `SecurityAudit` permissions and confirm PASS/FAIL/WARN verdicts match known resource states.

---

## Git Workflow

- The `master` branch is the primary branch
- Commit messages describe the change directly (no conventional commits prefix required)
- No CI/CD pipelines, pre-commit hooks, or automated releases
