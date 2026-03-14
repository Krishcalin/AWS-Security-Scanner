# CLAUDE.md -- AWS Security Scanner

## Project Overview

Three complementary AWS security scanners:
- **IaC Scanner** (`aws_scanner.py`) -- static analysis of CloudFormation + Terraform files
- **Base Audit Script** (`aws_security_audit_scripts.sh`) -- live AWS account audit (8 sections, 20 checks)
- **Enhanced Audit Script** (`aws_security_audit_enhanced.sh`) -- live AWS account audit (16 sections, 57 checks)

## Repository Structure

```
AWS-Security-Scanner/
├── aws_scanner.py                   # IaC scanner (Python, static analysis)
├── aws_security_audit_scripts.sh    # Base audit script (Bash + boto3)
├── aws_security_audit_enhanced.sh   # Enhanced audit script (Bash + boto3)
├── docs/banner.svg
├── LICENSE                          # GPL-3.0
└── README.md
```

## IaC Scanner (`aws_scanner.py` v1.1.0)

- **Type**: Static analysis of AWS IaC files (no AWS credentials needed)
- **Lines**: ~2,463
- **Dependencies**: Optional `pyyaml` for CloudFormation YAML
- **Python**: 3.10+

### Two Scanning Engines

| Engine | Input | Approach |
|--------|-------|----------|
| Terraform | `.tf` files | Regex SAST rules (`TF_SAST_RULES`) |
| CloudFormation | `.yaml`/`.yml`/`.json` | Structural analysis (`CF_DISPATCH` -> check methods) |

### Terraform Rules: 60+ across 25 services
Rule ID format: `AWS-{SERVICE}-TF-{NNN}` (e.g. AWS-S3-TF-001, AWS-IAM-TF-003)

### CloudFormation Checks: 42 resource types
Rule ID format: `AWS-{SERVICE}-{NNN}` (e.g. AWS-IAM-001, AWS-S3-001)
- 28 base resource types (v1.0.0)
- 14 gap-service types added in v1.1.0

### Architecture
- Custom YAML loader (`_CF_LOADER`) for CF intrinsic tags (`!Ref`, `!Sub`, `!GetAtt`)
- `Finding` class: rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve
- `AWSIaCScanner` class: `scan_path`, `_scan_directory`, `_dispatch_file`, `_scan_terraform`, `_scan_cloudformation`
- `_sast_scan()`: Applies regex rules line-by-line (skips comments)
- CF dispatch: `CF_DISPATCH` dict maps resource types -> `_cf_*` check methods
- Console + JSON + HTML reports (dark GitHub theme, severity/search filtering)
- Exit code: `1` if CRITICAL or HIGH, `0` otherwise

### CLI
```bash
python aws_scanner.py <target> [--severity SEV] [--json FILE] [--html FILE] [-v] [--version]
```

## Audit Scripts

- **Type**: Live AWS account audit via AWS CLI + boto3
- **Dependencies**: AWS CLI v2, Python 3.8+, boto3, SecurityAudit IAM policy
- **Architecture**: Bash with inline Python heredocs for complex checks
- **Output**: ANSI-coloured PASS/FAIL/WARN + evidence CSV/JSON files in timestamped directory
- **Sections 1-8**: Shared between base and enhanced scripts
- **Sections 9-16**: Enhanced script only

### Check ID Prefixes
IAM-XX, S3-XX, VPC-XX, LOG-XX, ENC-XX, EC2-XX, CNT-XX, BCK-XX, RDS-XX, GLC-XX, SNS-XX, SQS-XX, CFN-XX, R53-XX, BDR-XX, AGT-XX

### CLI
```bash
bash aws_security_audit_scripts.sh          # Base (20 checks)
bash aws_security_audit_enhanced.sh         # Enhanced (57 checks)
AWS_DEFAULT_REGION=us-east-1 bash aws_security_audit_enhanced.sh
```

## Conventions

- Audit scripts are read-only -- only `describe`/`get`/`list` API calls
- IaC scanner is pure static analysis -- no AWS connectivity
- Python blocks in shell scripts print ANSI output directly but do NOT increment shell PASS/FAIL counters
- Sections 1-8 are duplicated across both shell scripts -- changes must be applied to both
- The primary branch is `master`
