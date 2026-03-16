# CLAUDE.md -- AWS Security Scanner

## Project Overview

Two complementary AWS security scanners:
- **IaC Scanner** (`aws_offline_scanner.py`) -- static analysis of CloudFormation + Terraform files
- **Live Audit Scanner** (`aws_live_scanner.py`) -- live AWS account audit via boto3 (57 checks, 16 sections)

## Repository Structure

```
AWS-Security-Scanner/
├── aws_offline_scanner.py   # IaC scanner (Python, static analysis, no credentials)
├── aws_live_scanner.py      # Live audit scanner (Python, boto3, CIS Benchmark v3.0)
├── docs/banner.svg
├── LICENSE                  # GPL-3.0
└── README.md
```

## IaC Scanner (`aws_offline_scanner.py` v1.1.0)

- **Type**: Static analysis of AWS IaC files (no AWS credentials needed)
- **Lines**: ~2,469
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
- `Finding` dataclass: rule_id, name, category, severity, file_path, line_num, line_content, description, recommendation, cwe, cve
- `AWSIaCScanner` class: `scan_path`, `_scan_directory`, `_dispatch_file`, `_scan_terraform`, `_scan_cloudformation`
- `_sast_scan()`: Applies regex rules line-by-line (skips comments)
- CF dispatch: `CF_DISPATCH` dict maps resource types -> `_cf_*` check methods (via `getattr`)
- Console + JSON + HTML reports (dark GitHub theme, severity/search filtering)
- Exit code: `1` if CRITICAL or HIGH, `0` otherwise

### CLI
```bash
python aws_offline_scanner.py <target> [--severity SEV] [--json FILE] [--html FILE] [-v] [--version]
```

## Live Audit Scanner (`aws_live_scanner.py` v1.0.0)

- **Type**: Live AWS account audit via boto3
- **Lines**: ~2,220
- **Dependencies**: `boto3` (required), Python 3.10+
- **IAM permissions**: `SecurityAudit` AWS-managed policy (read-only)

### Architecture

```python
@dataclass
class Result:
    status: str    # PASS | FAIL | WARN | INFO
    check_id: str  # e.g. IAM-01
    section: str
    resource: str
    message: str

class AWSLiveScanner:
    def __init__(self, region="eu-west-1", verbose=False, sections=None): ...
    def _client(self, service, region=None): ...  # lazy boto3 client cache
    def run(self): ...                             # iterates CHECK_MAP, calls section methods
    def save_json(self, path): ...
    def save_html(self, path): ...
    def save_evidence(self, output_dir): ...
    def print_report(self): ...
```

- **`HAS_BOTO3` guard**: `try/except ImportError` at module level; `_client()` raises `ImportError` if boto3 absent
- **CHECK_MAP**: Dict mapping 16 section names -> bound check methods
- **16 sections**: IAM, S3, VPC, LOGGING, KMS, EC2, ECR, BACKUP, RDS, GLACIER, SNS, SQS, CLOUDFRONT, ROUTE53, BEDROCK, BEDROCK_AGENTS
- **57 checks** total; 8 sections (IAM through BACKUP) cover CIS Foundations core; sections 9-16 extend coverage
- **`--sections` flag**: Run a subset of sections (e.g. `--sections IAM S3 VPC`)
- Exit code: `1` if any FAIL results, `2` if boto3 not installed, `0` otherwise

### Check ID Prefixes
IAM-XX, S3-XX, VPC-XX, LOG-XX, ENC-XX, EC2-XX, CNT-XX, BCK-XX, RDS-XX, GLC-XX, SNS-XX, SQS-XX, CFN-XX, R53-XX, BDR-XX, AGT-XX

### CLI
```bash
python aws_live_scanner.py [--region REGION] [--json FILE] [--html FILE] \
    [--output-dir DIR] [--sections SECTION ...] [-v] [--version]
```

## Conventions

- Both scanners are read-only -- `aws_live_scanner.py` uses only `describe`/`get`/`list` boto3 calls
- `aws_offline_scanner.py` is pure static analysis -- no AWS connectivity
- The primary branch is `main`
