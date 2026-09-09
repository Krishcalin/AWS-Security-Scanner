# Check firing reference

<!-- GENERATED FILE - DO NOT EDIT BY HAND.
     Produced by scripts/check_firing.py from a real suite run:
       OVERWATCH_RECORD_CHECKS=fired.json python -m pytest tests/ -q
       python scripts/check_firing.py --from fired.json -->

Every registered check, and whether the test suite has ever made it emit a finding.
Derived by recording `AWSLiveScanner._add` across the whole suite, because the
question cannot be answered by reading the source - a check id reaches `_add` as a
literal, a variable, a subscript or a conditional, and all 90 sections use at least
one non-literal form.

`_add` reads severity, compliance and remediation from the catalogue **only for a
FAIL**. A WARN is forced to severity LOW and carries no remediation, and an INFO
carries neither - so a check that never fails never renders what the catalogue
advertises for it.


**509 registered checks.** 419 are proven to FAIL in the suite; 62 run but have never been driven to a failure; 28 were never observed at all.


## Never observed

No test makes these emit anything. Each is registered in all four metadata maps and counted in the catalogue total.

- `AMP-01` (declared MEDIUM)
- `CGP-01` (declared MEDIUM)
- `DATA-03` (declared MEDIUM)
- `DSQL-01` (declared MEDIUM)
- `FMS-01` (declared MEDIUM)
- `GRF-01` (declared MEDIUM)
- `IMI-01` (declared MEDIUM)
- `LATT-02` (declared MEDIUM)
- `MART-03` (declared LOW)
- `MBC-01` (declared MEDIUM)
- `MPV-01` (declared MEDIUM)
- `NWM-01` (declared MEDIUM)
- `SEC-04` (declared LOW)
- `SEG-06` (declared LOW)
- `SFN-01` (declared MEDIUM)
- `SFN-02` (declared LOW)
- `SFN-03` (declared LOW)
- `SGW-02` (declared MEDIUM)
- `SM-12` (declared MEDIUM)
- `SM-16` (declared MEDIUM)
- `SM-18` (declared MEDIUM)
- `SM-20` (declared MEDIUM)
- `SM-24` (declared MEDIUM)
- `SM-26` (declared MEDIUM)
- `SM-27` (declared LOW)
- `THREAT-02` (declared MEDIUM)
- `VPC-03` (declared MEDIUM)
- `WAF-01` (declared HIGH)


## Runs, but never fails

These emit only WARN/INFO/PASS in the suite. Where the declared severity is above LOW, that severity has never been rendered.

| Check | Declared | Observed |
|---|---|---|
| `ACM-03` | LOW | PASS/WARN |
| `ACM-05` | MEDIUM | WARN |
| `AGC-03` | LOW | WARN |
| `AGC-04` | LOW | WARN |
| `AGT-01` | LOW | INFO/PASS/WARN |
| `AGT-03` | LOW | INFO/WARN |
| `AGW2-03` | LOW | PASS/WARN |
| `AILOG-05` | LOW | WARN |
| `AILOG-06` | LOW | WARN |
| `APIGW-04` | LOW | PASS/WARN |
| `BDR-03` | LOW | INFO |
| `BDR-04` | LOW | WARN |
| `CNT-05` | LOW | PASS/WARN |
| `COG-04` | LOW | PASS/WARN |
| `DDB-01` | LOW | PASS/WARN |
| `DDB-03` | LOW | INFO/PASS |
| `DDB-04` | MEDIUM | PASS |
| `DIRSVC-02` | LOW | PASS |
| `EBS-05` | LOW | WARN |
| `EC2-05` | LOW | WARN |
| `EC2-09` | LOW | WARN |
| `EFS-03` | LOW | WARN |
| `EKS-04` | LOW | INFO |
| `EKS-05` | LOW | WARN |
| `EKS-07` | LOW | INFO |
| `ELB-04` | LOW | WARN |
| `ELB-08` | LOW | WARN |
| `ENC-03` | MEDIUM | PASS/WARN |
| `FARGATE-01` | LOW | INFO |
| `FLOW-01` | LOW | WARN |
| `FLOW-02` | LOW | WARN |
| `FW-02` | MEDIUM | PASS |
| `GLC-03` | LOW | WARN |
| `HSM-01` | MEDIUM | PASS |
| `LMB-02` | LOW | WARN |
| `LMB-05` | LOW | WARN |
| `MCP-04` | LOW | WARN |
| `NFW-01` | MEDIUM | PASS |
| `NFW-03` | MEDIUM | PASS |
| `OSR-03` | MEDIUM | PASS |
| `R53-02` | LOW | WARN |
| `R53-04` | LOW | INFO/WARN |
| `RDS-05` | LOW | WARN |
| `RDS-13` | LOW | WARN |
| `RS-05` | LOW | PASS/WARN |
| `RS-07` | LOW | PASS/WARN |
| `RSS-02` | LOW | PASS/WARN |
| `S3T-02` | MEDIUM | PASS |
| `SEC-03` | LOW | PASS |
| `SECRET-02` | LOW | WARN |
| `SEGREC-01` | INFO | INFO |
| `SHAI-03` | MEDIUM | PASS/WARN |
| `SM-22` | MEDIUM | PASS |
| `SM-25` | MEDIUM | PASS |
| `SNS-01` | LOW | PASS/WARN |
| `SQS-03` | LOW | WARN |
| `SQS-04` | LOW | PASS |
| `VPC-06` | LOW | INFO/PASS/WARN |
| `WINVULN-03` | LOW | INFO/WARN |
| `WINVULN-04` | LOW | PASS |
| `WKR-01` | INFO | INFO |
| `XFER-03` | INFO | INFO |


## Emitted but not registered

A finding whose id the catalogue does not know renders with the default severity and no remediation.

**Reaching FAIL: none - all are INFO/WARN/PASS markers**

- `AGC-00` (INFO)
- `AGY-00` (INFO)
- `AIDR-00` (INFO)
- `AIGRD-00` (INFO)
- `AILOG-00` (INFO)
- `AISPM-00` (INFO)
- `AITHR-00` (INFO)
- `AMEM-00` (INFO)
- `CIEM-00` (INFO)
- `CIEM-01` (WARN)
- `CWPP-04` (INFO/WARN)
- `FLOW-00` (INFO)
- `FLOW-03` (INFO)
- `GLC-00` (INFO)
- `IAM-03` (PASS)
- `IAMPE-00` (PASS)
- `KMS-01` (PASS)
- `KSPM-00` (INFO)
- `MART-00` (INFO)
- `NHI-00` (INFO)
- `NITRO-00` (INFO)
- `PATHS-01` (INFO)
- `PENT-00` (INFO)
- `PERIM-00` (INFO)
- `SECRET-00` (INFO)
- `SEG-04` (INFO)
- `SEGREC-00` (INFO)
- `SHAI-00` (INFO)
- `SM-00` (INFO)
- `VEC-00` (INFO)
- `ZZZ-99` (WARN)
