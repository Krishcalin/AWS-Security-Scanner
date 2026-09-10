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


**566 registered checks.** 508 are proven to FAIL in the suite; 58 run but have never been driven to a failure; 0 were never observed at all.


## Never observed

None - every registered check emits something somewhere.


## Runs, but never fails

These emit only WARN/INFO/PASS in the suite. Where the declared severity is above LOW, that severity has never been rendered.

| Check | Declared | Observed |
|---|---|---|
| `ACM-03` | LOW | PASS/WARN |
| `ACM-05` | LOW | WARN |
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
| `FARGATE-01` | LOW | INFO |
| `FLOW-01` | LOW | WARN |
| `FLOW-02` | LOW | WARN |
| `GLC-03` | LOW | WARN |
| `LMB-02` | LOW | WARN |
| `LMB-05` | LOW | WARN |
| `MART-03` | LOW | WARN |
| `MCP-04` | LOW | WARN |
| `R53-02` | LOW | WARN |
| `R53-04` | LOW | INFO/WARN |
| `RDS-05` | LOW | PASS/WARN |
| `RDS-13` | LOW | WARN |
| `RS-05` | LOW | PASS/WARN |
| `RS-07` | LOW | PASS/WARN |
| `RSS-02` | LOW | PASS/WARN |
| `SEC-03` | LOW | PASS |
| `SEC-04` | LOW | WARN |
| `SECRET-02` | LOW | WARN |
| `SEG-06` | LOW | WARN |
| `SEGREC-01` | INFO | INFO |
| `SFN-02` | LOW | PASS/WARN |
| `SFN-03` | LOW | PASS/WARN |
| `SHAI-03` | LOW | PASS/WARN |
| `SNS-01` | LOW | PASS/WARN |
| `SQS-03` | LOW | WARN |
| `SQS-04` | LOW | PASS |
| `VPC-06` | LOW | INFO/PASS/WARN |
| `WAF-01` | LOW | WARN |
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
- `AL2-00` (INFO)
- `AMEM-00` (INFO)
- `CIEM-00` (INFO)
- `CIEM-01` (WARN)
- `CREDEXP-00` (INFO)
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
