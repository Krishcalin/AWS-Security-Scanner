# OverWatch IaC Gate

A **shift-left PR gate** for infrastructure-as-code. It runs OverWatch's offline IaC SAST
(`aws_offline_scanner.py`) on your Terraform / CloudFormation, **fails the build** when findings
exceed a severity threshold (or a policy-as-code rule fires), and posts **inline SARIF
annotations** on the offending lines in the PR diff.

**Charter-clean by construction:** pure local static analysis — no cloud API, **no OverWatch
hub, no token, zero telemetry**. This is the *opposite* of [`overwatch-image-scan`](../overwatch-image-scan)
(which ingests an SBOM to the hub); the gate egresses nothing. Findings reach the PR only through
GitHub's own code-scanning upload.

## Usage

```yaml
name: iac-gate
on: [pull_request]
permissions:
  contents: read
  security-events: write        # required for the SARIF annotations
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # your IaC repo
      - uses: actions/checkout@v4          # the OverWatch scanner
        with:
          repository: Krishcalin/AWS-Security-Scanner
          path: .overwatch
      - uses: ./.overwatch/.github/actions/overwatch-iac-gate
        with:
          path: infra/
          fail-on: HIGH                    # CRITICAL | HIGH | MEDIUM | LOW  (default HIGH)
          policy: infra/policies.json      # optional policy-as-code gate
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | File or directory of Terraform / CloudFormation to scan. |
| `fail-on` | `HIGH` | Fail the build when any finding is at this severity **or above**. |
| `policy` | `""` | Optional path to a policy-as-code JSON file (a policy or a list). The build also fails when any policy **fires**. Findings-level clauses only — there is no cloud graph offline. |
| `sarif-file` | `overwatch-iac.sarif` | Where the SARIF report is written. |
| `upload-sarif` | `true` | Upload SARIF to GitHub code-scanning for inline PR annotations. |

## Exit codes (also usable as a bare CLI)

`python3 aws_offline_scanner.py <path> --fail-on HIGH --sarif out.sarif [--policy p.json]`

| Code | Meaning |
|---|---|
| `0` | Clean — no finding at/above the threshold and no policy fired. |
| `1` | Gate failure — a finding breached `--fail-on`, or a policy fired. |
| `2` | Usage / environment error (bad path, unreadable policy) — distinct from a gate failure. |

Because the IaC findings carry a **real `file:line`**, the SARIF annotations land on the exact
offending Terraform / CFN line in the PR — not a file-level note.
