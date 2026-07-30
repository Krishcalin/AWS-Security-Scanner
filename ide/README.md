# OverWatch IDE plugin — spec + reference stub

A **shift-left VS Code extension** that runs OverWatch's offline IaC scanner on the file you're
editing and surfaces findings **inline as diagnostics** — the exact "no AWS credentials, only code
to review" persona, in the editor. Pure local static analysis: no hub, no token, no network.

> **Status: reference stub, not a published extension.** `vscode/` is a minimal, runnable
> implementation that locks the design + the finding→diagnostic contract below. A polished,
> marketplace-published extension (CloudFormation line anchoring, on-type scanning, its own vsce
> release train) is a separate deliverable and is **deferred** — see *Deferred* below.

## Design (Design A — shift-left, local)

The extension is a thin TypeScript client over the already-blessed offline scanner. It never
opens a socket; its only I/O is spawning the scanner. It follows the same discipline as
`.github/actions/` — a non-Python satellite that stays off OverWatch's Python network surface.

```
save a .tf file
   └─ spawn: python3 aws_offline_scanner.py <file> --json <tmp>
        └─ read the JSON report
             └─ map each finding → a vscode.Diagnostic on its file:line
```

## Finding → Diagnostic contract

The offline scanner's JSON finding (`aws_offline_scanner.py` `save_json`):

```jsonc
{ "id", "name", "severity", "file", "line", "code", "description", "recommendation", "cwe", "cve" }
```

maps to a `vscode.Diagnostic`:

| Finding field | Diagnostic |
|---|---|
| `severity` CRITICAL/HIGH | `DiagnosticSeverity.Error` |
| `severity` MEDIUM | `DiagnosticSeverity.Warning` |
| `severity` LOW/INFO | `DiagnosticSeverity.Information` |
| `line` (1-indexed) | `Range(line-1, 0 … eol)` |
| `id` | `Diagnostic.code` (e.g. `AWS-S3-TF-001`) |
| `name` + `description` | `Diagnostic.message` |
| `recommendation` | `relatedInformation` / hover |
| — | `Diagnostic.source = "OverWatch IaC"` |

**Terraform-first.** Terraform findings carry a real 1-indexed line → crisp inline diagnostics.
**CloudFormation** structural findings have `line: null` and anchor to a resource, not a source
line; the stub surfaces those at line 1 (file-level). Full CFN line anchoring is deferred.

## Running the reference stub

```bash
cd ide/vscode
npm install
npm run compile      # tsc -> out/extension.js
# then press F5 in VS Code to launch an Extension Development Host, open a .tf file, and save.
```

Set `overwatch.scannerPath` (default `aws_offline_scanner.py` on PATH / the repo root) and
`overwatch.python` (default `python3`) in settings.

## Deferred (named, not built here)

- A **published marketplace extension** (vsce packaging, icon, tests, CI release train).
- **CloudFormation line anchoring** (structural findings → source lines).
- **On-type / incremental** scanning (the stub scans on save only).
- A **hub-viewer** mode (querying `GET /accounts/{id}/findings`) — deferred as lower-value
  duplication of the web console and the only network-touching design.
