// OverWatch IaC — reference VS Code stub. Runs the offline IaC scanner on the open Terraform /
// CloudFormation file and publishes findings as inline diagnostics. Pure local analysis: the only
// I/O is spawning the scanner (no network, no hub, no token) — the same shell-only discipline as
// the GitHub Actions. NOT a published extension; see ../README.md.
import * as vscode from 'vscode'
import { execFile } from 'node:child_process'
import { promises as fs } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

interface ScanFinding {
  id: string; name: string; severity: string; file: string; line: number | null
  code?: string; description?: string; recommendation?: string; cwe?: string | null; cve?: string | null
}
interface ScanReport { findings: ScanFinding[] }

const SUPPORTED = new Set(['terraform', 'yaml', 'json'])

function sevOf(s: string): vscode.DiagnosticSeverity {
  switch ((s || '').toUpperCase()) {
    case 'CRITICAL': case 'HIGH': return vscode.DiagnosticSeverity.Error
    case 'MEDIUM': return vscode.DiagnosticSeverity.Warning
    default: return vscode.DiagnosticSeverity.Information
  }
}

// run: <python> <scannerPath> <file> --json <tmp> ; then read the JSON report. The scanner's exit
// code is the SEVERITY GATE (1 = HIGH+ found), NOT a tool failure — so we key off the JSON, never
// the exit status (a non-zero exit with a written report is the normal "findings present" case).
function runScanner(file: string): Promise<ScanReport> {
  const cfg = vscode.workspace.getConfiguration('overwatch')
  const python = cfg.get<string>('python', 'python3')
  const scanner = cfg.get<string>('scannerPath', 'aws_offline_scanner.py')
  const out = join(tmpdir(), `overwatch-iac-${Date.now()}.json`)
  return new Promise((resolve, reject) => {
    execFile(python, [scanner, file, '--json', out], { timeout: 60_000 }, async (err) => {
      try {
        const report = JSON.parse(await fs.readFile(out, 'utf-8')) as ScanReport
        await fs.rm(out, { force: true })
        resolve(report)
      } catch {
        reject(err ?? new Error('scanner produced no report'))
      }
    })
  })
}

async function scan(doc: vscode.TextDocument, dc: vscode.DiagnosticCollection): Promise<void> {
  if (!SUPPORTED.has(doc.languageId) || doc.uri.scheme !== 'file') return
  let report: ScanReport
  try {
    report = await runScanner(doc.fileName)
  } catch (e) {
    vscode.window.showWarningMessage(`OverWatch IaC scan failed: ${e instanceof Error ? e.message : e}`)
    return
  }
  const diags: vscode.Diagnostic[] = []
  for (const f of report.findings || []) {
    // only diagnose findings that belong to THIS file (the scanner may walk a dir)
    if (f.file && !doc.fileName.endsWith(f.file) && f.file !== doc.fileName) continue
    const lineIdx = typeof f.line === 'number' && f.line > 0 ? f.line - 1 : 0
    const line = doc.lineAt(Math.min(lineIdx, doc.lineCount - 1))
    const d = new vscode.Diagnostic(
      line.range,
      `${f.name}${f.description ? ` — ${f.description}` : ''}${f.recommendation ? `\nFix: ${f.recommendation}` : ''}`,
      sevOf(f.severity),
    )
    d.code = f.id
    d.source = 'OverWatch IaC'
    diags.push(d)
  }
  dc.set(doc.uri, diags)
}

export function activate(ctx: vscode.ExtensionContext): void {
  const dc = vscode.languages.createDiagnosticCollection('overwatch-iac')
  ctx.subscriptions.push(dc)
  const run = (doc?: vscode.TextDocument) => { if (doc) void scan(doc, dc) }

  ctx.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => run(doc)),
    vscode.workspace.onDidOpenTextDocument((doc) => run(doc)),
    vscode.commands.registerCommand('overwatch.scanFile', () => run(vscode.window.activeTextEditor?.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => dc.delete(doc.uri)),
  )
  if (vscode.window.activeTextEditor) run(vscode.window.activeTextEditor.document)
}

export function deactivate(): void { /* diagnostics disposed via ctx.subscriptions */ }
