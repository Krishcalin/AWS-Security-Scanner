// controls.ts — the byte-for-byte TS mirror of aws_controls.py, so a saved-WQL Control produces
// the same synthetic WARN finding + the same org roll-up in SAMPLE mode as the live hub. Uses
// the parity-proven wql.ts engine. Guarded by the shared cross-language fixture (controls.test.ts).
import type { GraphFull, FindingCatalogEntry } from '../api/types'
import { evaluate } from './wql'

export const CONTROL_SECTION = 'Custom Controls'
export const CONTROL_PREFIX = 'CONTROL-'
const SEV = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

export interface ControlDef {
  id: string
  name?: string
  query: unknown
  severity?: string
  section?: string
  description?: string
  remediation_cmd?: string
  impact?: string
  steps?: string[]
  compliance?: Record<string, string>
}
export interface ControlRollup {
  id: string
  name: string
  severity: string
  section: string
  description: string
  query: unknown
  match_count: number
  accounts_matched: string[]
  status: 'WARN' | 'PASS'
}

// mirror aws_controls.control_severity: unknown/absent → MEDIUM.
export function controlSeverity(ctrl: ControlDef): string {
  return ctrl.severity && SEV.has(ctrl.severity) ? ctrl.severity : 'MEDIUM'
}

// mirror aws_controls.control_finding — never called with empty rows (a control that matches
// nothing simply passes and emits no finding). `rows` are wql.ts row objects ({id,kind,...}).
export function controlFinding(ctrl: ControlDef, account: string, rows: { id: string }[]): FindingCatalogEntry {
  const affected = rows.map((r) => r.id)
  const name = ctrl.name || ctrl.id
  return {
    check_id: CONTROL_PREFIX + String(ctrl.id),
    section: ctrl.section || CONTROL_SECTION,
    severity: controlSeverity(ctrl),
    status: 'WARN',
    compliance: ctrl.compliance || {},
    remediation_cmd: ctrl.remediation_cmd || '',
    risk: ctrl.description || `Custom control '${name}' matched ${rows.length} resource(s).`,
    impact: ctrl.impact || '',
    steps: ctrl.steps || [],
    affected,
    count: rows.length,
    distinct: new Set(affected).size,
    account,
  }
}

// mirror aws_controls.control_meta: the normalized descriptor (no roll-up).
export function controlMeta(ctrl: ControlDef): Omit<ControlRollup, 'match_count' | 'accounts_matched' | 'status'> {
  return {
    id: String(ctrl.id),
    name: ctrl.name || String(ctrl.id),
    severity: controlSeverity(ctrl),
    section: ctrl.section || CONTROL_SECTION,
    description: ctrl.description || '',
    query: ctrl.query,
  }
}

// mirror cnapp_service._controls_for_account: the WARN entries for controls matching this
// account's graph. A bad/unsafe saved query is inert (never throws out of here).
export function controlsForAccount(ctrl_defs: ControlDef[], account: string, graph: GraphFull): FindingCatalogEntry[] {
  const out: FindingCatalogEntry[] = []
  for (const ctrl of ctrl_defs) {
    let rows: { id: string }[]
    try {
      rows = evaluate(ctrl.query, graph).nodes
    } catch {
      continue
    }
    if (rows.length) out.push(controlFinding(ctrl, account, rows))
  }
  return out
}

// mirror cnapp_service.list_controls: org roll-up (match count + which accounts), WARN when a
// control matches anything, else PASS. `accounts` is iterated in order → accounts_matched order.
export function rollupControls(ctrl_defs: ControlDef[], accounts: { account: string; graph: GraphFull }[]): ControlRollup[] {
  return ctrl_defs.map((ctrl) => {
    let count = 0
    const matched: string[] = []
    for (const { account, graph } of accounts) {
      let rows: { id: string }[]
      try {
        rows = evaluate(ctrl.query, graph).nodes
      } catch {
        continue
      }
      if (rows.length) { count += rows.length; matched.push(account) }
    }
    return { ...controlMeta(ctrl), match_count: count, accounts_matched: matched, status: count ? 'WARN' : 'PASS' }
  })
}
