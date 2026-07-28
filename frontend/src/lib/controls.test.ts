import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { evaluate } from './wql'
import { controlFinding, controlSeverity, controlsForAccount, rollupControls, type ControlDef } from './controls'
import type { GraphFull } from '../api/types'

// controls.ts must build the SAME synthetic WARN finding as aws_controls.control_finding, else a
// saved Control reads differently offline vs online. Replayed from the shared parity fixture:
// for each control, evaluate its query with the (parity-proven) wql.ts engine, then assert
// controlFinding matches the Python oracle's `expected` (null → the control matched nothing).
interface CtrlCase { control: ControlDef; account: string; expected: FindingLike | null }
type FindingLike = Record<string, unknown>
interface Parity { graph: GraphFull; controls: CtrlCase[] }
const FX: Parity = JSON.parse(
  readFileSync(join(process.cwd(), 'src', 'lib', '__fixtures__', 'wql_parity.json'), 'utf-8'))

describe('controls.ts == aws_controls.py on the shared parity fixture', () => {
  it('has control cases (incl. a match-nothing → null case)', () => {
    expect(FX.controls.length).toBeGreaterThanOrEqual(4)
    expect(FX.controls.some((c) => c.expected === null)).toBe(true)
  })

  for (const c of FX.controls) {
    it(`control: ${c.control.id}`, () => {
      const rows = evaluate(c.control.query, FX.graph).nodes
      if (c.expected === null) {
        expect(rows.length).toBe(0)          // no match → the control passes → no finding
      } else {
        expect(controlFinding(c.control, c.account, rows)).toEqual(c.expected)
      }
    })
  }
})

describe('controlSeverity defaults to MEDIUM (matches aws_controls)', () => {
  it('normalizes an unknown/absent severity', () => {
    expect(controlSeverity({ id: 'x', query: {}, severity: 'BOGUS' })).toBe('MEDIUM')
    expect(controlSeverity({ id: 'x', query: {} })).toBe('MEDIUM')
    expect(controlSeverity({ id: 'x', query: {}, severity: 'HIGH' })).toBe('HIGH')
  })
})

describe('controlsForAccount + rollupControls over the fixture graph', () => {
  const defs: ControlDef[] = FX.controls.map((c) => c.control)

  it('folds a WARN entry per matching control and skips the empty one', () => {
    const found = controlsForAccount(defs, 'acct-1', FX.graph)
    const ids = found.map((f) => f.check_id)
    expect(ids).toContain('CONTROL-public-crown-data')
    expect(ids).toContain('CONTROL-roles-to-admin')
    expect(ids).not.toContain('CONTROL-matches-nothing')       // no DynamoDB → no entry
    expect(found.every((f) => f.status === 'WARN')).toBe(true)
  })

  it('a malformed saved query is inert, never throwing', () => {
    const bad: ControlDef[] = [{ id: 'broken', query: { where: { pred: 'nope' } } }]
    expect(() => controlsForAccount(bad, 'acct-1', FX.graph)).not.toThrow()
    expect(controlsForAccount(bad, 'acct-1', FX.graph)).toEqual([])
  })

  it('rolls up match counts + WARN/PASS across accounts', () => {
    const rows = rollupControls(defs, [
      { account: 'acct-1', graph: FX.graph }, { account: 'acct-2', graph: { ...FX.graph, nodes: [], edges: [] } },
    ])
    const by = Object.fromEntries(rows.map((r) => [r.id, r]))
    expect(by['roles-to-admin'].status).toBe('WARN')
    expect(by['roles-to-admin'].accounts_matched).toEqual(['acct-1'])   // acct-2 graph is empty
    expect(by['matches-nothing'].status).toBe('PASS')
    expect(by['matches-nothing'].match_count).toBe(0)
  })
})
