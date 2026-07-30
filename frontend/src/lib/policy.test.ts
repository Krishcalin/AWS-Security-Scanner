import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { evaluate, parse, policyFinding, policiesForAccount, PolicyError, type PolicyDef } from './policy'
import type { GraphFull, FindingCatalogEntry } from '../api/types'

// policy.ts must build the SAME POLICY-xx finding as aws_policy.py, else a policy-as-code rule
// reads differently offline vs online. Replayed from the shared parity fixture: for each policy,
// evaluate over the canonical graph + catalog with the (parity-proven) wql.ts engine, then assert
// policyFinding matches the Python oracle's `expected` (null → the policy did not fire).
interface PolCase { policy: PolicyDef; account: string; expected: Record<string, unknown> | null }
interface Parity { graph: GraphFull; policy_catalog: FindingCatalogEntry[]; policies: PolCase[] }
const FX: Parity = JSON.parse(
  readFileSync(join(process.cwd(), 'src', 'lib', '__fixtures__', 'wql_parity.json'), 'utf-8'))

describe('policy.ts == aws_policy.py on the shared parity fixture', () => {
  it('has policy cases incl. a non-firing (null) case', () => {
    expect(FX.policies.length).toBeGreaterThanOrEqual(5)
    expect(FX.policies.some((c) => c.expected === null)).toBe(true)
  })

  for (const c of FX.policies) {
    it(`policy: ${c.policy.id}`, () => {
      const matched = evaluate(parse(c.policy), FX.graph, FX.policy_catalog)
      if (c.expected === null) expect(matched).toBeNull()
      else expect(policyFinding(c.policy, c.account, matched!)).toEqual(c.expected)
    })
  }
})

describe('parse() rejects malformed policies (the config boundary)', () => {
  const bad: unknown[] = [
    { id: 'x' },
    { id: 'x', match: {} },
    { match: { finding: { status: 'FAIL' } } },
    { id: 'x', match: { op: 'xor', finding: { status: 'FAIL' } } },
    { id: 'x', match: { finding: { bogus: 1 } } },
    { id: 'x', match: { finding: {} } },
    { id: 'x', match: { finding: { severity: 'SPICY' } } },
    { id: 'x', match: { finding: { compliance_control: '3.4' } } },
    { id: 'x', match: { graph: { select: 'edge' } } },
    // JS prototype-key severities must be rejected (own-property guard mirrors the Python dict)
    { id: 'x', match: { finding: { severity: 'constructor' } } },
    { id: 'x', match: { finding: { severity: 'toString' } } },
    { id: 'x', match: { finding: { severity: '__proto__' } } },
  ]
  for (const p of bad) {
    it(`rejects ${JSON.stringify(p)}`, () => {
      expect(() => parse(p)).toThrow(PolicyError)
    })
  }
})

describe('policiesForAccount folds firing policies and skips the bad ones', () => {
  it('overlays fired policies, inert on a malformed rule', () => {
    const defs: PolicyDef[] = FX.policies.map((c) => c.policy)
    const bad = { id: 'broken', match: { finding: { bogus: 1 } } } as unknown as PolicyDef
    const out = policiesForAccount([...defs, bad], 'acct-1', FX.graph, FX.policy_catalog)
    const ids = out.map((f) => f.check_id)
    expect(ids).toContain('POLICY-pci-34-fail')
    expect(ids).not.toContain('POLICY-broken')            // malformed -> inert
    expect(ids).not.toContain('POLICY-never-fires')       // did not fire
    expect(out.every((f) => f.status === 'WARN')).toBe(true)
  })
})
