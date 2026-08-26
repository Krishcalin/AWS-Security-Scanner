/**
 * The score decomposition, and the four ways it must refuse to explain itself.
 *
 * A factor table is only worth building if it is honest about when the arithmetic did NOT
 * decide the score. There are three such cases in this model and every one of them
 * produces a plausible-looking table if handled carelessly:
 *
 *   DOMINATED   `max(privilege, impact)` drops the smaller term entirely. Drawing it as
 *               a contributing row would tell a reader to go and fix something that
 *               cannot move the number.
 *   SATURATED   the product is clamped to 1.0 before scaling, so above that no single
 *               factor moves anything.
 *   OVERRIDDEN  a floor or a cap set the score. A factor table shown without saying so
 *               presents a derivation that did not happen.
 *
 * The fourth is the framing itself: these factors are all <= 1.0 and multiply, so they
 * damp a maximum rather than adding risk. The tests below pin the "if neutral" semantics
 * so nobody later relabels the column "contribution" and inverts its meaning.
 */
import { describe, it, expect } from 'vitest'
import { factorTable } from './riskfactors'
import type { AttackPath } from '../api/types'

function path(factors: Record<string, number>, over: Partial<AttackPath> = {}): AttackPath {
  return {
    entry: 'internet', terminal: 'arn:aws:s3:::crown', terminal_kind: 'data',
    nodes: [], edges: [], severity: 'HIGH', conditioned: false, vuln_pivot: false,
    kev: false, active_threat: false, direct_public_crown: false,
    hard_floor_applied: false, driving_findings: [], rationale: '',
    factors, score: 0, ...over,
  } as AttackPath
}

/** The published formula, written out independently so the tests do not reuse the code. */
const expected = (e: number, x: number, p: number, i: number, r: number, b: number) =>
  Math.round(100 * Math.min(1, e * x * Math.max(p, i) * r * b))

describe('the arithmetic case', () => {
  const F = { exposure: 0.9, exploitability: 0.6, privilege: 0.6, impact: 1.0, reach: 0.85, boost: 1 }
  const t = factorTable(path(F, { score: expected(0.9, 0.6, 0.6, 1.0, 0.85, 1) }))

  it('reproduces the published formula', () => {
    expect(t.arithmeticScore).toBe(expected(0.9, 0.6, 0.6, 1.0, 0.85, 1))
    expect(t.determinedBy).toBe('arithmetic')
  })

  it('emits one row per factor', () => {
    expect(t.rows.map((r) => r.key)).toEqual(
      ['exposure', 'exploitability', 'privilege', 'impact', 'reach', 'boost'])
  })

  it('"if neutral" is checkable against the formula by hand', () => {
    // Neutralise exploitability (0.6 -> 1.0) and the rest holds.
    const row = t.rows.find((r) => r.key === 'exploitability')!
    expect(row.ifNeutral).toBe(expected(0.9, 1.0, 0.6, 1.0, 0.85, 1))
  })

  it('withheld is the gap between now and neutral, never negative', () => {
    for (const r of t.rows) {
      if (r.state !== 'active') continue
      expect(r.withheld).toBe(r.ifNeutral! - t.arithmeticScore)
      expect(r.withheld).toBeGreaterThanOrEqual(0)
    }
  })

  it('a factor already at 1.0 withholds nothing', () => {
    const boost = t.rows.find((r) => r.key === 'boost')!
    expect(boost.value).toBe(1)
    expect(boost.withheld).toBe(0)
  })

  it('the verdict explains what the numbers mean rather than asserting a rank', () => {
    expect(t.verdict).toContain('multiply out')
    expect(t.verdict).toContain('if that one factor were 1.0')
  })
})

describe('DOMINATED — max(privilege, impact) drops a term', () => {
  it('marks the smaller of privilege/impact as not in the product', () => {
    const t = factorTable(path(
      { exposure: 0.9, exploitability: 1, privilege: 0.6, impact: 1.0, reach: 0.85, boost: 1 },
      { score: 77 }))
    const priv = t.rows.find((r) => r.key === 'privilege')!
    expect(priv.state).toBe('dominated')
    expect(priv.ifNeutral).toBeNull()
    expect(priv.withheld).toBeNull()
    expect(priv.note).toContain('max(privilege, impact)')
  })

  it('the dominant term stays active', () => {
    const t = factorTable(path(
      { exposure: 0.9, exploitability: 1, privilege: 0.6, impact: 1.0, reach: 0.85, boost: 1 },
      { score: 77 }))
    expect(t.rows.find((r) => r.key === 'impact')!.state).toBe('active')
  })

  it('domination flips when privilege is the larger term', () => {
    const t = factorTable(path(
      { exposure: 0.9, exploitability: 1, privilege: 1.0, impact: 0.6, reach: 0.85, boost: 1 },
      { score: 77 }))
    expect(t.rows.find((r) => r.key === 'impact')!.state).toBe('dominated')
    expect(t.rows.find((r) => r.key === 'privilege')!.state).toBe('active')
  })

  it('a TIE is not domination', () => {
    // Both values ARE the term. Calling one dominated would tell a reader that raising
    // it is pointless, when raising it would move the score immediately.
    const t = factorTable(path(
      { exposure: 0.9, exploitability: 1, privilege: 0.8, impact: 0.8, reach: 1, boost: 1 },
      { score: 72 }))
    expect(t.rows.find((r) => r.key === 'privilege')!.state).toBe('active')
    expect(t.rows.find((r) => r.key === 'impact')!.state).toBe('active')
  })
})

describe('SATURATED — the product exceeds 1.0 and is clamped', () => {
  const t = factorTable(path(
    { exposure: 1, exploitability: 1, privilege: 1, impact: 1, reach: 1, boost: 1.5 },
    { score: 100 }))

  it('is detected', () => {
    expect(t.saturated).toBe(true)
    expect(t.arithmeticScore).toBe(100)
  })

  it('reports no per-factor movement, because there is none', () => {
    for (const r of t.rows) {
      expect(r.state).toBe('saturated')
      expect(r.ifNeutral).toBeNull()
    }
  })

  it('says so in the verdict', () => {
    expect(t.verdict).toContain('clamped')
  })
})

describe('OVERRIDDEN — a floor or cap decided the score', () => {
  it('detects a floor by comparing to the stored score, not by copying a constant', () => {
    // Weak factors, but the engine stored 90: a floor bound. This is observed, so the
    // file cannot drift when aws_correlate.WEIGHTS changes.
    const t = factorTable(path(
      { exposure: 0.5, exploitability: 0.2, privilege: 0.6, impact: 0.6, reach: 0.5, boost: 1 },
      { score: 90, kev: true, hard_floor_applied: true }))
    expect(t.determinedBy).toBe('floor')
    expect(t.arithmeticScore).toBeLessThan(90)
    expect(t.verdict).toContain('known-exploited')
    expect(t.verdict).toContain('floor decided this score')
  })

  it('names the unconditioned-reach floor when it is not the KEV one', () => {
    const t = factorTable(path(
      { exposure: 0.5, exploitability: 0.2, privilege: 0.6, impact: 0.6, reach: 0.5, boost: 1 },
      { score: 80, hard_floor_applied: false }))
    expect(t.determinedBy).toBe('floor')
    expect(t.verdict).toContain('unconditioned')
  })

  it('detects a cap', () => {
    const t = factorTable(path(
      { exposure: 1, exploitability: 1, privilege: 1, impact: 1, reach: 1, boost: 1 },
      { score: 55, conditioned: true }))
    expect(t.determinedBy).toBe('cap')
    expect(t.verdict).toContain('condition-guarded')
  })

  it('refuses to attribute ANY factor when an override bound', () => {
    // THE point. The arithmetic did not decide this number, so presenting per-factor
    // movement would describe a derivation that did not happen.
    const t = factorTable(path(
      { exposure: 0.5, exploitability: 0.2, privilege: 0.6, impact: 0.9, reach: 0.5, boost: 1 },
      { score: 90, hard_floor_applied: true }))
    for (const r of t.rows) {
      expect(r.ifNeutral).toBeNull()
      expect(r.withheld).toBeNull()
    }
  })

  it('still shows the factor VALUES, which remain true', () => {
    const t = factorTable(path(
      { exposure: 0.5, exploitability: 0.2, privilege: 0.6, impact: 0.9, reach: 0.5, boost: 1 },
      { score: 90, hard_floor_applied: true }))
    expect(t.rows.find((r) => r.key === 'exposure')!.value).toBe(0.5)
    expect(t.rows.find((r) => r.key === 'exposure')!.meaning).toBeTruthy()
  })
})

describe('the two axes', () => {
  const t = factorTable(path(
    { exposure: 0.9, exploitability: 0.9, privilege: 0.6, impact: 1, reach: 0.9, boost: 1 },
    { score: 72 }))

  it('every row declares what it drives and where it came from', () => {
    for (const r of t.rows) {
      expect(['probability', 'impact']).toContain(r.axis)
      expect(['asset', 'path', 'threat']).toContain(r.origin)
    }
  })

  it('threat boost is the only threat-intel factor', () => {
    expect(t.rows.filter((r) => r.origin === 'threat').map((r) => r.key)).toEqual(['boost'])
  })

  it('every row carries a plain-language meaning, not just a number', () => {
    for (const r of t.rows) expect(r.meaning.length).toBeGreaterThan(10)
  })
})

describe('malformed input', () => {
  it('a missing factors object does not throw', () => {
    const t = factorTable(path({} as Record<string, number>, { score: 100 }))
    expect(t.rows).toHaveLength(6)
  })

  it('a non-numeric factor falls back to neutral rather than NaN', () => {
    const t = factorTable(path(
      { exposure: NaN, exploitability: 1, privilege: 1, impact: 1, reach: 1, boost: 1 },
      { score: 100 }))
    expect(Number.isFinite(t.arithmeticScore)).toBe(true)
  })

  it('a zero factor collapses the score without dividing by zero', () => {
    const t = factorTable(path(
      { exposure: 0, exploitability: 1, privilege: 1, impact: 1, reach: 1, boost: 1 },
      { score: 0 }))
    expect(t.arithmeticScore).toBe(0)
    for (const r of t.rows) expect(Number.isFinite(r.ifNeutral ?? 0)).toBe(true)
  })
})
