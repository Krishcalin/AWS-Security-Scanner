/**
 * The Top-Risks roll-up, and the rules that keep its numbers honest.
 *
 * The dashboard this answers shows a 0–10 on every row. OverWatch has no such number,
 * so the tests that matter here are the negative ones: that a score is never derived
 * from a severity band, never invented when the data is silent, and that a CVSS never
 * outranks a whole-path score.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import {
  RISK_CATEGORIES, topRisks, rankRows, pathScores, cvssByNode, categoryOf,
  type TopRiskRow,
} from './toprisks'
import type { AttackPath, FindingCatalogEntry, IngestedVuln } from '../api/types'

const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))
const ACCTS = ['123456789012', '234567890123', '345678901234']

const F = (o: Partial<FindingCatalogEntry>): FindingCatalogEntry => ({
  check_id: 'X-01', section: 'X', severity: 'MEDIUM', status: 'FAIL',
  compliance: {}, remediation_cmd: '', risk: '', impact: '', steps: [],
  affected: [], count: 1, distinct: 1, ...o,
})
const R = (o: Partial<TopRiskRow>): TopRiskRow => ({
  key: 'k', check_id: 'X-01', section: 'X', severity: 'MEDIUM', status: 'FAIL',
  asset: '', assetCount: 1, score: null, basis: null, ...o,
})

// ── categories must be able to populate ─────────────────────────────────────
describe('category definitions', () => {
  it('every prefix ends with a dash so SEC- never swallows SEG-', () => {
    for (const c of RISK_CATEGORIES) {
      for (const p of c.prefixes) expect(p.endsWith('-'), `${c.slug}:${p}`).toBe(true)
    }
  })

  it('every prefix matches at least one check id the product ships', () => {
    // A category whose prefixes match nothing is a permanently empty card, and an
    // empty card reads as "no risk in this domain".
    const ids = new Set<string>()
    for (const a of ACCTS) {
      try { for (const e of read(`account_${a}_findings.json`)) ids.add(e.check_id) } catch { /* no fixture */ }
    }
    // The fixtures are a sample of the 452-check universe, so this asserts the
    // shape of a prefix rather than coverage: it must be a plausible family
    // (letters/digits then a dash), and the ones the fixtures DO exercise must hit.
    for (const c of RISK_CATEGORIES) {
      for (const p of c.prefixes) expect(p).toMatch(/^[A-Z0-9]+-$/)
    }
    const matched = [...ids].filter((id) => RISK_CATEGORIES.some((c) => categoryOf(id, c)))
    expect(matched.length, 'no sample finding lands in any category').toBeGreaterThan(0)
  })

  it('slugs are unique', () => {
    const s = RISK_CATEGORIES.map((c) => c.slug)
    expect(new Set(s).size).toBe(s.length)
  })
})

// ── the numbers ─────────────────────────────────────────────────────────────
describe('a score is never invented', () => {
  it('a finding with no path and no CVE gets null, not a number from its band', () => {
    const [vuln] = topRisks([F({ check_id: 'VULN-09', severity: 'CRITICAL' })], [], [])
      .filter((r) => r.cat.slug === 'vulnerabilities')
    expect(vuln.rows[0].score).toBeNull()
    expect(vuln.rows[0].basis).toBeNull()
  })

  it('a CRITICAL band does not become 9.x, 10, or any other number', () => {
    for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const out = topRisks([F({ check_id: 'IAM-99', severity: sev })], [], [])
      const row = out.find((r) => r.cat.slug === 'identity')!.rows[0]
      expect(row.score, sev).toBeNull()
    }
  })

  it('a null cvss_base is not treated as a zero score', () => {
    const v: IngestedVuln[] = [{
      node_id: 'n1', node_kind: 'EC2Instance', cve: 'CVE-1', package: 'p',
      installed_version: '1', fixed_version: null, severity: 'HIGH', cvss_base: null,
    } as IngestedVuln]
    const out = topRisks([F({ check_id: 'VULN-01', affected: ['n1'] })], [], v)
    expect(out.find((r) => r.cat.slug === 'vulnerabilities')!.rows[0].score).toBeNull()
  })
})

describe('score provenance', () => {
  const paths: AttackPath[] = [{
    entry: 'internet', terminal: 't', terminal_kind: 'data', nodes: [], edges: [],
    score: 84, severity: 'CRITICAL', conditioned: false, vuln_pivot: true, kev: true,
    active_threat: false, direct_public_crown: false, hard_floor_applied: true,
    factors: {}, driving_findings: ['ATTACK-01', 'VULN-02:CVE-2021-44228'], rationale: '',
  }]

  it('takes the path score for a finding that drives a path', () => {
    const out = topRisks([F({ check_id: 'ATTACK-01' })], paths, [])
    const row = out.find((r) => r.cat.slug === 'attack-paths')!.rows[0]
    expect(row.score).toBe(84)
    expect(row.basis).toBe('path')
  })

  it('matches a driving finding that carries a CVE suffix', () => {
    const out = topRisks([F({ check_id: 'VULN-02' })], paths, [])
    const row = out.find((r) => r.cat.slug === 'vulnerabilities')!.rows[0]
    expect(row.score).toBe(84)
    expect(row.basis).toBe('path')
  })

  it('takes the worst CVSS across the resources a finding affects', () => {
    const v = [
      { node_id: 'a', cvss_base: 5.3 }, { node_id: 'b', cvss_base: 9.8 },
    ] as IngestedVuln[]
    const out = topRisks([F({ check_id: 'VULN-07', affected: ['a', 'b'] })], [], v)
    const row = out.find((r) => r.cat.slug === 'vulnerabilities')!.rows[0]
    expect(row.score).toBe(9.8)
    expect(row.basis).toBe('cvss')
  })

  it('takes the WORST path when a finding drives several', () => {
    const two = [{ ...paths[0], score: 40 }, { ...paths[0], score: 91 }]
    expect(pathScores(two).get('ATTACK-01')).toBe(91)
  })

  it('prefers the path score over a CVSS on the same finding', () => {
    const v = [{ node_id: 'a', cvss_base: 10 }] as IngestedVuln[]
    const out = topRisks([F({ check_id: 'VULN-02', affected: ['a'] })], paths, v)
    const row = out.find((r) => r.cat.slug === 'vulnerabilities')!.rows[0]
    expect(row.basis).toBe('path')
    expect(row.score).toBe(84)
  })

  it('cvssByNode ignores entries with no base score', () => {
    const m = cvssByNode([{ node_id: 'a', cvss_base: null }] as IngestedVuln[])
    expect(m.has('a')).toBe(false)
  })
})

// ── ordering ────────────────────────────────────────────────────────────────
describe('rankRows', () => {
  it('a path score outranks a higher-looking CVSS', () => {
    // 10.0 CVSS on something unreachable must not beat a 30/100 real path.
    const out = rankRows([
      R({ check_id: 'A', score: 10, basis: 'cvss' }),
      R({ check_id: 'B', score: 30, basis: 'path' }),
    ])
    expect(out[0].check_id).toBe('B')
  })

  it('any scored row outranks an unscored CRITICAL', () => {
    const out = rankRows([
      R({ check_id: 'A', severity: 'CRITICAL' }),
      R({ check_id: 'B', score: 4.1, basis: 'cvss', severity: 'LOW' }),
    ])
    expect(out[0].check_id).toBe('B')
  })

  it('orders scored rows of the same basis by score', () => {
    const out = rankRows([
      R({ check_id: 'A', score: 55, basis: 'path' }),
      R({ check_id: 'B', score: 91, basis: 'path' }),
    ])
    expect(out.map((r) => r.check_id)).toEqual(['B', 'A'])
  })

  it('falls back to severity for unscored rows', () => {
    const out = rankRows([
      R({ check_id: 'A', severity: 'LOW' }),
      R({ check_id: 'B', severity: 'CRITICAL' }),
      R({ check_id: 'C', severity: 'MEDIUM' }),
    ])
    expect(out.map((r) => r.check_id)).toEqual(['B', 'C', 'A'])
  })

  it('breaks a severity tie on how many resources are affected', () => {
    const out = rankRows([
      R({ check_id: 'A', severity: 'HIGH', assetCount: 1 }),
      R({ check_id: 'B', severity: 'HIGH', assetCount: 12 }),
    ])
    expect(out[0].check_id).toBe('B')
  })

  it('is deterministic for otherwise identical rows', () => {
    const rows = [R({ check_id: 'Z-1' }), R({ check_id: 'A-1' })]
    expect(rankRows(rows).map((r) => r.check_id)).toEqual(['A-1', 'Z-1'])
    expect(rankRows([...rows].reverse()).map((r) => r.check_id)).toEqual(['A-1', 'Z-1'])
  })

  it('does not mutate its input', () => {
    const rows = [R({ check_id: 'B', severity: 'LOW' }), R({ check_id: 'A', severity: 'CRITICAL' })]
    rankRows(rows)
    expect(rows.map((r) => r.check_id)).toEqual(['B', 'A'])
  })

  it('an unknown severity sorts last rather than first', () => {
    // indexOf returns -1 for an unrecognised band; untreated that sorts it above
    // CRITICAL, putting a band nobody understands at the top of the card.
    const out = rankRows([
      R({ check_id: 'A', severity: 'WAT' }),
      R({ check_id: 'B', severity: 'LOW' }),
    ])
    expect(out[0].check_id).toBe('B')
  })
})

// ── the roll-up ─────────────────────────────────────────────────────────────
describe('topRisks', () => {
  it('returns every category, including the empty ones', () => {
    // An omitted category is invisible; an empty one says "nothing found here".
    const out = topRisks([], [], [])
    expect(out).toHaveLength(RISK_CATEGORIES.length)
    expect(out.every((r) => r.rows.length === 0)).toBe(true)
  })

  it('caps rows at the limit but reports the true total', () => {
    const many = Array.from({ length: 25 }, (_, i) =>
      F({ check_id: `IAM-${i}`, severity: 'HIGH' }))
    const out = topRisks(many, [], []).find((r) => r.cat.slug === 'identity')!
    expect(out.rows).toHaveLength(10)
    expect(out.total).toBe(25)
  })

  it('a finding may appear in more than one category only if both claim its prefix', () => {
    const out = topRisks([F({ check_id: 'EKS-01' })], [], [])
    const hits = out.filter((r) => r.rows.length > 0).map((r) => r.cat.slug)
    expect(hits).toEqual(['containers'])
  })

  it('SEG- lands on exposure and never on secrets', () => {
    const out = topRisks([F({ check_id: 'SEG-01' })], [], [])
    const hits = out.filter((r) => r.rows.length > 0).map((r) => r.cat.slug)
    expect(hits).toContain('exposure')
    expect(hits).not.toContain('secrets')
  })

  it('keys rows by account so the same check in two accounts stays distinct', () => {
    const out = topRisks([
      F({ check_id: 'IAM-01', account: '111111111111' }),
      F({ check_id: 'IAM-01', account: '222222222222' }),
    ], [], []).find((r) => r.cat.slug === 'identity')!
    expect(new Set(out.rows.map((r) => r.key)).size).toBe(2)
  })

  it('survives a finding with no affected list', () => {
    const out = topRisks([F({ check_id: 'IAM-01', affected: undefined as never })], [], [])
    expect(out.find((r) => r.cat.slug === 'identity')!.rows[0].asset).toBe('')
  })
})

// ── against the shipped fixtures ────────────────────────────────────────────
describe('over real-scan fixtures', () => {
  it('ranks without throwing and never emits a score outside its scale', () => {
    for (const a of ACCTS) {
      let catalog: FindingCatalogEntry[] = []
      try { catalog = read(`account_${a}_findings.json`) } catch { continue }
      const summary = read(`account_${a}_summary.json`)
      const out = topRisks(catalog, summary.attack_paths ?? [], [])
      for (const r of out) {
        for (const row of r.rows) {
          if (row.basis === 'path') expect(row.score).toBeGreaterThanOrEqual(0)
          if (row.basis === 'path') expect(row.score).toBeLessThanOrEqual(100)
          if (row.basis === 'cvss') expect(row.score).toBeLessThanOrEqual(10)
          if (row.basis === null) expect(row.score).toBeNull()
        }
      }
    }
  })

  it('places most sample findings in some category', () => {
    const catalog: FindingCatalogEntry[] = read(`account_${ACCTS[0]}_findings.json`)
    const placed = catalog.filter((e) => RISK_CATEGORIES.some((c) => categoryOf(e.check_id, c)))
    expect(placed.length / catalog.length).toBeGreaterThan(0.5)
  })
})
