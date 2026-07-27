import { describe, it, expect } from 'vitest'
import { crossAccountFindings, exposureReport, buildExecHtml, CROSS_ACCOUNT_CHECKS } from './reports'
import type { FindingCatalogEntry, GraphFull } from '../api/types'

const F = (check_id: string, extra: Partial<FindingCatalogEntry> = {}): FindingCatalogEntry => ({
  check_id, section: 'X', severity: 'HIGH', status: 'FAIL', compliance: {}, remediation_cmd: '',
  risk: 'r', impact: 'i', steps: [], affected: [], count: 1, distinct: 1, ...extra,
} as FindingCatalogEntry)

describe('crossAccountFindings', () => {
  it('keeps only trust-boundary-crossing check ids', () => {
    const rows = crossAccountFindings([F('VPC-06'), F('S3-01'), F('KMS-04'), F('IAM-01')])
    expect(rows.map((r) => r.check_id)).toEqual(['VPC-06', 'KMS-04'])
  })
  it('the check-id set is non-trivial', () => expect(CROSS_ACCOUNT_CHECKS.size).toBeGreaterThan(5))
})

describe('exposureReport', () => {
  it('flattens EXPOSED_TO edges (only), carrying ports/ip_kind/basis', () => {
    const g: GraphFull = {
      directed: true, multigraph: false, nodes: [],
      edges: [
        { source: 'internet', target: 'arn:eni-1', kind: 'EXPOSED_TO', ports: [443, 22], ip_kind: 'public', basis: '4-gate' },
        { source: 'a', target: 'b', kind: 'CAN_ASSUME' },
      ],
    }
    const rows = exposureReport(g)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ resource: 'arn:eni-1', exposed_via: 'internet', ports: '443,22', ip_kind: 'public', basis: '4-gate' })
  })
  it('null graph → empty', () => expect(exposureReport(null)).toEqual([]))
})

describe('buildExecHtml', () => {
  // AccountSummary.summary is a StatusCount (NOT narrative) — the report must never render it
  // as prose (that produced "[object Object]"). Severity comes from the findings.
  const html = buildExecHtml({
    scope: '123456789012', isOrg: false,
    summary: { posture_score: 72, posture_grade: 'C', summary: { PASS: 10, FAIL: 3, WARN: 1, INFO: 0 } } as never,
    findings: [F('ATTACK-01', { severity: 'CRITICAL', risk: 'internet to admin' }), F('IAM-02', { severity: 'HIGH' })],
  })
  it('is a self-contained HTML doc with the posture score and a findings table', () => {
    expect(html.startsWith('<!doctype html>')).toBe(true)
    expect(html).toContain('72')
    expect(html).toContain('ATTACK-01')
    expect(html).not.toMatch(/https?:\/\//)          // self-contained, no external asset
  })
  it('never renders a StatusCount object as prose', () => {
    expect(html).not.toContain('[object Object]')
    expect(html).toContain('1 critical and 1 high')  // derived assessment from findings
  })
  it('counts severity from findings, so ORG scope (no summary) is still populated', () => {
    const org = buildExecHtml({ scope: 'org', isOrg: true, summary: null, orgScore: 65,
      findings: [F('A', { severity: 'CRITICAL' }), F('B', { severity: 'CRITICAL' }), F('C', { severity: 'LOW' })] })
    expect(org).toContain('2 CRITICAL')              // pills reflect findings, not a null summary
    expect(org).toContain('65')
  })
  it('escapes HTML in finding text (no injection)', () => {
    const h = buildExecHtml({ scope: 'x', isOrg: false, summary: null, findings: [F('X-01', { risk: '<script>bad</script>' })] })
    expect(h).not.toContain('<script>bad')
    expect(h).toContain('&lt;script&gt;')
  })
})
