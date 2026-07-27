import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { DASHBOARDS, findingInDashboard, dashboardBySlug } from './dashboards'

// The dashboards roll up the SAME finding_catalog by check-id prefix. These guard the matcher
// (esp. the SEC-/SEG- disambiguation) and that every dashboard slug is unique + resolvable.
const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))

describe('findingInDashboard matcher', () => {
  const exposure = dashboardBySlug('exposure')!
  const secrets = dashboardBySlug('secrets')!

  it('matches by check-id prefix', () => {
    expect(findingInDashboard({ check_id: 'EXPOSURE-03', section: 'X' }, exposure)).toBe(true)
    expect(findingInDashboard({ check_id: 'SEG-01', section: 'X' }, exposure)).toBe(true)
  })
  it('does NOT let SEG- leak into the SEC- (secrets) dashboard', () => {
    expect(findingInDashboard({ check_id: 'SEG-01', section: 'NETWORK' }, secrets)).toBe(false)
    expect(findingInDashboard({ check_id: 'SEC-05', section: 'SECRETS' }, secrets)).toBe(true)
  })
  it('falls back to a section match', () => {
    expect(findingInDashboard({ check_id: 'ZZZ-01', section: 'DATA' }, dashboardBySlug('data-security')!)).toBe(true)
  })
  it('rejects an unrelated finding', () => {
    expect(findingInDashboard({ check_id: 'IAM-01', section: 'IAM' }, exposure)).toBe(false)
  })
})

describe('dashboard specs are well-formed', () => {
  it('every slug is unique and resolvable', () => {
    const slugs = DASHBOARDS.map((d) => d.slug)
    expect(new Set(slugs).size).toBe(slugs.length)
    for (const s of slugs) expect(dashboardBySlug(s)?.slug).toBe(s)
  })
  it('every dashboard has at least one prefix and a blurb', () => {
    for (const d of DASHBOARDS) {
      expect(d.prefixes.length).toBeGreaterThan(0)
      expect(d.blurb.length).toBeGreaterThan(0)
    }
  })
})

describe('the real sample findings light up at least one dashboard', () => {
  it('every dashboard-eligible sample finding routes somewhere', () => {
    const findings = read('account_123456789012_findings.json') as { check_id: string; section: string }[]
    // the flagship account has exposure findings — Exposure must be non-empty
    const exposure = dashboardBySlug('exposure')!
    const n = findings.filter((f) => findingInDashboard(f, exposure)).length
    expect(n).toBeGreaterThan(0)
  })
})
