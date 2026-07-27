import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { findingInProject, severityCounts } from './projects'
import type { FindingCatalogEntry } from '../api/types'

// The client matcher must mirror cnapp_service._finding_in_project so SAMPLE == LIVE. Also
// validate the sample projects.json actually lights up findings in the flagship account.
const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))

const F = (account: string, affected: string[], severity = 'HIGH'): FindingCatalogEntry =>
  ({ check_id: 'X-01', section: 'X', severity, affected, account } as unknown as FindingCatalogEntry)

describe('findingInProject', () => {
  it('account + glob: both must hold', () => {
    const m = { accounts: ['111'], resource_globs: ['*payments*'] }
    expect(findingInProject(F('111', ['prod-payments-db']), m)).toBe(true)
    expect(findingInProject(F('111', ['other']), m)).toBe(false)       // account ok, glob miss
    expect(findingInProject(F('222', ['prod-payments-db']), m)).toBe(false) // glob ok, account miss
  })
  it('account-only project matches any resource in that account', () => {
    expect(findingInProject(F('111', ['whatever']), { accounts: ['111'] })).toBe(true)
    expect(findingInProject(F('222', ['whatever']), { accounts: ['111'] })).toBe(false)
  })
  it('empty match matches nothing (never everything)', () => {
    expect(findingInProject(F('111', ['x']), {})).toBe(false)
  })
  it('glob is case-sensitive (mirrors fnmatchcase)', () => {
    expect(findingInProject(F('1', ['Prod']), { accounts: ['1'], resource_globs: ['prod'] })).toBe(false)
  })
  it('supports [...] / [!...] character classes like Python fnmatchcase', () => {
    const m = { accounts: ['1'], resource_globs: ['db-[0-9]*'] }
    expect(findingInProject(F('1', ['db-3-prod']), m)).toBe(true)
    expect(findingInProject(F('1', ['db-x-prod']), m)).toBe(false)
    const neg = { accounts: ['1'], resource_globs: ['[!p]*'] }
    expect(findingInProject(F('1', ['queue-1']), neg)).toBe(true)
    expect(findingInProject(F('1', ['prod-1']), neg)).toBe(false)
  })
})

describe('severityCounts', () => {
  it('tallies the four buckets', () => {
    const c = severityCounts([F('1', [], 'CRITICAL'), F('1', [], 'HIGH'), F('1', [], 'HIGH')])
    expect(c).toMatchObject({ CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0 })
  })
})

describe('sample projects.json lights up the flagship account', () => {
  it('prod-payments matches ≥1 finding in account 123456789012', () => {
    const defs = read('projects.json') as { id: string; match: { accounts?: string[]; resource_globs?: string[] } }[]
    const pay = defs.find((d) => d.id === 'prod-payments')!
    const findings = (read('account_123456789012_findings.json') as FindingCatalogEntry[])
      .map((f) => ({ ...f, account: '123456789012' }))
    expect(findings.filter((f) => findingInProject(f, pay.match)).length).toBeGreaterThan(0)
  })
})
