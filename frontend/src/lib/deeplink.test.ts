import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { pathId, lastSeg, matchPath, vulnKey, matchVuln } from './deeplink'
import type { AttackPath, IngestedVuln } from '../api/types'

// Fixtures are the source of truth: these tests fail the moment a sample ARN, cve, or
// account id drifts out from under a deep-link/scenario that references it.
const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))
const ACCTS = ['123456789012', '234567890123', '345678901234']

function allPaths(): AttackPath[] {
  return ACCTS.flatMap((a) => {
    const s = read(`account_${a}_summary.json`)
    return (s.attack_paths as AttackPath[]).map((p) => ({ ...p, account: a }))
  })
}

describe('lastSeg', () => {
  it('keeps internet literal', () => expect(lastSeg('internet')).toBe('internet'))
  it('takes the ARN tail after the last colon then slash', () => {
    expect(lastSeg('arn:aws:rds:us-east-1:123456789012:db:customers-db')).toBe('customers-db')
    expect(lastSeg('arn:aws:ec2:us-east-1:123456789012:instance/i-0app01server')).toBe('i-0app01server')
    expect(lastSeg('lb/arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-api-alb/6d0e12')).toBe('6d0e12')
  })
})

describe('pathId over the real fixtures', () => {
  const paths = allPaths()

  it('the flagship prod-payments path encodes to a readable internet__customers-db prefix', () => {
    const flagship = paths.find((p) => p.account === '123456789012' && Math.round(p.score) === 100)
    expect(flagship).toBeTruthy()
    expect(pathId(flagship!)).toMatch(/^internet__customers-db__/)
  })

  it('is unique within every account (no two paths collide)', () => {
    for (const a of ACCTS) {
      const inAcct = paths.filter((p) => p.account === a)
      const ids = inAcct.map(pathId)
      expect(new Set(ids).size, `collision in account ${a}: ${ids}`).toBe(inAcct.length)
    }
  })

  it('distinguishes two paths that share entry+terminal but differ in their node chain', () => {
    const term = 'arn:aws:rds:us-east-1:123456789012:db:customers-db'
    const a = { entry: 'internet', terminal: term, nodes: ['internet', 'nodeA', term] }
    const b = { entry: 'internet', terminal: term, nodes: ['internet', 'nodeB', term] }
    expect(pathId(a)).not.toBe(pathId(b))                 // regression: collision opened the wrong path
    expect(pathId(a)).toBe(pathId({ ...a }))              // deterministic
  })

  it('matchPath round-trips every path back to itself', () => {
    for (const p of paths) {
      const scoped = paths.filter((q) => q.account === p.account)
      expect(matchPath(scoped, pathId(p))).toBe(p)
    }
    expect(matchPath(paths, null)).toBeNull()
    expect(matchPath(paths, 'internet__does-not-exist')).toBeNull()
  })
})

describe('vuln keys over the real fixtures', () => {
  const vulns: IngestedVuln[] = read('vulns.json')

  it('vulnKey is a stable, lossless composite of account|node_id|cve', () => {
    const v = vulns.find((x) => x.cve === 'CVE-2021-44228' && x.account === '123456789012')!
    expect(vulnKey(v)).toBe(`123456789012|${v.node_id}|CVE-2021-44228`)
  })

  it('matchVuln resolves a row by its exact vulnKey and round-trips (no lossy collisions)', () => {
    const scoped = vulns.filter((v) => v.account === '123456789012')
    const log = scoped.find((v) => v.cve === 'CVE-2021-44228')!
    const v = matchVuln(scoped, vulnKey(log))
    expect(v).toBe(log)
    expect(v!.priority_score).toBe(94)
    expect(matchVuln(scoped, null)).toBeNull()
    expect(matchVuln(scoped, 'no|such|row')).toBeNull()
  })
})
