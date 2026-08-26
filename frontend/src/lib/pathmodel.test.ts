/**
 * The join the full-screen attack path view depends on.
 *
 * Run against the SHIPPED SAMPLE FIXTURES, which are generated from real scans. That
 * matters: the demo seeder used to build its graph beside its paths rather than from
 * them, so only `internet` appeared in both and any view that joined the two rendered
 * empty. The fixtures were coherent throughout, which is what makes them the honest
 * reference for what this join has to survive.
 */
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { buildPathModel, sentenceFor } from './pathmodel'
import type { AttackPath, GraphFull, FindingCatalogEntry } from '../api/types'

const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string) => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))
const ACCTS = ['123456789012', '234567890123', '345678901234']

interface Case { account: string; path: AttackPath; graph: GraphFull; catalog: FindingCatalogEntry[] }

function cases(): Case[] {
  const out: Case[] = []
  for (const account of ACCTS) {
    const summary = read(`account_${account}_summary.json`)
    const gf = join(SAMPLE, `account_${account}_graph.json`)
    if (!existsSync(gf)) continue
    const graph: GraphFull = read(`account_${account}_graph.json`)
    let catalog: FindingCatalogEntry[] = []
    try { catalog = read(`account_${account}_findings.json`) } catch { catalog = [] }
    for (const path of (summary.attack_paths ?? []) as AttackPath[]) {
      out.push({ account, path, graph, catalog })
    }
  }
  return out
}

const ALL = cases()

describe('fixtures', () => {
  it('there are paths to test against at all', () => {
    expect(ALL.length).toBeGreaterThan(0)
  })
})

describe('buildPathModel over real-scan fixtures', () => {
  it('resolves every path node against the graph', () => {
    for (const c of ALL) {
      const m = buildPathModel(c.path, c.graph, c.catalog)
      expect(m.missingNodes, `${c.account} → ${c.path.terminal}`).toEqual([])
    }
  })

  it('resolves every hop to an edge the graph declares', () => {
    for (const c of ALL) {
      const m = buildPathModel(c.path, c.graph, c.catalog)
      expect(m.missingHops, `${c.account} → ${c.path.terminal}`).toBe(0)
    }
  })

  it('produces one hop per path edge', () => {
    for (const c of ALL) {
      const m = buildPathModel(c.path, c.graph, c.catalog)
      expect(m.hops).toHaveLength(c.path.edges.length)
    }
  })

  it('recovers a basis for hops the graph recorded one on', () => {
    // Not every edge kind carries a basis, so this asserts that SOME hop across the
    // whole fixture set resolves one — the join working at all — rather than
    // demanding one everywhere and inviting a fabricated default.
    const withBasis = ALL.flatMap((c) => buildPathModel(c.path, c.graph, c.catalog).hops)
      .filter((h) => h.basis !== '')
    expect(withBasis.length).toBeGreaterThan(0)
  })

  it('never invents a basis', () => {
    for (const c of ALL) {
      const m = buildPathModel(c.path, c.graph, c.catalog)
      const byPair = new Map<string, Record<string, unknown>>()
      for (const e of c.graph.edges) byPair.set(`${e.source} ${e.target} ${e.kind}`, e)
      for (const h of m.hops) {
        if (!h.basis) continue
        const e = byPair.get(`${h.from} ${h.to} ${h.rel}`)
        expect(e?.basis, `${h.from}->${h.to}`).toBe(h.basis)
      }
    }
  })
})

// ── the invariant: a miss is reported, never hidden ──────────────────────────
const PATH: AttackPath = {
  entry: 'internet',
  terminal: 'arn:aws:s3:::acme-crown',
  terminal_kind: 'data',
  nodes: ['internet', 'arn:aws:ec2:us-east-1:1:instance/i-1', 'arn:aws:s3:::acme-crown'],
  edges: [
    ['internet', 'arn:aws:ec2:us-east-1:1:instance/i-1', 'EXPOSED_TO'],
    ['arn:aws:ec2:us-east-1:1:instance/i-1', 'arn:aws:s3:::acme-crown', 'CAN_READ_DATA'],
  ],
  score: 90, severity: 'CRITICAL', conditioned: false, vuln_pivot: true, kev: true,
  active_threat: false, direct_public_crown: false, hard_floor_applied: true,
  factors: {}, driving_findings: ['ATTACK-01', 'VULN-02:CVE-2021-44228'], rationale: 'x',
}

const GRAPH: GraphFull = {
  directed: true, multigraph: false,
  nodes: [
    { id: 'internet', kind: 'InternetSource' },
    { id: 'arn:aws:ec2:us-east-1:1:instance/i-1', kind: 'EC2Instance' },
    { id: 'arn:aws:s3:::acme-crown', kind: 'S3Bucket', crown_jewel: true },
  ],
  edges: [
    { source: 'internet', target: 'arn:aws:ec2:us-east-1:1:instance/i-1', kind: 'EXPOSED_TO', basis: '0.0.0.0/0 security group', ports: '22,443' },
    { source: 'arn:aws:ec2:us-east-1:1:instance/i-1', target: 'arn:aws:s3:::acme-crown', kind: 'CAN_READ_DATA', basis: 's3:GetObject' },
  ],
}

describe('unresolved data is reported, not hidden', () => {
  it('a null graph is flagged rather than read as a clean estate', () => {
    const m = buildPathModel(PATH, null, [])
    expect(m.hasGraph).toBe(false)
    // With no graph there is nothing to be missing FROM — the view reports the absent
    // graph itself, and must not also claim every node is missing.
    expect(m.missingNodes).toEqual([])
    expect(m.missingHops).toBe(0)
  })

  it('names path nodes the graph does not declare', () => {
    const thin: GraphFull = { ...GRAPH, nodes: GRAPH.nodes.slice(0, 1) }
    const m = buildPathModel(PATH, thin, [])
    expect(m.missingNodes).toHaveLength(2)
  })

  it('counts hops the graph does not declare, and keeps the hop', () => {
    const thin: GraphFull = { ...GRAPH, edges: [GRAPH.edges[0]] }
    const m = buildPathModel(PATH, thin, [])
    expect(m.missingHops).toBe(1)
    expect(m.hops).toHaveLength(2)          // the hop survives, drawn dashed
    expect(m.hops[1].known).toBe(false)
    expect(m.hops[1].basis).toBe('')        // and carries no invented basis
  })

  it('leaves basis empty when the graph recorded none', () => {
    const noBasis: GraphFull = {
      ...GRAPH,
      edges: GRAPH.edges.map(({ source, target, kind }) => ({ source, target, kind })),
    }
    const m = buildPathModel(PATH, noBasis, [])
    expect(m.hops.every((h) => h.known)).toBe(true)
    expect(m.hops.every((h) => h.basis === '')).toBe(true)
  })
})

describe('hop resolution', () => {
  it('carries basis and ports through', () => {
    const m = buildPathModel(PATH, GRAPH, [])
    expect(m.hops[0].basis).toBe('0.0.0.0/0 security group')
    expect(m.hops[0].ports).toBe('22,443')
    expect(m.hops[1].basis).toBe('s3:GetObject')
  })

  it('prefers the edge whose kind the path names when a pair has several', () => {
    const multi: GraphFull = {
      ...GRAPH,
      edges: [
        { source: 'internet', target: 'arn:aws:ec2:us-east-1:1:instance/i-1', kind: 'TARGETS', basis: 'wrong one' },
        ...GRAPH.edges,
      ],
    }
    const m = buildPathModel(PATH, multi, [])
    expect(m.hops[0].rel).toBe('EXPOSED_TO')
    expect(m.hops[0].basis).toBe('0.0.0.0/0 security group')
  })
})

describe('evidence attachment', () => {
  const catalog: FindingCatalogEntry[] = [
    { check_id: 'EC2-05', section: 'EC2', severity: 'MEDIUM', status: 'FAIL', compliance: {}, remediation_cmd: '', risk: '', impact: '', steps: [], affected: ['arn:aws:ec2:us-east-1:1:instance/i-1'], count: 1, distinct: 1 },
    { check_id: 'S3-01', section: 'S3', severity: 'CRITICAL', status: 'FAIL', compliance: {}, remediation_cmd: '', risk: '', impact: '', steps: [], affected: ['arn:aws:s3:::acme-crown'], count: 1, distinct: 1 },
    { check_id: 'IAM-01', section: 'IAM', severity: 'HIGH', status: 'FAIL', compliance: {}, remediation_cmd: '', risk: '', impact: '', steps: [], affected: ['arn:aws:iam::1:user/other'], count: 1, distinct: 1 },
  ]

  it('attaches a finding to the node its affected list names', () => {
    const m = buildPathModel(PATH, GRAPH, catalog)
    expect(m.evidence.get('arn:aws:s3:::acme-crown')?.map((e) => e.label)).toEqual(['S3-01'])
  })

  it('does not attach findings about resources that are not on the path', () => {
    const m = buildPathModel(PATH, GRAPH, catalog)
    const labels = [...m.evidence.values()].flat().map((e) => e.label)
    expect(labels).not.toContain('IAM-01')
  })

  it('hangs the pivot CVE on the compute node, not the terminal', () => {
    const m = buildPathModel(PATH, GRAPH, catalog)
    const host = m.evidence.get('arn:aws:ec2:us-east-1:1:instance/i-1') ?? []
    expect(host[0].label).toBe('CVE-2021-44228')
    expect(host[0].kind).toBe('cve')
    const crown = m.evidence.get('arn:aws:s3:::acme-crown') ?? []
    expect(crown.map((e) => e.kind)).not.toContain('cve')
  })

  it('marks the pivot CVE critical only when the path is KEV', () => {
    const notKev = { ...PATH, kev: false }
    const m = buildPathModel(notKev, GRAPH, catalog)
    const host = m.evidence.get('arn:aws:ec2:us-east-1:1:instance/i-1') ?? []
    expect(host[0].severity).toBe('HIGH')
    expect(host[0].sub).not.toContain('KEV')
  })

  it('orders evidence by severity so the worst is visible first', () => {
    const many: FindingCatalogEntry[] = [
      { ...catalog[0], check_id: 'A-LOW', severity: 'LOW' },
      { ...catalog[0], check_id: 'A-CRIT', severity: 'CRITICAL' },
      { ...catalog[0], check_id: 'A-MED', severity: 'MEDIUM' },
    ]
    const m = buildPathModel({ ...PATH, driving_findings: [] }, GRAPH, many)
    expect(m.evidence.get('arn:aws:ec2:us-east-1:1:instance/i-1')?.map((e) => e.label))
      .toEqual(['A-CRIT', 'A-MED', 'A-LOW'])
  })

  it('an empty catalog yields zero evidence rather than throwing', () => {
    const m = buildPathModel({ ...PATH, driving_findings: [] }, GRAPH, [])
    expect(m.evidenceTotal).toBe(0)
  })
})

describe('sentenceFor', () => {
  it('opens from the internet without naming a node the reader has not met', () => {
    const m = buildPathModel(PATH, GRAPH, [])
    const s = sentenceFor(m.hops[0], true)
    expect(s).toContain('unauthenticated adversary on the internet')
    expect(s).toContain('0.0.0.0/0 security group')
  })

  it('names both ends on a later hop', () => {
    const m = buildPathModel(PATH, GRAPH, [])
    const s = sentenceFor(m.hops[1], false)
    expect(s).toContain('i-1')
    expect(s).toContain('acme-crown')
    expect(s).toContain('can read')
  })

  it('states no reason when the graph recorded no basis', () => {
    const noBasis: GraphFull = {
      ...GRAPH,
      edges: GRAPH.edges.map(({ source, target, kind }) => ({ source, target, kind })),
    }
    const m = buildPathModel(PATH, noBasis, [])
    // The em-dash clause is the "because" — it must be absent rather than filled in.
    expect(sentenceFor(m.hops[1], false)).not.toContain('—')
  })

  it('every fixture hop produces a sentence that ends cleanly', () => {
    for (const c of ALL) {
      const m = buildPathModel(c.path, c.graph, c.catalog)
      m.hops.forEach((h, i) => {
        const s = sentenceFor(h, i === 0)
        expect(s.endsWith('.')).toBe(true)
        expect(s).not.toContain('undefined')
      })
    }
  })
})
