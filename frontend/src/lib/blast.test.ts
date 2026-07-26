import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { computeBlastRadius, E_PATH } from './blast'
import type { GraphFull } from '../api/types'

// The client-side blast radius must mirror cnapp_service.get_blast_radius exactly (SAMPLE
// mode BFSes the graph fixture, live mode calls the hub — same shape). Validated against a
// synthetic graph AND the real sample fixture so a fixture drift fails the build.
const SAMPLE = join(process.cwd(), 'public', 'sample')
const read = (f: string): GraphFull => JSON.parse(readFileSync(join(SAMPLE, f), 'utf-8'))

function synthetic(): GraphFull {
  return {
    directed: true, multigraph: false,
    nodes: [
      { id: 'internet', kind: 'InternetSource' },
      { id: 'ec2', kind: 'EC2Instance', name: 'i-1' },
      { id: 'role', kind: 'IAMRole' },
      { id: 'admin', kind: 'AdminCapability' },
      { id: 'bucket', kind: 'S3Bucket', name: 'crown', crown_jewel: true },
      { id: 'cve', kind: 'Vulnerability' },
    ],
    edges: [
      { source: 'internet', target: 'ec2', kind: 'EXPOSED_TO' },
      { source: 'ec2', target: 'role', kind: 'HAS_ROLE' },
      { source: 'role', target: 'admin', kind: 'CAN_PRIVESC_TO' },
      { source: 'ec2', target: 'bucket', kind: 'CAN_READ_DATA' },
      { source: 'ec2', target: 'cve', kind: 'HAS_VULN' }, // annotation — not traversed
    ],
  }
}

describe('E_PATH matches the backend edge universe', () => {
  it('includes the attack edges and excludes annotations', () => {
    expect(E_PATH.has('CAN_READ_DATA')).toBe(true)
    expect(E_PATH.has('HAS_VULN')).toBe(false)
    expect(E_PATH.has('RUNS_IMAGE')).toBe(false)
  })
})

describe('computeBlastRadius over a synthetic graph', () => {
  const r = computeBlastRadius(synthetic(), 'ec2')

  it('reaches the crown and admin forward, ordered data-first', () => {
    expect(r.reaches.map((x) => [x.id, x.terminal])).toEqual([['bucket', 'data'], ['admin', 'admin']])
    expect(r.counts).toEqual({ crowns: 1, admins: 1, sources: 1 })
  })
  it('does not traverse the HAS_VULN annotation', () => {
    expect(r.reaches.every((x) => x.id !== 'cve')).toBe(true)
  })
  it('is reached by the internet (reverse) and flags it', () => {
    expect(r.reached_by.map((x) => x.id)).toEqual(['internet'])
    expect(r.internet_reachable).toBe(true)
  })
  it('honors max_hops (admin is 2 hops from the host)', () => {
    const one = computeBlastRadius(synthetic(), 'ec2', 1)
    expect(one.reaches.map((x) => x.id)).toEqual(['bucket'])
  })
  it('clamps max_hops to [1,12]', () => {
    expect(computeBlastRadius(synthetic(), 'ec2', 99).max_hops).toBe(12)
  })
  it('returns exists:false for an unknown node', () => {
    const u = computeBlastRadius(synthetic(), 'nope')
    expect(u.exists).toBe(false)
    expect(u.reaches).toEqual([])
  })
})

describe('sort tie-break is code-point (matches Python), not locale-folded', () => {
  // two same-hop predecessors that differ only by case must order by Unicode code point
  // (Z=0x5A < a=0x61), exactly as the Python hub's str-tie-break does — else sample≠live.
  function tie(): GraphFull {
    return {
      directed: true, multigraph: false,
      nodes: [
        { id: 'x', kind: 'S3Bucket', crown_jewel: true },
        { id: 'arn:aws:iam::1:role/Zeus', kind: 'IAMRole' },
        { id: 'arn:aws:iam::1:role/apollo', kind: 'IAMRole' },
      ],
      edges: [
        { source: 'arn:aws:iam::1:role/Zeus', target: 'x', kind: 'CAN_READ_DATA' },
        { source: 'arn:aws:iam::1:role/apollo', target: 'x', kind: 'CAN_READ_DATA' },
      ],
    }
  }
  it('orders uppercase before lowercase at equal path length', () => {
    const r = computeBlastRadius(tie(), 'x')
    expect(r.reached_by.map((row) => row.id)).toEqual(
      ['arn:aws:iam::1:role/Zeus', 'arn:aws:iam::1:role/apollo'])   // code-point, not localeCompare
  })
})

describe('computeBlastRadius over the real sample fixture', () => {
  const g = read('account_123456789012_graph.json')
  const HOST = 'arn:aws:ec2:us-east-1:123456789012:instance/i-0app01server'

  it('the flagship host reaches at least one crown-jewel datastore and is internet-reachable', () => {
    const r = computeBlastRadius(g, HOST)
    expect(r.exists).toBe(true)
    expect(r.counts.crowns).toBeGreaterThanOrEqual(1)
    expect(r.internet_reachable).toBe(true)
    expect(r.reaches.every((x) => x.terminal === 'data' || x.terminal === 'admin')).toBe(true)
  })
})
