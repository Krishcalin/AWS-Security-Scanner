import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect } from 'vitest'
import { classify, applyDspm } from './dspm'
import type { GraphFull } from '../api/types'

// dspm.ts must classify identically to aws_dspm.py, else the DSPM data-type props differ offline
// vs online and the WQL "holds PII" query diverges. Replayed from the shared parity fixture
// (aws_dspm.classify is the oracle; tests/test_wql_parity.py fails if the fixture drifts).
interface DspmCase { props: Record<string, unknown>; expected: { data_types: string[]; sensitivity_tier: string; classifier: string } }
interface Parity { dspm: DspmCase[] }
const FX: Parity = JSON.parse(
  readFileSync(join(process.cwd(), 'src', 'lib', '__fixtures__', 'wql_parity.json'), 'utf-8'))

describe('dspm.ts classify == aws_dspm.py on the shared parity fixture', () => {
  it('has a non-trivial classify battery', () => {
    expect(FX.dspm.length).toBeGreaterThanOrEqual(10)
  })
  for (const c of FX.dspm) {
    it(`classify ${JSON.stringify(c.props)}`, () => {
      expect(classify(c.props)).toEqual(c.expected)
    })
  }
})

describe('applyDspm stamps datastores only (mirrors aws_dspm.apply_dspm)', () => {
  it('sets data_types/tier on crown + DataStore nodes, skips others', () => {
    const g: GraphFull = {
      directed: true, multigraph: false, nodes: [
        { id: 's3', kind: 'S3Bucket', crown_jewel: true, sensitivity: 'pii' },
        { id: 'ddb', kind: 'DynamoDBTable', DataStore: true, sensitivity: 'pci' },
        { id: 'ec2', kind: 'EC2Instance', name: 'web' },
      ], edges: [],
    }
    const n = applyDspm(g)
    expect(n).toBe(2)
    expect((g.nodes[0] as { data_types?: string[] }).data_types).toEqual(['PII'])
    expect((g.nodes[1] as { data_types?: string[] }).data_types).toEqual(['PCI'])
    expect((g.nodes[2] as { data_types?: string[] }).data_types).toBeUndefined()
  })
})
