import { describe, it, expect } from 'vitest'
import { composeQuery, QUERY_EXAMPLES, QUICK_PREDS } from './querybuilder'
import { parse } from './wql'

// The guided builder + every preset must emit queries the WQL parser accepts (no free text can
// escape the typed grammar). parse() is the same security boundary the backend enforces.
describe('composeQuery emits valid WQL', () => {
  it('kind only → no where', () => {
    expect(composeQuery('S3Bucket', [], 'and')).toEqual({ kind: 'S3Bucket' })
  })
  it('single predicate → bare where', () => {
    expect(composeQuery('S3Bucket', ['crown_jewel'], 'and')).toEqual({ kind: 'S3Bucket', where: { pred: 'crown_jewel' } })
  })
  it('multiple predicates → combined by op', () => {
    const q = composeQuery('S3Bucket', ['crown_jewel', 'internet'], 'and')
    expect(q).toEqual({ kind: 'S3Bucket', where: { op: 'and', of: [{ pred: 'crown_jewel' }, { pred: 'reachable_from', target: 'internet' }] } })
  })
  it('empty kind → all nodes (no kind key)', () => {
    expect(composeQuery('', ['crown_jewel'], 'or')).toEqual({ where: { pred: 'crown_jewel' } })
  })
  it('every composed query and preset parses', () => {
    const keys = QUICK_PREDS.map((p) => p.key)
    expect(() => parse(composeQuery('EC2Instance', keys, 'or'))).not.toThrow()
    for (const ex of QUERY_EXAMPLES) expect(() => parse(ex.query)).not.toThrow()
  })
})
