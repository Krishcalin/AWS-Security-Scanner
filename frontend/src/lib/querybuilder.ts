// querybuilder.ts — pure helpers for the Query console (routes/Query.tsx). The guided builder
// composes a typed WQL JSON object from a kind + a set of quick predicates; the presets double
// as documentation. All output is plain WQL that wql.ts / aws_wql.py validate — no free text.

// The node kinds worth offering as a starting filter (''=any). Aligned with lib/nodes META
// plus the graph's data-store kinds.
export const QUERY_KINDS = [
  '', 'S3Bucket', 'EC2Instance', 'IAMRole', 'IAMUser', 'RDSInstance', 'DynamoDBTable',
  'LoadBalancer', 'ECRImage', 'Vulnerability', 'AdminCapability', 'InternetSource',
]

export interface QuickPred { key: string; label: string; pred: Record<string, unknown> }
export const QUICK_PREDS: QuickPred[] = [
  { key: 'crown_jewel', label: 'Crown jewel', pred: { pred: 'crown_jewel' } },
  { key: 'internet', label: 'Internet-reachable', pred: { pred: 'reachable_from', target: 'internet' } },
  { key: 'reaches_admin', label: 'Reaches admin', pred: { pred: 'reaches', target: 'admin' } },
  { key: 'reaches_crown', label: 'Reaches crown data', pred: { pred: 'reaches', target: 'crown' } },
  { key: 'public', label: 'public = true', pred: { pred: 'has_prop', field: 'public', value: true } },
  { key: 'unencrypted', label: 'encrypted = false', pred: { pred: 'prop', field: 'encrypted', op: 'eq', value: false } },
]

/** Compose a WQL query from the guided builder. One predicate → bare where; many → combined by
 *  `combine` (and|or). Empty kind → no kind filter (all nodes); no predicates → no where. */
export function composeQuery(kind: string, predKeys: string[], combine: 'and' | 'or'): Record<string, unknown> {
  const q: Record<string, unknown> = {}
  if (kind) q.kind = kind
  const preds = QUICK_PREDS.filter((p) => predKeys.includes(p.key)).map((p) => p.pred)
  if (preds.length === 1) q.where = preds[0]
  else if (preds.length > 1) q.where = { op: combine, of: preds }
  return q
}

export interface Example { name: string; query: Record<string, unknown> }
export const QUERY_EXAMPLES: Example[] = [
  { name: 'Exposed crown-jewel S3', query: { kind: 'S3Bucket', where: { op: 'and', of: [{ pred: 'crown_jewel' }, { pred: 'reachable_from', target: 'internet' }] } } },
  { name: 'IAM roles that reach admin', query: { kind: 'IAMRole', where: { pred: 'reaches', target: 'admin' } } },
  { name: 'Public buckets', query: { kind: 'S3Bucket', where: { pred: 'has_prop', field: 'public', value: true } } },
  { name: 'Internet-reachable EC2', query: { kind_in: ['EC2Instance'], where: { pred: 'reachable_from', target: 'internet' } } },
  { name: 'All crown-jewel data', query: { where: { pred: 'crown_jewel' } } },
]

/** Stable pretty-print for the JSON editor (2-space, sorted-stable key order as authored). */
export function prettyQuery(q: unknown): string {
  return JSON.stringify(q, null, 2)
}
