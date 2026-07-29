// dspm.ts — the byte-for-byte TS mirror of aws_dspm.classify / apply_dspm, so SAMPLE mode (WQL
// over the graph fixture) sees the SAME data_types / sensitivity_tier the LIVE hub stamps at read
// time (cnapp_service._graph_with_runtime). Guarded by the shared cross-language parity fixture.
import type { GraphFull, GNode } from '../api/types'

const TYPE_MAP: Record<string, string> = {
  pii: 'PII', personal: 'PII', gdpr: 'PII', ferpa: 'PII', personal_information: 'PII',
  phi: 'PHI', hipaa: 'PHI',
  pci: 'PCI', 'pci-dss': 'PCI', pcidss: 'PCI', cardholder: 'PCI',
  financial: 'FINANCIAL', financial_information: 'FINANCIAL', glba: 'FINANCIAL', sox: 'FINANCIAL',
  secret: 'SECRET', credentials: 'SECRET',
  'ai-data': 'AI', ai: 'AI',
}
const DATA_TYPES_ORDER = ['PCI', 'PHI', 'PII', 'FINANCIAL', 'SECRET', 'AI']
const HIGH_TOKENS = new Set(['restricted', 'critical', 'secret', 'pci', 'phi', 'pii', 'hipaa',
  'pci-dss', 'pcidss', 'gdpr', 'credentials'])
const MED_TOKENS = new Set(['confidential', 'sensitive', 'high', 'financial', 'glba', 'sox', 'ai-data'])

export interface Classification { data_types: string[]; sensitivity_tier: string; classifier: string }

// mirror aws_dspm.classify — normalize a datastore node's heterogeneous signals.
export function classify(props: Record<string, unknown>): Classification {
  props = props || {}
  let sval = props.sensitivity
  const types: string[] = []
  let tier = ''
  let classifier = 'unclassified'

  if (props.secret) { types.push('SECRET'); tier = 'restricted'; classifier = 'secret' }

  if (typeof sval === 'boolean') sval = undefined       // a stray bool is not a sensitivity signal
  if (typeof sval === 'number' && Number.isFinite(sval)) {
    classifier = 'macie-auto'
    tier = sval >= 75 ? 'restricted' : 'confidential'
  } else if (typeof sval === 'string' && sval.trim()) {
    const token = sval.trim().toLowerCase()
    if (classifier === 'unclassified') classifier = 'tag'
    const t = TYPE_MAP[token]
    if (t && !types.includes(t)) types.push(t)
    if (HIGH_TOKENS.has(token)) tier = tier || 'restricted'
    else if (MED_TOKENS.has(token)) tier = tier || 'confidential'
    else tier = tier || 'internal'
  }

  if (props.sensitivity === 'ai-data' && !types.includes('AI')) types.push('AI')

  const ordered = DATA_TYPES_ORDER.filter((t) => types.includes(t))
  return { data_types: ordered, sensitivity_tier: tier, classifier }
}

// mirror aws_dspm.apply_dspm — stamp data_types / sensitivity_tier / classifier on every
// crown-jewel / DataStore node (matching add_node MERGE: empty values are omitted, not set).
export function applyDspm(graph: GraphFull): number {
  let n = 0
  for (const node of graph.nodes as GNode[]) {
    if (!(node.crown_jewel || node.DataStore)) continue
    const c = classify(node)
    if (c.data_types.length) node.data_types = c.data_types
    if (c.sensitivity_tier) node.sensitivity_tier = c.sensitivity_tier
    node.classifier = c.classifier
    n++
  }
  return n
}
