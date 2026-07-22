import { api } from '../api/client'
import type { GraphFull, GNode, GEdge } from '../api/types'

/** Ids of accounts that have scan results (the org aggregation set). */
export async function activeAccountIds(): Promise<string[]> {
  const list = await api.listAccounts()
  return list.filter((a) => a.onboarding_status === 'active').map((a) => a.account_id)
}

/** Load one account's graph, or the union across active accounts (org scope),
 *  tagging every node/edge with the account it came from. */
export async function loadGraph(scope: string): Promise<{ nodes: GNode[]; edges: GEdge[] }> {
  const tag = (g: GraphFull, acct: string) => ({
    nodes: g.nodes.map((n) => ({ ...n, account: acct })),
    edges: g.edges.map((e) => ({ ...e, account: acct })),
  })
  if (scope !== 'org') return tag(await api.graph(scope), scope)
  const ids = await activeAccountIds()
  const parts = await Promise.all(
    ids.map((id) => api.graph(id).then((g) => tag(g, id)).catch(() => ({ nodes: [], edges: [] }))),
  )
  return { nodes: parts.flatMap((p) => p.nodes), edges: parts.flatMap((p) => p.edges) }
}
