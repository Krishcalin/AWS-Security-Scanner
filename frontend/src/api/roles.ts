/**
 * Workspace membership: who is in a workspace and what they may do.
 *
 * SEPARATE FROM api/client.ts ON PURPOSE. Everything there is scan data, read
 * through a SAMPLE-mode branch that falls back to fixtures. These are
 * authorisation writes: there is no sample fallback, because a role picker that
 * silently "worked" against a fixture would be the worst possible thing to
 * demo — an operator would believe they had granted something.
 */

const API_BASE = (import.meta.env.VITE_API_BASE as string) ?? '/api'

export interface RoleSpec {
  role: string
  rank: number
  description: string
}

export interface RoleCatalogue {
  roles: RoleSpec[]
  legacy_aliases: Record<string, string>
  note: string
}

export interface Member {
  workspace_id: string
  principal: string
  role: string
  status: string
  added_by?: string | null
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    ...init,
  })
  if (!r.ok) {
    let detail: unknown = `${r.status} ${r.statusText}`
    try { detail = (await r.json()).detail ?? detail } catch { /* keep status */ }
    throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
  }
  return r.status === 204 ? (undefined as T) : ((await r.json()) as T)
}

/** The assignable roles, served by the API so the picker cannot offer a role
 *  the gate does not know — or omit one it does. */
export const listRoles = () => json<RoleCatalogue>('/roles')

export const listMembers = (workspaceId: string) =>
  json<Member[]>(`/workspaces/${encodeURIComponent(workspaceId)}/members`)

export const addMember = (workspaceId: string, principal: string, role: string) =>
  json<Member>(`/workspaces/${encodeURIComponent(workspaceId)}/members`, {
    method: 'POST',
    body: JSON.stringify({ principal, role }),
  })

export const removeMember = (workspaceId: string, principal: string) =>
  json<void>(
    `/workspaces/${encodeURIComponent(workspaceId)}/members/${encodeURIComponent(principal)}`,
    { method: 'DELETE' },
  )
