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

/* ── local accounts ─────────────────────────────────────────────────────────
 * Creating an account and granting it a role is ONE call, because two can
 * half-succeed and both halves fail badly alone: an account with no role signs
 * in and sees nothing, and a role with no account is a grant to somebody who
 * cannot arrive. The server rolls the account back if the grant fails. */
export interface AppUser {
  username: string
  display_name: string
  status: string
  must_change_password: boolean | number
  last_login_at: number | null
  /** The role this user holds IN THE WORKSPACE BEING VIEWED. Null means they
   *  have an account but no membership here — which is exactly the half-state
   *  worth seeing rather than hiding. */
  role: string | null
}

export interface CreatedUser {
  username: string
  role: string
  workspace_id: string
  /** Shown once and not recoverable. Never stored in the clear. */
  password: string
  must_change_password: boolean
  note: string
}

export const listUsers = (workspaceId: string) =>
  json<AppUser[]>(`/auth/users?workspace_id=${encodeURIComponent(workspaceId)}`)

export const createUser = (
  workspaceId: string, username: string, role: string, displayName: string,
) => json<CreatedUser>('/auth/users', {
  method: 'POST',
  body: JSON.stringify({ workspace_id: workspaceId, username, role,
                         display_name: displayName }),
})

export const setUserStatus = (workspaceId: string, username: string, status: string) =>
  json<{ username: string; status: string }>(
    `/auth/users/${encodeURIComponent(username)}/status`,
    { method: 'POST', body: JSON.stringify({ workspace_id: workspaceId, status }) })

export const resetUserPassword = (workspaceId: string, username: string) =>
  json<{ username: string; password: string }>(
    `/auth/users/${encodeURIComponent(username)}/password`,
    { method: 'POST', body: JSON.stringify({ workspace_id: workspaceId }) })
