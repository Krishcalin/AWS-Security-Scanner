// Authentication client for the built-in local-auth provider (/api/auth/*).
//
// The session is an HttpOnly cookie, so there is deliberately NO token handling
// here: JavaScript cannot read it, which is the point — an XSS bug in the console
// cannot exfiltrate a session. `fetch` defaults to credentials: 'same-origin', so
// the cookie rides along without being touched.
//
// In sample mode the console reads static fixtures and never calls the API, so
// there is nothing to authenticate against; `AuthGate` skips itself there rather
// than bouncing an offline demo to a login page that cannot work.
const API_BASE = (import.meta.env.VITE_API_BASE as string) ?? '/api'

export interface Me {
  username: string
  display_name: string
  is_superadmin: boolean
  must_change_password: boolean
  memberships: Record<string, string>
}

/** The signed-in user, or null when unauthenticated. Never throws on a 401 —
 *  "not logged in" is an expected state on first load, not an error. */
export async function me(): Promise<Me | null> {
  const r = await fetch(`${API_BASE}/auth/me`, { headers: { Accept: 'application/json' } })
  if (r.status === 401) return null
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return (await r.json()) as Me
}

/** Throws with the server's message on failure. That message is deliberately the
 *  same for a wrong password and an unknown user — do not "improve" it here, the
 *  distinction is a username oracle. */
export async function login(username: string, password: string): Promise<Me> {
  const r = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  if (!r.ok) {
    let detail = 'Sign-in failed'
    try {
      const body = await r.json()
      if (body && typeof body.detail === 'string') detail = body.detail
    } catch {
      /* a non-JSON error body is still a failed sign-in */
    }
    throw new Error(detail)
  }
  return (await r.json()) as Me
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/auth/logout`, { method: 'POST' })
}

export async function changePassword(
  currentPassword: string, newPassword: string,
): Promise<void> {
  const r = await fetch(`${API_BASE}/auth/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  })
  if (!r.ok) {
    let detail = 'Could not change the password'
    try {
      const body = await r.json()
      if (body && typeof body.detail === 'string') detail = body.detail
    } catch { /* keep the generic message */ }
    throw new Error(detail)
  }
}
