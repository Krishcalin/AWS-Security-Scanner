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

/** Thrown when the password was right and a 6-digit code is still needed. A
 *  distinct type, not a message match: the UI has to branch on this, and matching
 *  on prose breaks the moment the wording changes. */
export class TotpRequired extends Error {
  constructor(message = 'Enter the 6-digit code from your authenticator app.') {
    super(message)
    this.name = 'TotpRequired'
  }
}

/** Reads the server's error body, distinguishing "needs a second factor" from a
 *  real failure. The failure message is deliberately identical for a wrong password
 *  and an unknown user — do not "improve" it here, the distinction is a username
 *  oracle. A wrong CODE lands there too, on purpose: "password right, code wrong"
 *  would confirm a guessed password. */
async function authError(r: Response, fallback: string): Promise<Error> {
  try {
    const body = await r.json()
    const d = body?.detail
    if (d && typeof d === 'object' && d.error === 'totp_required') {
      return new TotpRequired(typeof d.message === 'string' ? d.message : undefined)
    }
    if (typeof d === 'string') return new Error(d)
  } catch {
    /* a non-JSON error body is still a failure */
  }
  return new Error(fallback)
}

export async function login(
  username: string, password: string, totpCode?: string,
): Promise<Me> {
  const r = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ username, password, totp_code: totpCode ?? '' }),
  })
  if (!r.ok) throw await authError(r, 'Sign-in failed')
  return (await r.json()) as Me
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/auth/logout`, { method: 'POST' })
}

/** Change a password with CREDENTIALS rather than a session, so the form can live
 *  on the sign-in screen — the usual reason to change a password is that you were
 *  handed a temporary one and cannot get in with it yet. Throws TotpRequired when a
 *  second factor is enrolled and no code was supplied. */
export async function changePassword(
  username: string, currentPassword: string, newPassword: string, totpCode?: string,
): Promise<void> {
  const r = await fetch(`${API_BASE}/auth/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      username, current_password: currentPassword,
      new_password: newPassword, totp_code: totpCode ?? '',
    }),
  })
  if (!r.ok) throw await authError(r, 'Could not change the password')
}

// ── second-factor enrolment (all require a session) ─────────────────────────
export interface TotpStatus { enabled: boolean; recovery_codes_left: number }
export interface TotpEnrolment {
  secret: string
  formatted_secret: string
  uri: string
  /** Server-rendered SVG. Safe to inline: the encoder emits only <rect> elements
   *  at numeric coordinates, so no part of the URI (which contains the username)
   *  ever reaches the markup. */
  qr_svg: string
}

export async function totpStatus(): Promise<TotpStatus> {
  const r = await fetch(`${API_BASE}/auth/totp/status`)
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  return (await r.json()) as TotpStatus
}

export async function totpBegin(): Promise<TotpEnrolment> {
  const r = await fetch(`${API_BASE}/auth/totp/begin`, { method: 'POST' })
  if (!r.ok) throw await authError(r, 'Could not start enrolment')
  return (await r.json()) as TotpEnrolment
}

/** Returns the recovery codes, which are shown ONCE — only fingerprints are stored
 *  server-side, so they can never be redisplayed, only regenerated. */
export async function totpConfirm(totpCode: string): Promise<string[]> {
  const r = await fetch(`${API_BASE}/auth/totp/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ totp_code: totpCode }),
  })
  if (!r.ok) throw await authError(r, 'That code is not valid')
  return ((await r.json()).recovery_codes ?? []) as string[]
}

export async function totpDisable(password: string, totpCode: string): Promise<void> {
  const r = await fetch(`${API_BASE}/auth/totp/disable`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ password, totp_code: totpCode }),
  })
  if (!r.ok) throw await authError(r, 'Could not turn off two-factor authentication')
}
