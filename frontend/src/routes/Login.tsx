import { useState } from 'react'
import { useNavigate } from 'react-router'
import { login } from '../api/auth'

/**
 * The sign-in screen — the first thing an unauthenticated visitor sees.
 *
 * Split layout: the form on the left where the eye lands and the cursor already is,
 * the brand on the right. Same shape as the sibling product's console so the two
 * read as one family.
 *
 * THE ERROR MESSAGE IS DELIBERATELY VAGUE. The server returns the same
 * "invalid username or password" for a wrong password and an unknown account, and
 * this renders it verbatim. Splitting them would be friendlier and would turn the
 * form into a directory an attacker can enumerate before guessing a single password.
 *
 * There is no "forgot password" link because there is no self-service reset: an
 * unauthenticated reset path is a way in. An administrator issues a new password.
 */
export default function Login() {
  const nav = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login(username.trim(), password)
      // Full reload rather than a client-side navigate: every screen fetches on
      // mount, and a hard load guarantees they all start from the authenticated
      // state instead of reusing whatever a pre-login render had cached.
      window.location.assign('/')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed')
      setPassword('')
      setBusy(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-form-side">
        <div className="login-form-wrap">
          <h1 className="login-title">Sign in</h1>
          <p className="login-sub">
            AWS cloud-native posture, exposure and attack paths — assessed
            agentlessly, tracked to closure.
          </p>

          <form className="login-card" onSubmit={submit}>
            <label className="login-label" htmlFor="username">Username</label>
            <input
              id="username" className="login-input" autoComplete="username"
              autoFocus value={username} onChange={(e) => setUsername(e.target.value)}
            />

            <label className="login-label" htmlFor="password">Password</label>
            <input
              id="password" className="login-input" type="password"
              autoComplete="current-password" value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            {error && <p className="login-error" role="alert">{error}</p>}

            <button className="login-btn" type="submit" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="login-help">
            Forgotten it? There is no self-service reset — an unauthenticated reset
            is a way in. Ask an administrator, who can issue you a new one.
          </p>
        </div>
      </div>

      <div className="login-brand-side">
        <img className="login-logo" src="/overwatch-logo.png"
             alt="OverWatch — AWS Cloud-Native Application Protection" />
      </div>
    </div>
  )
}
