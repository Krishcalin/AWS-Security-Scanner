import { useState } from 'react'
import { login, changePassword, TotpRequired } from '../api/auth'

/**
 * The sign-in screen. Three modes on one page, because they are the same
 * conversation: prove who you are, prove it again with a second factor, or replace
 * the password you were just handed.
 *
 * WHY CHANGE-PASSWORD LIVES HERE AND NOT BEHIND A LOGIN. The usual reason to change
 * a password is that an administrator issued you a temporary one — so requiring a
 * session first would put the feature behind the door it exists to open. It is not
 * weaker: the form proves the current password and the second factor, which is the
 * whole check either way. A session was never what protected it.
 *
 * THE ERROR MESSAGE IS DELIBERATELY VAGUE. The server returns the same
 * "invalid username or password" for a wrong password, an unknown account AND a
 * wrong 6-digit code, and this renders it verbatim. Splitting them would be
 * friendlier and would turn the form into an oracle — the account-exists version is
 * a directory, and the "password right, code wrong" version confirms a guessed
 * password to someone holding only half the credential.
 *
 * There is no "forgot password" link because there is no self-service reset: an
 * unauthenticated reset path is a way in.
 */
type Mode = 'signin' | 'totp' | 'change'

export default function Login() {
  const [mode, setMode] = useState<Mode>('signin')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  function resetMessages() { setError(''); setNotice('') }

  function toMode(next: Mode) {
    resetMessages()
    setCode('')
    setNewPassword(''); setConfirmPassword('')
    if (next !== 'totp') setPassword('')
    setMode(next)
  }

  async function submitSignin(e: React.FormEvent) {
    e.preventDefault(); resetMessages(); setBusy(true)
    try {
      await login(username.trim(), password, mode === 'totp' ? code : undefined)
      // Hard load, not a client-side navigate: every screen fetches on mount, and
      // this guarantees they all start from the authenticated state rather than
      // reusing anything a pre-login render cached.
      window.location.assign('/')
    } catch (err) {
      if (err instanceof TotpRequired) {
        // The password is already proven; ask for the code and keep it in state so
        // the user does not retype it.
        setMode('totp'); setCode(''); setNotice(err.message)
      } else {
        setError(err instanceof Error ? err.message : 'Sign-in failed')
        setCode('')
        if (mode !== 'totp') setPassword('')
      }
      setBusy(false)
    }
  }

  async function submitChange(e: React.FormEvent) {
    e.preventDefault(); resetMessages()
    if (newPassword !== confirmPassword) {
      setError('The two new passwords do not match.'); return
    }
    setBusy(true)
    try {
      await changePassword(username.trim(), password, newPassword, code || undefined)
      // Every session was revoked, including any this call opened — so the only
      // correct next step is to sign in again.
      toMode('signin')
      setNotice('Password changed. Sign in with the new one.')
    } catch (err) {
      if (err instanceof TotpRequired) setNotice(err.message)
      else setError(err instanceof Error ? err.message : 'Could not change the password')
      setBusy(false)
      return
    }
    setBusy(false)
  }

  return (
    <div className="login-page">
      <div className="login-form-side">
        <div className="login-form-wrap">
          <h1 className="login-title">
            {mode === 'change' ? 'Change password'
              : mode === 'totp' ? 'Two-factor authentication' : 'Sign in'}
          </h1>
          <p className="login-sub">
            {mode === 'totp'
              ? 'Open your authenticator app and enter the current 6-digit code. A recovery code works here too.'
              : 'AWS cloud-native posture, exposure and attack paths — assessed agentlessly, tracked to closure.'}
          </p>

          {mode === 'totp' ? (
            <form className="login-card" onSubmit={submitSignin}>
              <label className="login-label" htmlFor="code">Authentication code</label>
              <input
                id="code" className="login-input" inputMode="numeric"
                autoComplete="one-time-code" autoFocus value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="123456"
              />
              {notice && <p className="login-notice">{notice}</p>}
              {error && <p className="login-error" role="alert">{error}</p>}
              <button className="login-btn" type="submit" disabled={busy}>
                {busy ? 'Verifying…' : 'Verify'}
              </button>
              <button className="login-link" type="button" onClick={() => toMode('signin')}>
                Back
              </button>
            </form>
          ) : mode === 'change' ? (
            <form className="login-card" onSubmit={submitChange}>
              <label className="login-label" htmlFor="cu">Username</label>
              <input id="cu" className="login-input" autoComplete="username" autoFocus
                     value={username} onChange={(e) => setUsername(e.target.value)} />

              <label className="login-label" htmlFor="cp">Current password</label>
              <input id="cp" className="login-input" type="password"
                     autoComplete="current-password" value={password}
                     onChange={(e) => setPassword(e.target.value)} />

              <label className="login-label" htmlFor="np">New password</label>
              <input id="np" className="login-input" type="password"
                     autoComplete="new-password" value={newPassword}
                     onChange={(e) => setNewPassword(e.target.value)} />

              <label className="login-label" htmlFor="np2">Confirm new password</label>
              <input id="np2" className="login-input" type="password"
                     autoComplete="new-password" value={confirmPassword}
                     onChange={(e) => setConfirmPassword(e.target.value)} />

              <label className="login-label" htmlFor="cc">
                Authentication code <span className="login-hint">(if 2FA is on)</span>
              </label>
              <input id="cc" className="login-input" inputMode="numeric"
                     autoComplete="one-time-code" value={code}
                     onChange={(e) => setCode(e.target.value)} placeholder="123456" />

              {notice && <p className="login-notice">{notice}</p>}
              {error && <p className="login-error" role="alert">{error}</p>}
              <button className="login-btn" type="submit" disabled={busy}>
                {busy ? 'Changing…' : 'Change password'}
              </button>
              <button className="login-link" type="button" onClick={() => toMode('signin')}>
                Back to sign in
              </button>
            </form>
          ) : (
            <form className="login-card" onSubmit={submitSignin}>
              <label className="login-label" htmlFor="username">Username</label>
              <input id="username" className="login-input" autoComplete="username"
                     autoFocus value={username}
                     onChange={(e) => setUsername(e.target.value)} />

              <label className="login-label" htmlFor="password">Password</label>
              <input id="password" className="login-input" type="password"
                     autoComplete="current-password" value={password}
                     onChange={(e) => setPassword(e.target.value)} />

              {notice && <p className="login-notice">{notice}</p>}
              {error && <p className="login-error" role="alert">{error}</p>}
              <button className="login-btn" type="submit" disabled={busy}>
                {busy ? 'Signing in…' : 'Sign in'}
              </button>
              <button className="login-link" type="button" onClick={() => toMode('change')}>
                Change password
              </button>
            </form>
          )}

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
