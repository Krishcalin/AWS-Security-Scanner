import { useEffect, useState } from 'react'
import { Navigate, useLocation } from 'react-router'
import { me, type Me } from '../api/auth'
import { DATA_MODE } from '../api/client'

/**
 * Wraps the console: unauthenticated visitors get the sign-in page.
 *
 * WHY THIS EXISTS AT ALL, GIVEN THE SERVER ALREADY REFUSES. The API is the security
 * boundary — every route resolves a Principal and an unauthenticated one is deny-all.
 * This gate is purely so the user sees a login form instead of a console rendering
 * a screenful of failed requests. Nothing here is a control; deleting it would leak
 * no data, only dignity.
 *
 * SAMPLE MODE IS EXEMPT. In sample mode the console reads static fixtures and never
 * calls the API, so there is nothing to authenticate against — gating it would bounce
 * an offline demo to a login page that cannot possibly succeed.
 */
export default function AuthGate({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const [state, setState] = useState<'checking' | 'in' | 'out'>(
    DATA_MODE === 'live' ? 'checking' : 'in')

  useEffect(() => {
    if (DATA_MODE !== 'live') return
    let cancelled = false
    me()
      .then((u: Me | null) => { if (!cancelled) setState(u ? 'in' : 'out') })
      // A network or 500 error is NOT an authenticated state. Failing to 'out' sends
      // the user somewhere honest rather than into a console whose every panel is
      // about to error.
      .catch(() => { if (!cancelled) setState('out') })
    return () => { cancelled = true }
  }, [location.pathname])

  if (state === 'checking') {
    // Deliberately blank rather than a spinner: the check is a single local request
    // and a flash of chrome that then disappears reads worse than a beat of nothing.
    return <div className="auth-checking" aria-busy="true" />
  }
  if (state === 'out') return <Navigate to="/login" replace />
  return <>{children}</>
}
