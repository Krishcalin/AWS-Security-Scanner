import { createContext, useContext, useCallback, type ReactNode } from 'react'
import { useSearchParams } from 'react-router'
import { PANEL_PARAMS } from '../lib/deeplink'

// The account/region scope the whole console is viewed through: the org aggregate
// or a single onboarded account. Scope lives in the URL (`?scope=<account>`; absent
// ⇒ 'org') so a view is fully shareable — a pasted link carries both the scope AND
// any open panel, and the product tour drives everything by navigating to one URL.
type ScopeValue = { scope: string; setScope: (s: string) => void }

const ScopeCtx = createContext<ScopeValue>({ scope: 'org', setScope: () => {} })

export function ScopeProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams()
  const scope = params.get('scope') || 'org'

  const setScope = useCallback(
    (s: string) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev)
          if (!s || s === 'org') p.delete('scope')
          else p.set('scope', s)
          // switching scope invalidates any open panel — its id belongs to the old
          // account, so drop every panel param rather than resolve it to nothing.
          for (const k of PANEL_PARAMS) p.delete(k)
          return p
        },
        { replace: false },
      )
    },
    [setParams],
  )

  return <ScopeCtx.Provider value={{ scope, setScope }}>{children}</ScopeCtx.Provider>
}

export const useScope = () => useContext(ScopeCtx)
export const isOrgScope = (s: string) => s === 'org'
