import { createContext, useContext, useState, type ReactNode } from 'react'

// The account/region scope the whole console is viewed through: the org aggregate
// or a single onboarded account. 'org' is the default landing scope.
type ScopeValue = { scope: string; setScope: (s: string) => void }

const ScopeCtx = createContext<ScopeValue>({ scope: 'org', setScope: () => {} })

export function ScopeProvider({ children }: { children: ReactNode }) {
  const [scope, setScope] = useState<string>('org')
  return <ScopeCtx.Provider value={{ scope, setScope }}>{children}</ScopeCtx.Provider>
}

export const useScope = () => useContext(ScopeCtx)
export const isOrgScope = (s: string) => s === 'org'
