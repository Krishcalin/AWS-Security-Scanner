import { useState } from 'react'
import { Search, Sparkles, Sun, Moon, ChevronDown, Building2, Check } from 'lucide-react'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { applyTheme, isDark } from '../lib/theme'
import { healthTone, acctLabel } from '../lib/format'
import type { Account } from '../api/types'

function ScopeSwitcher() {
  const { scope, setScope } = useScope()
  const { data: accounts } = useFetch(() => api.listAccounts(), [])
  const [open, setOpen] = useState(false)
  const list: Account[] = accounts ?? []
  const current = scope === 'org' ? null : list.find((a) => a.account_id === scope)
  const label = scope === 'org' ? 'Organization' : acctLabel(current?.alias, scope)

  const pick = (s: string) => { setScope(s); setOpen(false) }

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3 py-1.5 text-sm font-semibold text-ink hover:border-accent/40 transition-colors"
      >
        <Building2 size={15} className="text-ink3" />
        <span>{label}</span>
        {scope !== 'org' && <span className="font-mono text-xs text-ink3">{scope}</span>}
        <ChevronDown size={14} className="text-ink3" />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div className="absolute left-0 top-full mt-1.5 z-30 w-72 rounded-xl border border-line bg-panel shadow-lg p-1.5">
            <button
              onClick={() => pick('org')}
              className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm hover:bg-panel2 text-left"
            >
              <Building2 size={15} className="text-ink3" />
              <span className="font-semibold text-ink flex-1">Organization</span>
              <span className="text-xs text-ink3">{list.length} accounts</span>
              {scope === 'org' && <Check size={15} className="text-accent" />}
            </button>
            <div className="my-1 border-t border-line2" />
            {list.map((a) => {
              const tone = healthTone(a.health)
              return (
                <button
                  key={a.account_id}
                  onClick={() => pick(a.account_id)}
                  className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm hover:bg-panel2 text-left"
                >
                  <span className="h-2 w-2 rounded-full shrink-0" style={{ background: tone.fg }} />
                  <span className="flex-1 min-w-0">
                    <span className="font-semibold text-ink block truncate">{acctLabel(a.alias, a.account_id)}</span>
                    <span className="font-mono text-[11px] text-ink3">{a.account_id}</span>
                  </span>
                  {scope === a.account_id && <Check size={15} className="text-accent" />}
                </button>
              )
            })}
          </div>
        </>
      )}
    </div>
  )
}

export function TopBar() {
  const [dark, setDark] = useState(isDark())
  const toggleTheme = () => { const d = !dark; applyTheme(d); setDark(d) }

  return (
    <header className="h-14 shrink-0 border-b border-line bg-panel/85 backdrop-blur flex items-center gap-3 px-5 sticky top-0 z-10">
      <ScopeSwitcher />

      <div className="flex-1 max-w-md relative hidden md:block">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-ink3" />
        <input
          type="text"
          placeholder="Search accounts, ARNs, check IDs…"
          className="w-full rounded-lg border border-line bg-panel2 pl-9 pr-3 py-1.5 text-sm text-ink placeholder:text-ink3 outline-none focus:border-accent/50"
        />
      </div>

      <div className="flex-1 md:hidden" />

      <button
        onClick={toggleTheme}
        title="Toggle theme"
        className="h-9 w-9 grid place-items-center rounded-lg border border-line bg-panel2 text-ink2 hover:text-ink transition-colors"
      >
        {dark ? <Sun size={16} /> : <Moon size={16} />}
      </button>

      <button className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-semibold text-white ow-grad shadow-sm hover:opacity-90 transition-opacity">
        <Sparkles size={15} />
        <span className="hidden sm:inline">Ask OverWatch</span>
      </button>
    </header>
  )
}
