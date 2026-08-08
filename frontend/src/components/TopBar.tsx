import { useEffect, useState } from 'react'
import { Search, Sparkles, Sun, Moon, ChevronDown, Building2, Check, Compass,
         LogOut, ShieldUser } from 'lucide-react'
import { Link } from 'react-router'
import { useScope } from '../state/scope'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { applyTheme, isDark } from '../lib/theme'
import { healthTone, acctLabel } from '../lib/format'
import { useTour } from '../lib/tour/TourProvider'
import { useDeepLinkPanel } from '../lib/deeplink'
import { me, logout, type Me } from '../api/auth'
import { DATA_MODE } from '../api/client'
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
        data-tour="scope-switcher"
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


/**
 * Who is signed in, and the way out.
 *
 * Renders NOTHING in sample mode. The offline demo reads static fixtures and has no
 * session at all, so a user chip there would name a person who does not exist and a
 * Log out button would do nothing — both of which teach the wrong thing about how
 * the product works.
 */
function UserMenu() {
  const [user, setUser] = useState<Me | null>(null)
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  // `tick` re-runs the identity fetch. TopBar mounts ONCE inside AppShell and never
  // remounts on client-side navigation, so with `[]` deps a single transient failure
  // — one 502 from a proxy restarting — left `user` null forever and removed the only
  // Log out control for the life of the tab, on a console that was otherwise working
  // perfectly. Opening the menu retries, which also refreshes a stale privilege
  // label rather than asserting one taken at page load.
  const [tick, setTick] = useState(0)

  useEffect(() => {
    if (DATA_MODE !== 'live') return
    let cancelled = false
    me().then((u) => { if (!cancelled && u) setUser(u) })
        .catch(() => { /* AuthGate owns the redirect; keep the last good identity */ })
    return () => { cancelled = true }
  }, [tick])

  if (DATA_MODE !== 'live' || !user) return null

  async function signOut() {
    setBusy(true)
    setError('')
    try {
      await logout()
    } catch {
      // DO NOT REDIRECT. logout() throws only when the sign-out genuinely did not
      // happen — a non-2xx or the 5s timeout — which means the session and its
      // cookie are still live on the server. Showing a login form at that point
      // tells the user they signed out when they did not, and one Back press puts
      // them straight back into an authenticated console. Saying so is the only
      // honest option; the alternative is a lie the UI cannot detect afterwards.
      setBusy(false)
      setError('Sign-out failed — you are still signed in. Try again.')
      return
    }
    // replace(), not assign(): a signed-out console should not be one Back press
    // away. A full document load also guarantees no authenticated state survives in
    // memory.
    window.location.replace('/login')
  }

  const label = user.display_name || user.username

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        // Named explicitly because the visible name is hidden below `lg`, which
        // leaves the avatar's single initial as the button's ENTIRE accessible name
        // — "K, button". `title` does not rescue that: it is only a fallback for a
        // control with no text content at all, and the initial counts as content.
        // ScopeSwitcher gets its name for free from a label that is always visible.
        aria-label={`Account menu — signed in as ${user.username}`}
        title={`Signed in as ${user.username}`}
        className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-2.5 py-1.5 text-sm font-semibold text-ink hover:border-accent/40 transition-colors"
      >
        <span className="grid h-6 w-6 place-items-center rounded-full ow-grad text-[11px] font-bold text-white">
          {label.slice(0, 1).toUpperCase()}
        </span>
        <span className="hidden lg:inline max-w-[10rem] truncate">{label}</span>
        <ChevronDown size={14} className="text-ink3" />
      </button>

      {open && (
        <>
          <div className="fixed inset-0 z-20" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-full mt-1.5 z-30 w-60 rounded-xl border border-line bg-panel shadow-lg p-1.5">
            <div className="px-2.5 py-2">
              <p className="text-sm font-semibold text-ink truncate">{label}</p>
              <p className="text-xs text-ink3 truncate">{user.username}</p>
              {user.is_superadmin && (
                <p className="mt-1 text-[11px] font-semibold text-accent">Platform administrator</p>
              )}
            </div>
            <div className="my-1 border-t border-line2" />
            <Link
              to="/security"
              onClick={() => setOpen(false)}
              className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-ink hover:bg-panel2"
            >
              <ShieldUser size={15} className="text-ink3" />
              <span>My security</span>
            </Link>
            {error && (
              <p className="px-2.5 py-1.5 text-xs text-crit" role="alert">{error}</p>
            )}
            <button
              onClick={signOut}
              disabled={busy}
              className="flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-ink hover:bg-panel2 disabled:opacity-60"
            >
              <LogOut size={15} className="text-ink3" />
              <span>{busy ? 'Signing out…' : 'Log out'}</span>
            </button>
          </div>
        </>
      )}
    </div>
  )
}

export function TopBar() {
  const [dark, setDark] = useState(isDark())
  const toggleTheme = () => { const d = !dark; applyTheme(d); setDark(d) }
  const { openGallery } = useTour()
  const [, setCopilot] = useDeepLinkPanel('copilot')

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

      <button
        onClick={openGallery}
        title="Take a guided tour"
        className="flex items-center gap-2 rounded-lg border border-line bg-panel2 px-3 py-1.5 text-sm font-semibold text-ink2 hover:text-ink hover:border-accent/40 transition-colors"
      >
        <Compass size={15} />
        <span className="hidden lg:inline">Take a tour</span>
      </button>

      <button
        onClick={() => setCopilot('1')}
        title="Ask OverWatch — grounded copilot over your scan"
        className="flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-semibold text-white ow-grad shadow-sm hover:opacity-90 transition-opacity">
        <Sparkles size={15} />
        <span className="hidden sm:inline">Ask OverWatch</span>
      </button>

      <UserMenu />
    </header>
  )
}
