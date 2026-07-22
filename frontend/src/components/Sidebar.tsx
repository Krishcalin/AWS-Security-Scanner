import { NavLink } from 'react-router-dom'
import { NAV_MAIN, NAV_ADMIN, type NavItem } from '../lib/nav'
import { DATA_MODE } from '../api/client'

function Row({ item }: { item: NavItem }) {
  const Icon = item.icon
  return (
    <NavLink
      to={item.to}
      end={item.to === '/'}
      className={({ isActive }) =>
        `relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors ${
          isActive ? 'bg-accentdim text-accent' : 'text-ink2 hover:bg-panel2 hover:text-ink'
        }`
      }
    >
      {({ isActive }) => (
        <>
          {isActive && <span className="absolute left-0 top-1.5 bottom-1.5 w-[3px] rounded-full ow-grad" />}
          <Icon size={17} strokeWidth={2} />
          <span>{item.label}</span>
          {item.hero && (
            <span className="ml-auto text-[9px] font-mono font-bold tracking-wide text-accent/70">HERO</span>
          )}
        </>
      )}
    </NavLink>
  )
}

export function Sidebar() {
  return (
    <aside className="w-60 shrink-0 border-r border-line bg-panel flex flex-col">
      <div className="h-14 flex items-center gap-2.5 px-5 border-b border-line">
        <div className="h-8 w-8 rounded-lg ow-grad grid place-items-center text-white text-lg shadow">🛡️</div>
        <div className="leading-tight">
          <div className="font-extrabold tracking-tight text-ink">OverWatch</div>
          <div className="text-[10px] text-ink3 font-mono -mt-0.5">AWS CNAPP</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-3 flex flex-col gap-0.5">
        {NAV_MAIN.map((i) => <Row key={i.to} item={i} />)}
        <div className="mt-4 mb-1 px-3 text-[10px] font-semibold uppercase tracking-wider text-ink3">Manage</div>
        {NAV_ADMIN.map((i) => <Row key={i.to} item={i} />)}
      </nav>

      <div className="p-3 border-t border-line flex items-center justify-between text-[11px] text-ink3 font-mono">
        <span>v2.19.0</span>
        <span className="rounded px-1.5 py-0.5" style={{ background: 'var(--panel2)' }}>
          {DATA_MODE === 'live' ? 'live' : 'sample'}
        </span>
      </div>
    </aside>
  )
}
