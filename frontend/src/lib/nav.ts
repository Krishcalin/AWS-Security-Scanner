import {
  LayoutDashboard, Waypoints, CircleAlert, Boxes, KeyRound,
  ShieldCheck, Wrench, FileText, Cloud, Settings2,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  hero?: boolean
}

// Ordered to LEAD with the differentiator (Attack Paths), per the UX blueprint.
export const NAV_MAIN: NavItem[] = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/attack-paths', label: 'Attack Paths', icon: Waypoints, hero: true },
  { to: '/findings', label: 'Findings', icon: CircleAlert },
  { to: '/inventory', label: 'Inventory', icon: Boxes },
  { to: '/identity', label: 'Identity', icon: KeyRound },
  { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
  { to: '/remediation', label: 'Remediation', icon: Wrench },
  { to: '/reports', label: 'Reports', icon: FileText },
]

export const NAV_ADMIN: NavItem[] = [
  { to: '/accounts', label: 'Cloud Accounts', icon: Cloud },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]
