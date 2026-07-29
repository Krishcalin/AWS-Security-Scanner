import {
  LayoutDashboard, Waypoints, CircleAlert, ShieldAlert, Boxes, KeyRound,
  ShieldCheck, Wrench, FileText, Cloud, Settings2, PackageCheck,
  Globe, Database, Container, BrainCircuit, UserRoundMinus, FolderKanban, Terminal, Radar,
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
  { to: '/projects', label: 'Projects', icon: FolderKanban },
  { to: '/findings', label: 'Findings', icon: CircleAlert },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
  { to: '/runtime', label: 'Runtime', icon: Radar },
  { to: '/supply-chain', label: 'Supply Chain', icon: PackageCheck },
  { to: '/inventory', label: 'Inventory', icon: Boxes },
  { to: '/query', label: 'Query', icon: Terminal },
  { to: '/identity', label: 'Identity', icon: KeyRound },
  { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
  { to: '/remediation', label: 'Remediation', icon: Wrench },
  { to: '/reports', label: 'Reports', icon: FileText },
]

export const NAV_ADMIN: NavItem[] = [
  { to: '/accounts', label: 'Cloud Accounts', icon: Cloud },
  { to: '/settings', label: 'Settings', icon: Settings2 },
]

// Risk Dashboards — named roll-ups over the finding catalog (see lib/dashboards.ts).
export const NAV_DASHBOARDS: NavItem[] = [
  { to: '/exposure', label: 'External Exposure', icon: Globe },
  { to: '/data-security', label: 'Data Security', icon: Database },
  { to: '/containers', label: 'Containers', icon: Container },
  { to: '/ai-security', label: 'AI Security', icon: BrainCircuit },
  { to: '/secrets', label: 'Secrets', icon: KeyRound },
  { to: '/excessive-access', label: 'Excessive Access', icon: UserRoundMinus },
]
