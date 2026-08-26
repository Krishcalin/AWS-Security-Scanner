import {
  ScanSearch,
  LayoutDashboard, Waypoints, CircleAlert, ShieldAlert, Boxes, KeyRound,
  ShieldCheck, Wrench, FileText, Cloud, Settings2, PackageCheck,
  Globe, Database, Container, BrainCircuit, UserRoundMinus, FolderKanban, Terminal, Radar,
  Server, ShieldUser, LayoutGrid,
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
  { to: '/data', label: 'Data Security', icon: Database },
  { to: '/supply-chain', label: 'Supply Chain', icon: PackageCheck },
  { to: '/registries', label: 'Registries', icon: Server },
  { to: '/inventory', label: 'Inventory', icon: Boxes },
  { to: '/query', label: 'Query', icon: Terminal },
  { to: '/identity', label: 'Identity', icon: KeyRound },
  { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
  { to: '/remediation', label: 'Remediation', icon: Wrench },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/coverage', label: 'Coverage', icon: ScanSearch },
]

export const NAV_ADMIN: NavItem[] = [
  { to: '/accounts', label: 'Cloud Accounts', icon: Cloud },
  { to: '/settings', label: 'Settings', icon: Settings2 },
  // Beside My Security because both answer "who may do what here" — one about
  // everybody's access, one about your own.
  { to: '/roles', label: 'Roles & Access', icon: ShieldCheck },
  // Your own account's second factor. A route with no nav entry is a route nobody
  // finds: /security shipped reachable only by typing the URL, so two-factor could
  // never be enrolled — which made it look like the whole feature was unwired.
  { to: '/security', label: 'My Security', icon: ShieldUser },
]

// Risk Dashboards — named roll-ups over the finding catalog (see lib/dashboards.ts).
export const NAV_DASHBOARDS: NavItem[] = [
  // First, because it is the way IN to the other five: the worst ten in every
  // domain on one screen, each card linking to the full-page roll-up below it.
  { to: '/top-risks', label: 'Top Risks', icon: LayoutGrid },
  { to: '/exposure', label: 'External Exposure', icon: Globe },
  { to: '/data-security', label: 'Data Findings', icon: Database },
  { to: '/containers', label: 'Containers', icon: Container },
  { to: '/ai-security', label: 'AI Security', icon: BrainCircuit },
  { to: '/secrets', label: 'Secrets', icon: KeyRound },
  { to: '/excessive-access', label: 'Excessive Access', icon: UserRoundMinus },
]
