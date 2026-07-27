// Risk Dashboards — named, deep-linkable roll-up screens over the SAME finding_catalog the
// Findings screen already serves (api.findings / api.orgFindings). Pure surfacing: no new
// backend, no new scanning. Each dashboard selects findings by check_id PREFIX (primary,
// robust because _add sets section independently) with section as a secondary include.
import {
  Globe, Database, Boxes, BrainCircuit, KeyRound, UserRoundMinus, type LucideIcon,
} from 'lucide-react'

export interface DashboardSpec {
  slug: string
  title: string
  icon: LucideIcon
  blurb: string
  prefixes: string[]  // check_id prefixes (include the dash so "SEC-" ≠ "SEG-")
  sections?: string[] // optional secondary include, by uppercase section
}

export const DASHBOARDS: DashboardSpec[] = [
  {
    slug: 'exposure', title: 'External Exposure', icon: Globe,
    blurb: 'Internet-reachable resources and true exposure paths — 4-gate reachability-verified, never "0.0.0.0/0 SG alone".',
    prefixes: ['EXPOSURE-', 'SEG-', 'FARGATE-'], sections: ['EXPOSURE'],
  },
  {
    slug: 'data-security', title: 'Data Security', icon: Database,
    blurb: 'Crown-jewel datastores, their exposure, and which identities can reach the data (DSPM).',
    prefixes: ['DSPM-', 'EXTACCESS-'], sections: ['DATA'],
  },
  {
    slug: 'containers', title: 'Containers', icon: Boxes,
    blurb: 'EKS / ECS / Fargate posture — RBAC, Pod Security, NetworkPolicy, IRSA, and task hardening.',
    prefixes: ['EKS-', 'ECS-', 'FARGATE-', 'KSPM-', 'KIEM-', 'CNT-'], sections: ['CONTAINERS', 'EKS', 'ECS'],
  },
  {
    slug: 'ai-security', title: 'AI Security', icon: BrainCircuit,
    blurb: 'Managed AWS AI (SageMaker / Bedrock) posture plus AI execution-role blast radius.',
    prefixes: ['SM-', 'BDR-', 'AGT-', 'AISPM-', 'AIPATH-'], sections: ['AI', 'SAGEMAKER', 'BEDROCK'],
  },
  {
    slug: 'secrets', title: 'Secure Use of Secrets', icon: KeyRound,
    blurb: 'AWS-resident secret posture — plaintext vs KMS, staleness, and over-permissive resource policies.',
    prefixes: ['SEC-'], sections: ['SECRETS'],
  },
  {
    slug: 'excessive-access', title: 'Excessive Access', icon: UserRoundMinus,
    blurb: 'Over-privileged identities — granted-but-unused access and least-privilege right-sizing.',
    prefixes: ['CIEM-'], sections: [],
  },
]

/** True iff a finding belongs on a dashboard: check_id prefix match, or section match. */
export function findingInDashboard(e: { check_id: string; section: string }, spec: DashboardSpec): boolean {
  const c = (e.check_id || '').toUpperCase()
  if (spec.prefixes.some((p) => c.startsWith(p))) return true
  const s = (e.section || '').toUpperCase()
  return !!spec.sections && spec.sections.includes(s)
}

export const dashboardBySlug = (slug: string): DashboardSpec | undefined =>
  DASHBOARDS.find((d) => d.slug === slug)
