/**
 * toprisks — the Top-10-per-category roll-up.
 *
 * THE HONESTY PROBLEM THIS FILE SOLVES
 * -------------------------------------
 * The dashboard this is modelled on puts a single 0–10 "risk level" on every row.
 * OverWatch does not compute one. `FindingCatalogEntry` carries a severity band, an
 * affected-resource count, and nothing numeric. Rendering `9.8` next to a finding
 * would mean inventing a precision the scanner never produced — the exact failure the
 * rest of this codebase is built to refuse.
 *
 * So a row shows a number only when a real one exists, and says which kind it is:
 *
 *   PATH   the 0–100 score of the attack path this finding drives. Computed by
 *          aws_correlate from exposure × exploitability × privilege/impact × reach,
 *          and the only whole-risk number the product has.
 *   CVSS   the base score of a CVE, as published. Ingested, not derived.
 *   —      no number. The row shows its severity band, which is what we know.
 *
 * Ordering follows the same rule, and the UI states it, so a reader can see why one
 * row outranks another instead of trusting an opaque scalar.
 */
import {
  Bug, KeyRound, Database, Globe, BrainCircuit, Boxes, FileKey, ScrollText,
  Waypoints, Server, type LucideIcon,
} from 'lucide-react'
import type { AttackPath, FindingCatalogEntry, IngestedVuln } from '../api/types'

export interface RiskCategory {
  slug: string
  title: string
  icon: LucideIcon
  /** check_id prefixes, dash included so "SEC-" never swallows "SEG-". */
  prefixes: string[]
  /** Existing full-page dashboard to hand off to, when one covers this category. */
  seeAll?: string
}

/**
 * Ten categories covering EVERY check family the product ships. Two ratchets hold
 * that: `test_toprisks_categorises_every_check_family` (Python, reads this file)
 * fails when a new family is added and left uncategorised, and the test here fails
 * on a prefix shaped so it can never match. Both exist for the same reason — a
 * finding on no card, or a card that can never fill, reads as an estate with less
 * wrong with it than it has.
 */
export const RISK_CATEGORIES: RiskCategory[] = [
  {
    slug: 'vulnerabilities', title: 'Vulnerabilities', icon: Bug,
    prefixes: ['VULN-', 'WINVULN-', 'CWPP-', 'IMI-', 'ECRPUB-'],
    seeAll: '/vulnerabilities',
  },
  {
    slug: 'attack-paths', title: 'Attack Paths', icon: Waypoints,
    prefixes: ['ATTACK-', 'CHOKEPOINT-', 'AIPATH-', 'TFLOW-'],
    seeAll: '/attack-paths',
  },
  {
    slug: 'identity', title: 'Identity & Access', icon: KeyRound,
    // NHI- is here rather than in its own card: a non-human identity is an identity,
    // and splitting the pillar out would let a reader review "identity" and miss the
    // machine half -- which is the half that outnumbers the other and goes unrotated.
    prefixes: ['IAM-', 'IAMPE-', 'IDENTITY-', 'CIEM-', 'SSO-', 'COG-', 'DIRSVC-',
      'MPA-', 'VP-', 'NHI-'],
    seeAll: '/identity',
  },
  {
    slug: 'data', title: 'Data Security', icon: Database,
    prefixes: ['DSPM-', 'DATA-', 'EXTACCESS-', 'S3-', 'S3T-', 'RDS-', 'DDB-', 'AUR-',
      'DOCDB-', 'NEP-', 'DSQL-', 'EFS-', 'RS-', 'RSS-', 'OSR-', 'EBS-', 'GLC-', 'BCK-',
      'SGW-', 'LF-', 'EMR-', 'QS-', 'AMP-'],
    seeAll: '/data-security',
  },
  {
    slug: 'exposure', title: 'External Exposure', icon: Globe,
    prefixes: ['EXPOSURE-', 'SEG-', 'SEGREC-', 'VPC-', 'ELB-', 'CLB-', 'APIGW-',
      'AGW2-', 'WAF-', 'NFW-', 'FMS-', 'FLOW-', 'PERIM-', 'CFN-', 'R53-', 'LATT-',
      'XFER-', 'NWM-', 'LSAIL-'],
    seeAll: '/exposure',
  },
  {
    slug: 'ai-security', title: 'AI Security', icon: BrainCircuit,
    prefixes: ['SM-', 'BDR-', 'AGT-', 'AISPM-', 'AGC-', 'AGY-', 'MCP-', 'VEC-',
      'AIGRD-', 'AITHR-', 'AILOG-', 'MART-', 'AMEM-', 'TPOIS-', 'SHAI-', 'AIDR-'],
    seeAll: '/ai-security',
  },
  {
    slug: 'containers', title: 'Containers & Kubernetes', icon: Boxes,
    prefixes: ['EKS-', 'ECS-', 'CNT-', 'KSPM-', 'KIEM-', 'FARGATE-'],
    seeAll: '/containers',
  },
  {
    slug: 'secrets', title: 'Secrets & Encryption', icon: FileKey,
    // FW- (IoT FleetWise), SW- (IoT SiteWise) and AMP- are here for the same reason:
    // each check is "default service encryption rather than a customer-managed key".
    // NITRO- is in-transit encryption between instances. GLUE-01 is the Data Catalog
    // returning connection passwords in cleartext.
    prefixes: ['SEC-', 'SECRET-', 'KMS-', 'ENC-', 'HSM-', 'PCA-', 'ACM-', 'PAY-',
      'NITRO-', 'FW-', 'SW-', 'GLUE-'],
    seeAll: '/secrets',
  },
  {
    slug: 'logging', title: 'Logging & Detection', icon: ScrollText,
    // No 'CDR-': aws_epistemics records that the prefix was deliberately never
    // invented. Cloud detections arrive as NormalizedDetection objects with a
    // source and type and no check id at all, so a CDR- card would be a category
    // describing nothing. They live on the Runtime screen instead.
    prefixes: ['CW-', 'LOG-', 'THREAT-', 'XRAY-', 'PENT-', 'MBC-', 'WKR-'],
    seeAll: '/findings',
  },
  {
    slug: 'workload', title: 'Workload & Service Posture', icon: Server,
    // The remainder: compute, serverless, messaging, developer tooling and the
    // long tail of managed services. A category exists for these because the
    // alternative is 27% of the catalog appearing on no card at all, which reads
    // as an estate with less wrong with it than it has.
    // APRUN- (App Runner), BATCH- and EB- (Elastic Beanstalk) arrived with the CIS
    // Compute Services Benchmark. All three are managed compute, so they belong here
    // rather than under Containers: none of them is a cluster the operator runs.
    prefixes: ['EC2-', 'AMI-', 'ASG-', 'LT-', 'SSM-', 'LMB-', 'SFN-', 'SQS-', 'SNS-',
      'ELC-', 'MM-', 'IOT-', 'MPV-', 'WM-', 'WSW-', 'CART-', 'CB-', 'CGP-', 'GRF-',
      'STACK-', 'IMGB-', 'APRUN-', 'BATCH-', 'EB-'],
    seeAll: '/findings',
  },
]

export const SEV_RANK = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export type ScoreBasis = 'path' | 'cvss' | null

export interface TopRiskRow {
  key: string
  check_id: string
  section: string
  severity: string
  status: string
  account?: string
  /** First affected resource, or '' when the check is account-scoped. */
  asset: string
  assetCount: number
  /** A real number, or null. NEVER derived from the severity band. */
  score: number | null
  basis: ScoreBasis
}

/** check_id → best attack-path score driving it. Prefix before ':' — VULN-02:CVE-x. */
export function pathScores(paths: AttackPath[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const p of paths ?? []) {
    for (const d of p.driving_findings ?? []) {
      const id = d.split(':')[0]
      const prev = m.get(id)
      if (prev === undefined || p.score > prev) m.set(id, p.score)
    }
  }
  return m
}

/** Highest published CVSS per affected node, for findings that name a node. */
export function cvssByNode(vulns: IngestedVuln[]): Map<string, number> {
  const m = new Map<string, number>()
  for (const v of vulns ?? []) {
    if (v.cvss_base === null || v.cvss_base === undefined) continue
    const prev = m.get(v.node_id)
    if (prev === undefined || v.cvss_base > prev) m.set(v.node_id, v.cvss_base)
  }
  return m
}

export function categoryOf(check_id: string, cat: RiskCategory): boolean {
  const c = (check_id || '').toUpperCase()
  return cat.prefixes.some((p) => c.startsWith(p))
}

/**
 * Rank rows within one category.
 *
 * A path score is a whole-risk number and outranks a CVSS, which describes a
 * component in isolation and says nothing about whether anything can reach it —
 * ranking by CVSS alone is the behaviour this product exists to replace. Rows with
 * no number fall back to severity, then to how many resources they touch.
 */
export function rankRows(rows: TopRiskRow[]): TopRiskRow[] {
  return [...rows].sort((a, b) => {
    const ba = a.basis === 'path' ? 2 : a.basis === 'cvss' ? 1 : 0
    const bb = b.basis === 'path' ? 2 : b.basis === 'cvss' ? 1 : 0
    if (ba !== bb) return bb - ba
    if (a.score !== null && b.score !== null && a.score !== b.score) return b.score - a.score
    const sa = SEV_RANK.indexOf(a.severity), sb = SEV_RANK.indexOf(b.severity)
    if (sa !== sb) return (sa < 0 ? 99 : sa) - (sb < 0 ? 99 : sb)
    if (a.assetCount !== b.assetCount) return b.assetCount - a.assetCount
    return a.check_id.localeCompare(b.check_id)
  })
}

export interface CategoryResult {
  cat: RiskCategory
  rows: TopRiskRow[]
  total: number
}

export function topRisks(
  catalog: FindingCatalogEntry[],
  paths: AttackPath[],
  vulns: IngestedVuln[],
  limit = 10,
): CategoryResult[] {
  const byPath = pathScores(paths)
  const byCvss = cvssByNode(vulns)

  return RISK_CATEGORIES.map((cat) => {
    const rows: TopRiskRow[] = []
    for (const e of catalog ?? []) {
      if (!categoryOf(e.check_id, cat)) continue
      const affected = e.affected ?? []
      const p = byPath.get(e.check_id)
      // A CVSS only applies when the finding names a node the ingest scored. It is
      // per-node, so take the worst node this finding touches.
      let cv: number | undefined
      for (const a of affected) {
        const c = byCvss.get(a)
        if (c !== undefined && (cv === undefined || c > cv)) cv = c
      }
      const score = p ?? cv ?? null
      rows.push({
        key: `${e.account ?? ''}::${e.check_id}`,
        check_id: e.check_id,
        section: e.section,
        severity: e.severity,
        status: e.status,
        account: e.account,
        asset: affected[0] ?? '',
        assetCount: e.distinct || affected.length,
        score,
        basis: p !== undefined ? 'path' : cv !== undefined ? 'cvss' : null,
      })
    }
    const ranked = rankRows(rows)
    return { cat, rows: ranked.slice(0, limit), total: ranked.length }
  })
}
