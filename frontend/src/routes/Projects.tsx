import { Link, useParams } from 'react-router'
import { FolderKanban, ArrowLeft, ArrowRight } from 'lucide-react'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty } from '../components/ui'
import { FindingRow } from './Findings'
import { TIER_META } from '../lib/projects'
import { sevColor } from '../lib/format'
import type { Project, ProjectDetail } from '../api/types'

const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

function TierBadge({ tier }: { tier: string }) {
  const m = TIER_META[tier]
  if (!m) return null
  return (
    <span className="rounded-md px-2 py-0.5 text-[11px] font-bold" title={m.label}
      style={{ color: m.color, background: `color-mix(in srgb, ${m.color} 14%, transparent)` }}>{tier}</span>
  )
}

function SevRollup({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="flex gap-1.5">
      {SEVS.map((s) => (
        <span key={s} className="rounded px-1.5 py-0.5 text-[11px] font-mono font-bold tabular-nums"
          style={{ color: counts[s] ? sevColor(s) : 'var(--ink3)', background: 'var(--panel2)' }}>
          {counts[s] ?? 0}
        </span>
      ))}
    </div>
  )
}

// ── list ────────────────────────────────────────────────────────────────────
export function Projects() {
  const { data, loading, error } = useFetch<Project[]>(() => api.listProjects(), [])
  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  const projects = data ?? []

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <FolderKanban size={22} className="text-accent" /> Projects
        </h1>
        <p className="text-ink2 text-sm mt-1 max-w-3xl">Business-impact groupings (HBI / MBI / LBI) that roll up your findings by owning team or application — configured on the hub, read-only.</p>
      </div>

      {projects.length === 0 ? (
        <Card><Empty icon={<FolderKanban size={26} />}>No projects configured. Define them on the hub via <span className="font-mono">CNAPP_PROJECTS</span> to group resources by business impact.</Empty></Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {projects.map((p) => (
            <Link key={p.id} to={`/projects/${encodeURIComponent(p.id)}`}
              className="rounded-2xl border border-line bg-panel p-5 hover:border-accent/50 hover:shadow-sm transition-all">
              <div className="flex items-center gap-2 mb-3">
                <span className="font-bold text-ink flex-1 truncate">{p.name}</span>
                <TierBadge tier={p.tier} />
              </div>
              <div className="flex items-center justify-between">
                <SevRollup counts={p.severity_counts} />
                <span className="text-xs text-ink3">{p.finding_count} finding{p.finding_count === 1 ? '' : 's'}</span>
              </div>
              <div className="flex items-center gap-1 text-accent text-xs font-semibold mt-3">Open <ArrowRight size={12} /></div>
            </Link>
          ))}
        </div>
      )}
    </div>
  )
}

// ── detail ──────────────────────────────────────────────────────────────────
export function ProjectView() {
  const { id = '' } = useParams()
  const { data, loading, error } = useFetch<ProjectDetail>(() => api.projectSummary(id), [id])
  if (loading) return <Loader />
  if (error) return <ErrorNote msg={error} />
  if (!data) return null

  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <Link to="/projects" className="inline-flex items-center gap-1.5 text-sm text-ink3 hover:text-ink mb-4"><ArrowLeft size={15} /> All projects</Link>
      <div className="mb-5 flex items-center gap-3">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <FolderKanban size={22} className="text-accent" /> {data.name}
        </h1>
        <TierBadge tier={data.tier} />
        <span className="text-sm text-ink3">{data.finding_count} finding{data.finding_count === 1 ? '' : 's'}</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        {SEVS.map((s) => (
          <Card key={s} className="p-4">
            <div className="text-3xl font-extrabold tabular-nums leading-none" style={{ color: data.severity_counts[s] ? sevColor(s) : 'var(--ink3)' }}>{data.severity_counts[s] ?? 0}</div>
            <div className="text-xs font-semibold uppercase tracking-wide mt-2 text-ink3">{s}</div>
          </Card>
        ))}
      </div>

      {data.findings.length === 0 ? (
        <Card><Empty icon={<FolderKanban size={26} />}>No findings match this project's resources.</Empty></Card>
      ) : (
        <div className="flex flex-col gap-2">
          {data.findings.map((e, i) => (
            <FindingRow key={`${e.account ?? ''}${e.check_id}${i}`} e={e} onPath={false} onOpen={() => { /* detail is read-only here */ }} />
          ))}
        </div>
      )}
    </div>
  )
}
