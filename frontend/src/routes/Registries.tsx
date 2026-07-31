import { useState } from 'react'
import {
  Server, ShieldCheck, ShieldQuestion, PlayCircle, Loader2, PackageCheck, GitBranch,
} from 'lucide-react'
import { useFetch } from '../lib/useFetch'
import { api } from '../api/client'
import { Card, Loader, ErrorNote, Empty, Chip } from '../components/ui'
import type { RegistryConnectorRow, OciImageRow } from '../api/types'

// registry-type → tone (a provenance accent, distinct from the severity palette)
const TYPE_TONE: Record<string, { fg: string; bg: string; label: string }> = {
  ghcr: { fg: 'var(--ink)', bg: 'var(--panel2)', label: 'GitHub GHCR' },
  dockerhub: { fg: 'var(--accent)', bg: 'var(--accentdim)', label: 'Docker Hub' },
  harbor: { fg: 'var(--low)', bg: 'var(--lowbg)', label: 'Harbor' },
  acr: { fg: 'var(--accent)', bg: 'var(--accentdim)', label: 'Azure ACR' },
  generic: { fg: 'var(--ink2)', bg: 'var(--panel2)', label: 'OCI Registry' },
}
const typeTone = (t: string) => TYPE_TONE[t] ?? TYPE_TONE.generic

function sevChips(im: { critical: number; high: number; vuln_count: number }) {
  return (
    <div className="flex items-center gap-1.5">
      {im.critical > 0 && <Chip fg="var(--crit)" bg="var(--critbg)">{im.critical} crit</Chip>}
      {im.high > 0 && <Chip fg="var(--high)" bg="var(--highbg)">{im.high} high</Chip>}
      {im.vuln_count === 0 ? (
        <Chip fg="var(--low)" bg="var(--lowbg)">clean</Chip>
      ) : (
        <span className="text-xs text-ink3 font-mono tabular-nums">{im.vuln_count} CVE</span>
      )}
    </div>
  )
}

function ImageRow({ im }: { im: OciImageRow }) {
  return (
    <div className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-panel2 transition-colors text-sm">
      <PackageCheck size={14} className="text-ink3 shrink-0" />
      <span className="font-semibold text-ink truncate max-w-[220px]">{im.repository}</span>
      <span className="font-mono text-[11px] text-ink3">{(im.tags[0] || im.digest.slice(0, 19))}</span>
      {!im.ok && <Chip fg="var(--med)" bg="var(--medbg)">not scanned</Chip>}
      {im.ok && <span className="text-xs text-ink3">{im.components} pkgs</span>}
      <span className="ml-auto flex items-center gap-2">
        {im.scan_sources.map((s) => (
          <Chip key={s} fg="var(--ink2)" bg="var(--panel2)" mono>{s}</Chip>
        ))}
        {sevChips(im)}
      </span>
    </div>
  )
}

function ConnectorCard({ c }: { c: RegistryConnectorRow }) {
  const [imgs, setImgs] = useState<OciImageRow[] | null>(null)
  const [scanning, setScanning] = useState(false)
  const [note, setNote] = useState<string | null>(null)
  const tone = typeTone(c.type)

  async function scan() {
    setScanning(true)
    setNote(null)
    try {
      const r = await api.scanRegistry(c.connector_id)
      setImgs(r.images)
      if (r.images.length === 0) setNote(r.notes[0] || 'No images returned — check the connector config.')
    } catch (e) {
      setNote(String((e as Error)?.message ?? e))
    } finally {
      setScanning(false)
    }
  }

  const ls = c.last_scan
  return (
    <Card className="p-5">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-xl p-2" style={{ background: tone.bg }}>
          <Server size={18} style={{ color: tone.fg }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-bold text-ink truncate">{c.name}</h3>
            <Chip fg={tone.fg} bg={tone.bg}>{tone.label}</Chip>
            {!c.enabled && <Chip fg="var(--ink3)" bg="var(--panel2)">disabled</Chip>}
          </div>
          <p className="font-mono text-[11px] text-ink3 mt-0.5 truncate">{c.host}</p>
        </div>
        <button
          onClick={scan}
          disabled={!c.enabled || scanning}
          className="shrink-0 flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-sm font-semibold transition-colors disabled:opacity-40"
          style={{ background: 'var(--accentdim)', color: 'var(--accent)' }}
        >
          {scanning ? <Loader2 size={14} className="animate-spin" /> : <PlayCircle size={14} />}
          {scanning ? 'Scanning…' : 'Scan now'}
        </button>
      </div>

      <div className="flex items-center gap-2 flex-wrap mt-3 text-xs">
        {c.secret_configured ? (
          <span className="flex items-center gap-1 text-ink2"><ShieldCheck size={13} className="text-low" /> {c.auth} · credential set</span>
        ) : (
          <span className="flex items-center gap-1 text-ink2"><ShieldQuestion size={13} className="text-ink3" /> anonymous</span>
        )}
        {c.images.length > 0 && (
          <span className="flex items-center gap-1 text-ink3"><PackageCheck size={12} /> {c.images.length} image{c.images.length > 1 ? 's' : ''}</span>
        )}
        {c.repositories.length > 0 && (
          <span className="flex items-center gap-1 text-ink3"><GitBranch size={12} /> {c.repositories.length} repo{c.repositories.length > 1 ? 's' : ''} · newest {c.newest_n}</span>
        )}
        {ls && (
          <span className="ml-auto text-ink3 tabular-nums">
            last scan · {ls.ok}/{ls.images} ok
            {ls.critical > 0 && <span className="text-crit"> · {ls.critical} crit</span>}
            {ls.high > 0 && <span className="text-high"> · {ls.high} high</span>}
          </span>
        )}
      </div>

      {note && <p className="mt-3 text-xs text-ink3 bg-panel2 rounded-lg px-3 py-2">{note}</p>}

      {imgs && imgs.length > 0 && (
        <div className="mt-3 border-t border-line pt-2 flex flex-col gap-0.5">
          {imgs.map((im) => <ImageRow key={im.node_id} im={im} />)}
        </div>
      )}
    </Card>
  )
}

export function Registries() {
  const { data, loading, error } = useFetch(() => api.registryConnectors(), [])
  return (
    <div className="p-6 md:p-8 max-w-[1200px] mx-auto">
      <div className="mb-5">
        <h1 className="text-2xl font-extrabold tracking-tight text-ink flex items-center gap-2">
          <Server size={22} className="text-accent" /> Registries
        </h1>
        <p className="text-ink2 text-sm mt-1">
          Agentless vulnerability side-scan of your non-AWS container registries — GitHub GHCR,
          Docker Hub, Harbor, Azure ACR — reusing the same SBOM + OSV engine as ECR. Read-only:
          images are pulled and inspected, never modified.
        </p>
      </div>
      {loading && <Loader label="Loading registry connectors…" />}
      {error && <ErrorNote msg={error} />}
      {data && data.length === 0 && (
        <Empty icon={<Server size={22} />}>
          No registry connectors configured. Set <span className="font-mono text-ink2">CNAPP_REGISTRIES</span> on
          the hub to declare a GHCR / Docker Hub / Harbor / ACR registry to scan.
        </Empty>
      )}
      {data && data.length > 0 && (
        <div className="grid grid-cols-1 gap-4">
          {data.map((c) => <ConnectorCard key={c.connector_id} c={c} />)}
        </div>
      )}
    </div>
  )
}
