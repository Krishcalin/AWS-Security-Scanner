import { useLocation, Link } from 'react-router-dom'
import { Hammer } from 'lucide-react'
import { NAV_MAIN, NAV_ADMIN } from '../lib/nav'

const HINTS: Record<string, string> = {
  '/attack-paths': 'ranked attack paths + choke points already come from aws_correlate',
  '/findings': 'the deduped, enriched finding_catalog is already produced every scan',
  '/inventory': 'the ARN-keyed asset graph is already built',
  '/identity': 'the effective-permissions CIEM graph + privesc rules already run',
  '/compliance': 'the per-framework compliance_scorecard is already computed',
  '/remediation': 'the prioritized fix plan + remediation-as-code already generate',
  '/reports': 'JSON / HTML / SARIF / ASFF exports already exist in the engine',
  '/accounts': 'the onboarding wizard + registry/health backend is already built',
  '/settings': 'integrations, waivers, and RBAC live here',
}

export function Placeholder() {
  const { pathname } = useLocation()
  const item = [...NAV_MAIN, ...NAV_ADMIN].find((i) => i.to === pathname)
  const Icon = item?.icon ?? Hammer
  const hint = HINTS[pathname]
  return (
    <div className="p-6 md:p-8 max-w-[1440px] mx-auto">
      <h1 className="text-2xl font-extrabold tracking-tight text-ink">{item?.label ?? 'Screen'}</h1>
      <p className="text-ink2 text-sm mt-1">Part of the Phase 1 console build.</p>
      <div className="mt-6 rounded-2xl border border-dashed border-line bg-panel p-16 flex flex-col items-center gap-3 text-center">
        <div className="h-14 w-14 rounded-2xl grid place-items-center ow-grad text-white"><Icon size={26} /></div>
        <div className="text-ink font-bold text-lg">Next up in the build</div>
        <div className="text-ink2 text-sm max-w-md">
          {hint ? <>The engine already does the work — {hint}. The screen renders it next.</>
            : 'This screen is part of the phased console rollout.'}
        </div>
        <Link to="/" className="mt-2 text-sm font-semibold text-accent hover:underline">← Back to Overview</Link>
      </div>
    </div>
  )
}
