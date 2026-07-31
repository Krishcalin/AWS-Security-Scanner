import { BrowserRouter, Routes, Route } from 'react-router'
import { ScopeProvider } from './state/scope'
import { AppShell } from './components/AppShell'
import { Overview } from './routes/Overview'
import { AttackPaths } from './routes/AttackPaths'
import { Findings } from './routes/Findings'
import { Vulnerabilities } from './routes/Vulnerabilities'
import { SupplyChain } from './routes/SupplyChain'
import { CloudAccounts } from './routes/CloudAccounts'
import { Inventory } from './routes/Inventory'
import { Identity } from './routes/Identity'
import { Compliance } from './routes/Compliance'
import { Remediation } from './routes/Remediation'
import { Reports } from './routes/Reports'
import { Settings } from './routes/Settings'
import { Placeholder } from './routes/Placeholder'
import { CategoryDashboard } from './routes/CategoryDashboard'
import { Projects, ProjectView } from './routes/Projects'
import { Query } from './routes/Query'
import { Runtime } from './routes/Runtime'
import { Data } from './routes/Data'
import { Registries } from './routes/Registries'
import { DASHBOARDS } from './lib/dashboards'
import { TourProvider } from './lib/tour/TourProvider'
import { TourOverlay } from './components/tour/TourOverlay'
import { TourLauncher } from './components/tour/TourLauncher'
import { CopilotPanel } from './components/CopilotPanel'

export default function App() {
  // BrowserRouter is outermost so ScopeProvider (scope lives in `?scope=`) and the
  // tour engine can both use the router. TourOverlay/TourLauncher are siblings of
  // <Routes> so they survive navigation between screens.
  return (
    <BrowserRouter>
      <ScopeProvider>
        <TourProvider>
          <Routes>
            <Route element={<AppShell />}>
              <Route path="/" element={<Overview />} />
              <Route path="/attack-paths" element={<AttackPaths />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/supply-chain" element={<SupplyChain />} />
              <Route path="/registries" element={<Registries />} />
              <Route path="/inventory" element={<Inventory />} />
              <Route path="/identity" element={<Identity />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/remediation" element={<Remediation />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/accounts" element={<CloudAccounts />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/projects" element={<Projects />} />
              <Route path="/projects/:id" element={<ProjectView />} />
              <Route path="/query" element={<Query />} />
              <Route path="/runtime" element={<Runtime />} />
              <Route path="/data" element={<Data />} />
              {DASHBOARDS.map((d) => (
                <Route key={d.slug} path={`/${d.slug}`} element={<CategoryDashboard spec={d} />} />
              ))}
              <Route path="*" element={<Placeholder />} />
            </Route>
          </Routes>
          <CopilotPanel />
          <TourOverlay />
          <TourLauncher />
        </TourProvider>
      </ScopeProvider>
    </BrowserRouter>
  )
}
