import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ScopeProvider } from './state/scope'
import { AppShell } from './components/AppShell'
import { Overview } from './routes/Overview'
import { AttackPaths } from './routes/AttackPaths'
import { Findings } from './routes/Findings'
import { Vulnerabilities } from './routes/Vulnerabilities'
import { CloudAccounts } from './routes/CloudAccounts'
import { Inventory } from './routes/Inventory'
import { Identity } from './routes/Identity'
import { Compliance } from './routes/Compliance'
import { Remediation } from './routes/Remediation'
import { Reports } from './routes/Reports'
import { Settings } from './routes/Settings'
import { Placeholder } from './routes/Placeholder'

export default function App() {
  return (
    <ScopeProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<Overview />} />
            <Route path="/attack-paths" element={<AttackPaths />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/identity" element={<Identity />} />
            <Route path="/compliance" element={<Compliance />} />
            <Route path="/remediation" element={<Remediation />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/accounts" element={<CloudAccounts />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Placeholder />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ScopeProvider>
  )
}
