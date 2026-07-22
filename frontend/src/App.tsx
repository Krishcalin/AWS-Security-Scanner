import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ScopeProvider } from './state/scope'
import { AppShell } from './components/AppShell'
import { Overview } from './routes/Overview'
import { Placeholder } from './routes/Placeholder'

export default function App() {
  return (
    <ScopeProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<Overview />} />
            <Route path="/attack-paths" element={<Placeholder />} />
            <Route path="/findings" element={<Placeholder />} />
            <Route path="/inventory" element={<Placeholder />} />
            <Route path="/identity" element={<Placeholder />} />
            <Route path="/compliance" element={<Placeholder />} />
            <Route path="/remediation" element={<Placeholder />} />
            <Route path="/reports" element={<Placeholder />} />
            <Route path="/accounts" element={<Placeholder />} />
            <Route path="/settings" element={<Placeholder />} />
            <Route path="*" element={<Placeholder />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ScopeProvider>
  )
}
