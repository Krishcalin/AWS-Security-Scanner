# OverWatch Console (`frontend/`)

The React SPA for the OverWatch CNAPP — a live console over the existing FastAPI hub
(`cnapp_api.py` / `cnapp_service.py`). Phase 1 of the AccuKnox-informed UX roadmap.

**Stack:** React 19 · Vite · TypeScript · Tailwind v4 · React Router · lucide-react.
**Design:** light blue/white tokens continuous with the exported HTML report
(`_REPORT_CSS`), one severity color-law, cyan→indigo signature, crown gold for data
terminals / true choke points. Light + dark themes.

## Run it

```bash
cd frontend
npm install            # first time only
npm run dev            # http://localhost:5173  (sample data, no AWS needed)
```

The app opens on **Overview**. Use the scope switcher (top-left) to view the org
aggregate or drill into one of the three sample accounts.

### Data source (sample ↔ live)

The data layer (`src/api/client.ts`) toggles at build time — same fetch shape either way:

| `VITE_DATA_SOURCE` | Source | Notes |
|--------------------|--------|-------|
| `sample` (default) | `public/sample/*.json` | engine-generated fixtures; zero AWS |
| `live`             | `VITE_API_BASE` (default `/api`) | the FastAPI hub; dev-proxied to `:8000` |

```bash
# build against the live hub
VITE_DATA_SOURCE=live npm run dev
```

The Vite dev-proxy forwards `/api/*` → `http://127.0.0.1:8000` (a root-routed
`cnapp_api.create_app`). In production the hub serves both from one origin.

## Build & serve (single deployable)

```bash
npm run build          # -> dist/  (tsc typecheck + Vite bundle)
```

Serve `dist/` from the hub — the API lands under `/api`, the SPA at `/` with a
history-API fallback:

```python
# server.py  (hosted control plane)
import uvicorn
from cnapp_api import create_hosted_app
app = create_hosted_app(service, static_dir="frontend/dist", current_role=my_auth_hook)
uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Layout

```
src/
  api/         types.ts (mirror of the cnapp_api shapes) + client.ts (sample↔live)
  components/  AppShell · Sidebar · TopBar · ui (Card/GradeDial/StackBar/…)
  lib/         format · nav · theme · useFetch
  routes/      Overview (org + account scopes) · Placeholder
  state/       scope (org ↔ account switcher context)
public/sample/ engine-generated fixtures (org_overview, accounts, per-account summary/issues/paths/graph)
```

Fixtures are produced by the real engine (`aws_correlate` scoring /
`compliance_scorecard` / `compute_risk_score`) — regenerate with the fixture
generator kept in the session scratchpad.

## Backend endpoints consumed

`GET /org/overview` · `GET /accounts` · `GET /accounts/{id}/summary` ·
`GET /accounts/{id}/issues` · `GET /accounts/{id}/paths` · `GET /accounts/{id}/graph`
(all viewer-role; see `cnapp_api.py`).
