# Architecture — the three layers

Until this split, all 109 python modules sat flat in the repository root
(68,433 lines). They are now three packages, and the boundary is a real
dependency rule rather than a filing convention.

```
hub/      17 modules   the hosted platform: API, auth, workspaces, connectors
  |
  v
engine/   89 modules   scanning: collection, checks, correlation, scoring
  |
  v
store/     3 modules   persistence: backend, schema, dialect
```

**The rule: dependencies point downward only.** `hub/` may import `engine/` and
`store/`. `engine/` may import `store/`. `store/` imports neither. There are
**zero** exceptions, and `tests/test_layering.py` fails if one appears — the
rule is executable, not documentary.

## Why store/ is its own layer

`aws_state`, `aws_state_dialect` and `cnapp_backend` are mutually recursive:

```
aws_state         -> cnapp_backend
cnapp_backend     -> aws_state, aws_state_dialect
aws_state_dialect -> aws_state
```

They are one unit. `aws_state` is imported by 8 hub modules and 4 engine
modules, so it belongs to neither side, and it already defers its
`cnapp_backend` imports into function bodies — the fingerprint of this cycle
being worked around once before. Putting the trio in `engine/` or `hub/` would
have placed a circular dependency across a package boundary, which is worse
than the flat root it replaced.

## Placement follows dependencies, not filenames

Two modules sit in the package their imports demand rather than the one their
prefix suggests:

| module | package | why |
|---|---|---|
| `aws_registry_connectors` | `hub/` | imports `cnapp_onboarding`; consumed only by `cnapp_service`. In `engine/` it would be the one remaining engine→hub back-edge. |
| `compliance_crosswalk` | `engine/` | no prefix at all; a leaf crosswalk loader with no layer of its own. |

The `aws_`/`cnapp_` prefixes are historical. Where a name and its package
disagree, **the package is correct** — it is checked; the prefix is not.

## Imports

Modules are imported through their package, and usage sites are unchanged:

```python
from engine import aws_correlate      # then aws_correlate.build_graph(...)
from store import aws_state
from hub.cnapp_api import Principal
```

The uvicorn entry point is `hub.cnapp_server:create_app_from_env`.

## Running the CLIs

Modules are packages now, so a bare script path no longer works — it puts
`engine/` on `sys.path` instead of the repository root, and `from engine import
...` then fails. Use `-m` from the repository root:

```bash
python -m engine.aws_live_scanner --help
python -m engine.aws_offline_scanner --help
python -m hub.cnapp_mcp
```
