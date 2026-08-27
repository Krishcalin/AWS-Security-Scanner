"""
LOCAL DEVELOPMENT LAUNCHER — NOT FOR PRODUCTION, NOT FOR ANY SHARED HOST.

────────────────────────────────────────────────────────────────────────────────
WHY THIS FILE EXISTS INSTEAD OF A FLAG ON cnapp_server.py
────────────────────────────────────────────────────────────────────────────────
`cnapp_server.create_app_from_env()` leaves `current_principal` unset, which makes
every route 403. That is deliberate and its docstring says so in as many words:

    "NEVER ship with a permissive hook."

A `--dev-auth` flag on the shipped server would be exactly that hook — one
environment variable away from being switched on in production by accident, and
indistinguishable from the real thing in a code review. So the permissive hook
lives HERE, in a separate file, under `deploy/local/`, with a name and a docstring
that cannot be mistaken for the production entrypoint. `cnapp_server.py` is not
modified at all and stays fail-closed.

WHAT THIS GRANTS. A single hard-coded superadmin principal, unauthenticated. Every
request to this app is a platform administrator. There is no login, no token and no
way to be anyone else. That is fine on a laptop bound to 127.0.0.1 and is a total
compromise anywhere else.

The compose file binds the port to 127.0.0.1 rather than 0.0.0.0 for the same
reason — publishing 8080 on all interfaces would put an unauthenticated admin
console on the local network.
"""
from __future__ import annotations

import os

from hub import cnapp_server
from hub.cnapp_api import Principal

#: The one principal every local request authenticates as. `is_superadmin` makes
#: `Principal.role_in()` return "admin" for any workspace, so the console behaves
#: as it would for a platform operator without needing a workspace membership row.
_LOCAL_ADMIN = Principal(subject="local-dev@127.0.0.1", memberships={},
                         is_superadmin=True)


def _local_principal() -> Principal:
    """The injected FastAPI dependency. Returns the same admin for every request."""
    return _LOCAL_ADMIN


def create_app():
    """Factory for `uvicorn deploy.local.local_server:create_app --factory`."""
    if os.environ.get("OVERWATCH_LOCAL_DEV") != "1":
        # A second, explicit gate. Copying this file onto a server is not enough to
        # arm it — the operator has to have set the variable too, and the variable
        # is named so that seeing it in a production manifest is itself the alarm.
        raise RuntimeError(
            "deploy/local/local_server.py is a DEVELOPMENT launcher with "
            "unauthenticated superadmin access. It refuses to start unless "
            "OVERWATCH_LOCAL_DEV=1 is set. Production uses "
            "hub.cnapp_server:create_app_from_env with a real IdP-backed "
            "current_principal.")
    return cnapp_server.create_app_from_env(current_principal=_local_principal)
