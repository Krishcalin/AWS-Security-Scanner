# Production rollout

What a first production load of the OverWatch hub requires, and why each item is
required rather than defaulted. Everything here is configuration: the code ships
safe, and "safe" for an unconfigured hub means **refusing**, not guessing.

## The three settings with no safe default

| Setting | Value | Without it |
|---|---|---|
| `CNAPP_AUTH_MODE` | `local` or `idp` | **the process refuses to start** |
| `CNAPP_SECRETS_BACKEND` | `aws-secrets-manager` | onboarding and every connector refuse |
| `CNAPP_COOKIE_SECURE` | `always` behind a TLS proxy | the session cookie ships **without `Secure`** |

Each of these used to fail quietly. `CNAPP_AUTH_MODE` replaces an image that
served **403 on every route** — correct, and indistinguishable from a broken
deployment.

## Authentication

```
CNAPP_AUTH_MODE=local
OVERWATCH_BOOTSTRAP_USER=<first admin>
OVERWATCH_BOOTSTRAP_PASSWORD=<strong, from your secret store>
```

`local` uses the built-in provider: pbkdf2 password hashing, server-side
sessions, optional TOTP, workspace RBAC. Unauthenticated requests resolve to an
empty principal, which is deny-all — this is not a permissive mode, it is a way
to obtain a session.

The bootstrap credential is applied **once, against an empty user table**, and is
never printed. It does nothing on a database that already has users, so it cannot
be used to reset a forgotten password — use `/auth/users/{username}/password` as
an existing admin.

For an IdP in front of the hub, set `CNAPP_AUTH_MODE=idp` and inject your own
`current_principal` via `create_app_from_env`.

## Secrets — AWS Secrets Manager

```
CNAPP_SECRETS_BACKEND=aws-secrets-manager
CNAPP_SECRETS_PREFIX=overwatch/            # optional, this is the default
CNAPP_SECRETS_KMS_KEY_ID=<cmk>             # optional; omit for the AWS-managed key
CNAPP_SECRETS_REGION=<region>              # optional; falls back to AWS_REGION
```

Onboarding ExternalIds and connector API tokens are written here; **only the
`secretsmanager://` reference is stored in the hub database**, never the value.

The hub's **own task role** needs, scoped to the prefix (e.g. `overwatch/*`):

```
secretsmanager:CreateSecret      a new ExternalId or connector token
secretsmanager:PutSecretValue    rotation
secretsmanager:GetSecretValue    resolve at scan / delivery time
secretsmanager:DescribeSecret    the ownership check before any overwrite
secretsmanager:TagResource       provenance stamp at creation
kms:Encrypt, kms:Decrypt, kms:GenerateDataKey   only with a customer-managed key
```

This is **not** the cross-account scanning role. That one stays read-only, and
nothing here belongs in `aws_perm_ledger`.

**Ownership is enforced.** Every secret is tagged `cnapp:owner=overwatch` at
creation, and an update refuses unless the existing secret carries that tag — so
a prefix collision with one of your own secrets fails loudly instead of
overwriting it. If `DescribeSecret` fails, the write refuses rather than
proceeding: an ownership check that fails open is not a check.

## TLS and the session cookie

Set **`CNAPP_COOKIE_SECURE=always`** whenever TLS terminates before the app.

The default (`auto`) marks the cookie `Secure` only when the request arrived over
HTTPS, which keeps a local `http://127.0.0.1` stack working. Behind a
TLS-terminating proxy the app sees the proxy's plain-http hop, so `auto` omits
`Secure` — and nothing reports it. Uvicorn honours `X-Forwarded-Proto` only from
`forwarded_allow_ips`, which **defaults to `127.0.0.1`**; a proxy in another
container or a load balancer is never `127.0.0.1`.

Either set `CNAPP_COOKIE_SECURE=always` (recommended — it states the deployment's
own truth), or set `FORWARDED_ALLOW_IPS` to the proxy's address so `auto` can
work it out. The first does not depend on getting the second right.

## Database

```
CNAPP_DB_URL=postgresql://user:pass@host:5432/overwatch
```

Schema creation and migration run at startup. Take a backup before first start on
an existing database: migrations include in-place constraint changes.

## Before you call it live

- [ ] `docker logs` shows `Application startup complete` — not a `CNAPP_AUTH_MODE` refusal
- [ ] `GET /` serves the console; `GET /api/auth/me` returns 401 unauthenticated
- [ ] Sign in as the bootstrap admin, then **change that password**
- [ ] Confirm the session cookie carries `Secure` and `HttpOnly` in browser devtools
- [ ] Onboard one account end to end — this is the only real test of the secret store
- [ ] Confirm a `secretsmanager://` ref appears in the DB and **no plaintext**

## Known gaps at this version

Deliberate, and named rather than left to be discovered:

- **Auto-fix execution is withheld** (decision D11). The governance is built; no
  execution role is deployed. OverWatch mutates only resources it created.
- **`aws_trend` and `aws_guardrail` are not wired** into the pipeline.
- **Inbound ticket sync is not built** (`OW2-CC-021`). ServiceDesk Plus ticket
  creation is outbound only; a ticket closed while the finding persists does not
  reopen — `OW2-AR-030` says the finding wins.
- **`iam:ListAccessKeys` is not collected**, so the leaked-key join (NHI-02) is
  inert.
