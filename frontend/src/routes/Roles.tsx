import { useEffect, useState } from 'react'
import { ShieldCheck, UserPlus, Trash2, Info, KeyRound, UserCog, Users } from 'lucide-react'
import { me as fetchMe, type Me } from '../api/auth'
import {
  addMember, createUser, listMembers, listRoles, listUsers, removeMember,
  resetUserPassword, setUserStatus,
  type AppUser, type CreatedUser, type Member, type RoleCatalogue,
} from '../api/roles'
import { Card, Loader, ErrorNote, Empty, Chip } from '../components/ui'

/**
 * Who is in this workspace, and what each of them may do.
 *
 * THE ROLE LIST IS FETCHED, NEVER HARD-CODED. A picker written in the console
 * can offer a role the gate does not know, or miss one it does — and the
 * failure is a 400 at grant time, long after the operator chose. `GET /roles`
 * returns the same list `cnapp_workspace.ASSIGNABLE_ROLES` gates on, with the
 * description the gate enforces.
 *
 * THE WORKSPACE IS NOT TAKEN FROM `me.memberships` ALONE. The local dev server
 * authenticates every request as a superadmin with NO memberships, and mounts
 * no /auth routes at all — so deriving the workspace from that map left this
 * screen showing "Members of —" and loading forever. It defaults to the
 * workspace a single-tenant install has, which is also the one a superadmin is
 * implicitly an admin of.
 *
 * PERMISSION IS ASSUMED WHEN IT CANNOT BE READ, for the same reason. Greying
 * out controls that would in fact work is worse than letting the API answer:
 * the API refuses regardless, and this screen explains rather than enforces.
 *
 * STYLED WITH TAILWIND UTILITIES AND THE THEME TOKENS, like every other route
 * here. The first version of this file used a vocabulary of semantic class
 * names — card-title, btn, lookup-input — that belongs to a DIFFERENT product
 * in this workspace and is defined nowhere in OverWatch, so the whole screen
 * rendered as unstyled text.
 */

const DEFAULT_WORKSPACE = 'ws-default'

const ROLE_TONE: Record<string, { fg: string; bg: string }> = {
  admin: { fg: 'var(--crit)', bg: 'var(--critbg)' },
  analyst: { fg: 'var(--high)', bg: 'var(--highbg)' },
  ingest: { fg: 'var(--med)', bg: 'var(--medbg)' },
  auditor: { fg: 'var(--ink2)', bg: 'var(--panel2)' },
}

const INPUT =
  'rounded-lg border border-line bg-panel px-3 py-1.5 text-sm text-ink ' +
  'placeholder:text-ink3 focus:outline-none focus:border-accent disabled:opacity-50'
const BTN =
  'rounded-lg border border-line px-3 py-1.5 text-xs font-semibold text-ink2 ' +
  'hover:text-ink disabled:opacity-40 transition-colors whitespace-nowrap'
const BTN_PRIMARY =
  'inline-flex items-center gap-1.5 rounded-lg bg-accent text-white font-semibold ' +
  'text-sm px-4 py-1.5 disabled:opacity-50 hover:brightness-110 transition-all'

function RoleChip({ role }: { role: string }) {
  // `viewer` is the original name for auditor and is still stored on older
  // rows. Shown as what it IS rather than silently relabelled, so the list
  // matches the string the database holds.
  const tone = ROLE_TONE[role] ?? ROLE_TONE.auditor
  return (
    <Chip fg={tone.fg} bg={tone.bg}>
      {role}{role === 'viewer' ? ' (= auditor)' : ''}
    </Chip>
  )
}

function Title({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 text-sm font-semibold text-ink mb-1">
      {icon}{children}
    </div>
  )
}

export default function Roles() {
  const [me, setMe] = useState<Me | null>(null)
  const [meKnown, setMeKnown] = useState(false)
  const [catalogue, setCatalogue] = useState<RoleCatalogue | null>(null)
  const [workspace, setWorkspace] = useState(DEFAULT_WORKSPACE)
  const [members, setMembers] = useState<Member[] | null>(null)
  const [users, setUsers] = useState<AppUser[] | null>(null)
  const [principal, setPrincipal] = useState('')
  const [role, setRole] = useState('auditor')
  const [newUser, setNewUser] = useState({ username: '', display: '', role: 'auditor' })
  const [issued, setIssued] =
    useState<CreatedUser | { username: string; password: string } | null>(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    fetchMe()
      .then(m => {
        setMe(m); setMeKnown(Boolean(m))
        const first = Object.keys(m?.memberships ?? {})[0]
        if (first) setWorkspace(first)
      })
      // No /auth/me on this entrypoint. Not an error: the API still enforces.
      .catch(() => { setMe(null); setMeKnown(false) })
    listRoles().then(setCatalogue).catch(() => setCatalogue(null))
  }, [])

  function refresh(ws: string) {
    if (!ws) return
    setMembers(null); setUsers(null); setError('')
    listMembers(ws)
      .then(setMembers)
      .catch(e => { setMembers([]); setError(String(e?.message ?? e)) })
    // A non-admin cannot list accounts. Not worth shouting about on a screen
    // they are allowed to read the rest of.
    listUsers(ws).then(setUsers).catch(() => setUsers([]))
  }
  useEffect(() => { refresh(workspace) }, [workspace])

  const myRole = me?.memberships?.[workspace] ?? ''
  // Optimistic when the session cannot be read — see the header.
  const isAdmin = !meKnown || Boolean(me?.is_superadmin) || myRole === 'admin'

  function run(job: () => Promise<void>) {
    setBusy(true); setError(''); setNotice('')
    job().finally(() => setBusy(false))
  }

  const grant = (e: React.FormEvent) => {
    e.preventDefault()
    const who = principal.trim()
    if (!who) { setError('A principal is required.'); return }
    run(async () => {
      try {
        await addMember(workspace, who, role)
        setNotice(`${who} is now ${role} in ${workspace}.`)
        setPrincipal(''); refresh(workspace)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'the role could not be granted')
      }
    })
  }

  const addPerson = (e: React.FormEvent) => {
    e.preventDefault()
    const who = newUser.username.trim()
    if (!who) { setError('A username is required.'); return }
    run(async () => {
      try {
        setIssued(await createUser(workspace, who, newUser.role, newUser.display.trim()))
        setNewUser({ username: '', display: '', role: 'auditor' })
        refresh(workspace)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'the account could not be created')
      }
    })
  }

  const revoke = (m: Member) => run(async () => {
    try {
      await removeMember(workspace, m.principal)
      setNotice(`${m.principal} was removed from ${workspace}.`)
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the member could not be removed')
    }
  })

  const toggleStatus = (u: AppUser) => run(async () => {
    const next = u.status === 'active' ? 'disabled' : 'active'
    try {
      await setUserStatus(workspace, u.username, next)
      setNotice(`${u.username} is now ${next}.`); refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the status could not be changed')
    }
  })

  const resetPassword = (u: AppUser) => run(async () => {
    try {
      setIssued(await resetUserPassword(workspace, u.username)); refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the password could not be reset')
    }
  })

  const workspaces = Object.keys(me?.memberships ?? {})
  const roleOptions = catalogue?.roles ?? []

  return (
    <div className="flex flex-col gap-4">
      <Card className="p-5">
        <Title icon={<ShieldCheck size={15} className="text-accent" />}>Roles and access</Title>
        <p className="text-sm text-ink2">
          Who belongs to a workspace, and what each of them may do. Only an
          administrator can grant a role — including another administrator.
        </p>
        <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-ink3">
          {workspaces.length > 1 ? (
            <select className={INPUT} value={workspace} aria-label="Workspace"
                    onChange={e => setWorkspace(e.target.value)}>
              {workspaces.map(w => (
                <option key={w} value={w}>{w} — you are {me?.memberships[w]}</option>
              ))}
            </select>
          ) : (
            <span className="font-mono rounded-md border border-line px-2 py-1">{workspace}</span>
          )}
          {meKnown && !isAdmin && (
            <span>You are {myRole || 'not a member'} here, so these controls are read-only.</span>
          )}
        </div>
      </Card>

      {catalogue && (
        <Card className="p-5">
          <Title icon={<Info size={15} className="text-ink3" />}>What the roles mean</Title>
          <div className="mt-2 flex flex-col divide-y divide-line">
            {catalogue.roles.map(r => (
              <div key={r.role} className="flex items-start gap-4 py-2.5">
                <div className="w-24 shrink-0"><RoleChip role={r.role} /></div>
                <div className="text-sm text-ink2">{r.description}</div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-ink3">{catalogue.note}</p>
        </Card>
      )}

      <Card className="p-5">
        <Title icon={<UserCog size={15} className="text-accent" />}>Add a person</Title>
        <p className="text-sm text-ink2">
          Creates the account and grants the role in one step. Two steps can
          half-succeed, and an account with no role signs in to an empty console.
        </p>
        <form onSubmit={addPerson} className="mt-3 flex flex-wrap items-center gap-2">
          <input className={`${INPUT} min-w-[15rem] flex-1`} value={newUser.username}
                 disabled={!isAdmin} placeholder="priya@acme.example"
                 aria-label="Username" autoComplete="off" spellCheck={false}
                 onChange={e => setNewUser(u => ({ ...u, username: e.target.value }))} />
          <input className={`${INPUT} w-44`} value={newUser.display} disabled={!isAdmin}
                 placeholder="Display name" aria-label="Display name" autoComplete="off"
                 onChange={e => setNewUser(u => ({ ...u, display: e.target.value }))} />
          <select className={`${INPUT} w-32`} value={newUser.role} disabled={!isAdmin}
                  aria-label="Role for the new account"
                  onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}>
            {roleOptions.map(r => <option key={r.role} value={r.role}>{r.role}</option>)}
          </select>
          <button className={BTN_PRIMARY} disabled={!isAdmin || busy}>
            <UserPlus size={14} />{busy ? 'Working…' : 'Create'}
          </button>
        </form>
      </Card>

      {/* THE ONE-TIME PASSWORD. Its own block because it exists nowhere else —
          only the hash is stored — and a credential rendered as a toast is a
          credential somebody loses. */}
      {issued && (
        <Card className="p-5">
          <Title icon={<KeyRound size={15} className="text-accent" />}>
            One-time password for {issued.username}
          </Title>
          <div className="mt-2 rounded-lg border border-line px-4 py-3 font-mono text-base tracking-wide text-ink"
               style={{ background: 'var(--panel2)' }}>
            {issued.password}
          </div>
          <p className="mt-2 text-xs text-ink3">
            Shown once and not recoverable. The account is locked to the change
            form until its owner picks their own password. Copy it now.
          </p>
          <button className={`${BTN} mt-3`} onClick={() => setIssued(null)}>Done</button>
        </Card>
      )}

      <Card className="p-5">
        <Title icon={<UserPlus size={15} className="text-ink3" />}>
          Grant a role to an existing principal
        </Title>
        <form onSubmit={grant} className="mt-3 flex flex-wrap items-center gap-2">
          <input className={`${INPUT} min-w-[15rem] flex-1`} value={principal}
                 disabled={!isAdmin} placeholder="someone@example.com"
                 aria-label="Principal" autoComplete="off" spellCheck={false}
                 onChange={e => setPrincipal(e.target.value)} />
          <select className={`${INPUT} w-32`} value={role} disabled={!isAdmin}
                  aria-label="Role" onChange={e => setRole(e.target.value)}>
            {roleOptions.map(r => <option key={r.role} value={r.role}>{r.role}</option>)}
          </select>
          <button className={BTN_PRIMARY} disabled={!isAdmin || busy}>Grant</button>
        </form>
        <p className="mt-2 text-xs text-ink3">
          Granting a role to somebody who already has one replaces it.
        </p>
      </Card>

      {error && <ErrorNote msg={error} />}
      {notice && (
        <div className="rounded-xl border border-line px-4 py-3 text-sm text-ink2">{notice}</div>
      )}

      <Card className="p-5">
        <Title icon={<Users size={15} className="text-ink3" />}>Members of {workspace}</Title>
        {members === null && <Loader />}
        {members !== null && members.length === 0 && (
          <Empty>Nobody is a member of this workspace yet.</Empty>
        )}
        {members !== null && members.length > 0 && (
          <div className="mt-2 flex flex-col divide-y divide-line">
            {members.map(m => {
              const isMe = m.principal === me?.username
              return (
                <div key={m.principal} className="flex items-center gap-3 py-2.5">
                  <div className="flex-1 font-mono text-sm text-ink truncate">
                    {m.principal}
                    {isMe && <span className="text-ink3"> (you)</span>}
                  </div>
                  <RoleChip role={m.role} />
                  <div className="w-16 text-xs text-ink3">{m.status}</div>
                  <button className={BTN}
                          // Removing yourself leaves a workspace you can no
                          // longer administer. The API allows it; this does not.
                          disabled={!isAdmin || busy || isMe}
                          title={isMe ? 'You cannot remove your own access' : ''}
                          onClick={() => revoke(m)}>
                    <Trash2 size={12} className="inline -mt-0.5 mr-1" />Remove
                  </button>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      {users !== null && users.length > 0 && (
        <Card className="p-5">
          <Title icon={<UserCog size={15} className="text-ink3" />}>Local accounts</Title>
          <div className="mt-2 flex flex-col divide-y divide-line">
            {users.map(u => {
              const isMe = u.username === me?.username
              return (
                <div key={u.username} className="flex flex-wrap items-center gap-3 py-2.5">
                  <div className="flex-1 min-w-[14rem]">
                    <div className="font-mono text-sm text-ink truncate">
                      {u.username}{isMe && <span className="text-ink3"> (you)</span>}
                    </div>
                    <div className="text-xs text-ink3">
                      {u.status}
                      {Boolean(u.must_change_password) && ' · must change password'}
                      {' · '}
                      {u.last_login_at
                        ? `last signed in ${new Date(u.last_login_at * 1000).toLocaleDateString()}`
                        : 'never signed in'}
                    </div>
                  </div>
                  {/* No role here is a real state: the account exists and can
                      sign in to nothing. */}
                  {u.role
                    ? <RoleChip role={u.role} />
                    : <span className="text-xs text-ink3">no role here</span>}
                  <button className={BTN} disabled={!isAdmin || busy}
                          onClick={() => resetPassword(u)}>Reset password</button>
                  <button className={BTN}
                          disabled={!isAdmin || busy || (isMe && u.status === 'active')}
                          title={isMe ? 'You cannot disable your own account' : ''}
                          onClick={() => toggleStatus(u)}>
                    {u.status === 'active' ? 'Disable' : 'Enable'}
                  </button>
                </div>
              )
            })}
          </div>
        </Card>
      )}
    </div>
  )
}
