import { useEffect, useState } from 'react'
import { ShieldCheck, UserPlus, Trash2, Info, KeyRound, UserCog } from 'lucide-react'
import { me as fetchMe, type Me } from '../api/auth'
import {
  addMember, createUser, listMembers, listRoles, listUsers, removeMember,
  resetUserPassword, setUserStatus,
  type AppUser, type CreatedUser, type Member, type RoleCatalogue,
} from '../api/roles'
import { Card, Loader, Empty, Chip } from '../components/ui'

/**
 * Who is in this workspace, and what each of them may do.
 *
 * THE ROLE LIST IS FETCHED, NEVER HARD-CODED. A picker written in the console
 * can offer a role the gate does not know, or miss one it does — and the
 * failure is a 400 at grant time, long after the operator chose. `GET /roles`
 * returns the same list `cnapp_workspace.ASSIGNABLE_ROLES` gates on, with the
 * description the gate actually enforces.
 *
 * EVERY CONTROL IS DISABLED FOR A NON-ADMIN RATHER THAN HIDDEN. A viewer who
 * cannot see the member list has no way to learn who could help them; one who
 * sees it greyed out learns both that roles exist and that they need an
 * administrator. The API refuses regardless — this is the explanation, not the
 * enforcement.
 *
 * REMOVING YOURSELF IS BLOCKED IN THE UI. The API would allow it, and the
 * result is a workspace you can no longer administer — recoverable only by
 * another admin or by hand in the database. That is a bad afternoon to hand
 * somebody for one mis-click.
 */

const RANK_TONE: Record<string, { fg: string; bg: string }> = {
  admin: { fg: 'var(--crit)', bg: 'var(--critbg)' },
  analyst: { fg: 'var(--high)', bg: 'var(--highbg)' },
  ingest: { fg: 'var(--med)', bg: 'var(--medbg)' },
  auditor: { fg: 'var(--ink2)', bg: 'var(--card2)' },
}

function RoleChip({ role }: { role: string }) {
  // `viewer` is the original name for auditor and is still stored on older
  // rows. Shown as what it IS rather than silently relabelled, so an operator
  // reading the table sees the same string the database holds.
  const tone = RANK_TONE[role] ?? RANK_TONE.auditor
  return (
    <Chip fg={tone.fg} bg={tone.bg}>
      {role}{role === 'viewer' ? ' (= auditor)' : ''}
    </Chip>
  )
}

export default function Roles() {
  const [me, setMe] = useState<Me | null>(null)
  const [catalogue, setCatalogue] = useState<RoleCatalogue | null>(null)
  const [workspace, setWorkspace] = useState('')
  const [members, setMembers] = useState<Member[] | null>(null)
  const [principal, setPrincipal] = useState('')
  const [role, setRole] = useState('auditor')
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const [users, setUsers] = useState<AppUser[] | null>(null)
  const [newUser, setNewUser] = useState({ username: '', display: '', role: 'auditor' })
  // Shown ONCE. Held in state rather than refetched because it does not exist
  // anywhere to refetch from — only the hash is stored.
  const [issued, setIssued] = useState<
    CreatedUser | { username: string; password: string } | null>(null)

  useEffect(() => {
    fetchMe().then(m => {
      setMe(m)
      const first = Object.keys(m?.memberships ?? {})[0] ?? ''
      setWorkspace(w => w || first)
    }).catch(() => setMe(null))
    listRoles().then(setCatalogue).catch(() => setCatalogue(null))
  }, [])

  function refresh(ws: string) {
    if (!ws) return
    setMembers(null); setUsers(null); setError('')
    listMembers(ws).then(setMembers).catch(e => setError(String(e.message ?? e)))
    // A non-admin cannot list accounts. That is not an error worth shouting
    // about on a screen they are allowed to read the rest of.
    listUsers(ws).then(setUsers).catch(() => setUsers([]))
  }
  useEffect(() => { refresh(workspace) }, [workspace])

  const myRole = me?.memberships?.[workspace] ?? ''
  const isAdmin = Boolean(me?.is_superadmin) || myRole === 'admin'

  async function grant(e: React.FormEvent) {
    e.preventDefault()
    const who = principal.trim()
    if (!who) { setError('A principal is required.'); return }
    setBusy(true); setError(''); setNotice('')
    try {
      await addMember(workspace, who, role)
      setNotice(`${who} is now ${role} in ${workspace}.`)
      setPrincipal('')
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the role could not be granted')
    } finally {
      setBusy(false)
    }
  }

  async function revoke(member: Member) {
    setBusy(true); setError(''); setNotice('')
    try {
      await removeMember(workspace, member.principal)
      setNotice(`${member.principal} was removed from ${workspace}.`)
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the member could not be removed')
    } finally {
      setBusy(false)
    }
  }

  async function addPerson(e: React.FormEvent) {
    e.preventDefault()
    const who = newUser.username.trim()
    if (!who) { setError('A username is required.'); return }
    setBusy(true); setError(''); setNotice(''); setIssued(null)
    try {
      const created = await createUser(workspace, who, newUser.role, newUser.display.trim())
      setIssued(created)
      setNewUser({ username: '', display: '', role: 'auditor' })
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the account could not be created')
    } finally { setBusy(false) }
  }

  async function toggleStatus(user: AppUser) {
    setBusy(true); setError(''); setNotice(''); setIssued(null)
    const next = user.status === 'active' ? 'disabled' : 'active'
    try {
      await setUserStatus(workspace, user.username, next)
      setNotice(`${user.username} is now ${next}.`)
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the status could not be changed')
    } finally { setBusy(false) }
  }

  async function resetPassword(user: AppUser) {
    setBusy(true); setError(''); setNotice(''); setIssued(null)
    try {
      setIssued(await resetUserPassword(workspace, user.username))
      refresh(workspace)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'the password could not be reset')
    } finally { setBusy(false) }
  }

  const workspaces = Object.keys(me?.memberships ?? {})

  return (
    <div className="stack">
      <Card>
        <div className="card-title"><ShieldCheck size={14} className="inline -mt-0.5 mr-1" />Roles and access</div>
        <p className="lede">
          Who belongs to a workspace, and what each of them may do. Only an
          administrator can grant a role — including another administrator.
        </p>
        {!isAdmin && (
          <div className="banner banner-info">
            You are {myRole || 'not a member'} in this workspace, so the controls
            below are read-only. Ask an administrator to change a role.
          </div>
        )}
      </Card>

      {workspaces.length > 1 && (
        <Card>
          <div className="card-title">Workspace</div>
          <select className="lookup-input" value={workspace}
                  onChange={e => setWorkspace(e.target.value)}>
            {workspaces.map(w => (
              <option key={w} value={w}>{w} — you are {me?.memberships[w]}</option>
            ))}
          </select>
        </Card>
      )}

      {/* WHAT EACH ROLE MEANS, from the API. An operator granting a role should
          not have to read the source to find out what they are handing over. */}
      {catalogue && (
        <Card>
          <div className="card-title"><Info size={13} className="inline -mt-0.5 mr-1" />What the roles mean</div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>Role</th><th>Can do</th></tr></thead>
              <tbody>
                {catalogue.roles.map(r => (
                  <tr key={r.role}>
                    <td><RoleChip role={r.role} /></td>
                    <td className="text-ink2">{r.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="gap-why">{catalogue.note}</div>
        </Card>
      )}

      <Card>
        <div className="card-title"><UserCog size={13} className="inline -mt-0.5 mr-1" />Add a person</div>
        <p className="lede">
          Creates the account and grants the role in one step. Two steps can
          half-succeed, and an account with no role signs in to an empty console.
        </p>
        <form onSubmit={addPerson} className="lookup-form">
          <input className="lookup-input" value={newUser.username} disabled={!isAdmin}
                 placeholder="priya@acme.example" aria-label="Username"
                 autoComplete="off" spellCheck={false}
                 onChange={e => setNewUser(u => ({ ...u, username: e.target.value }))} />
          <input className="lookup-input" style={{ maxWidth: '12rem' }}
                 value={newUser.display} disabled={!isAdmin}
                 placeholder="Display name" aria-label="Display name"
                 autoComplete="off"
                 onChange={e => setNewUser(u => ({ ...u, display: e.target.value }))} />
          <select className="lookup-input" style={{ maxWidth: '10rem' }}
                  value={newUser.role} disabled={!isAdmin}
                  aria-label="Role for the new account"
                  onChange={e => setNewUser(u => ({ ...u, role: e.target.value }))}>
            {(catalogue?.roles ?? []).map(r => (
              <option key={r.role} value={r.role}>{r.role}</option>
            ))}
          </select>
          <button className="btn btn-primary" disabled={!isAdmin || busy}>
            {busy ? 'Working…' : 'Create'}
          </button>
        </form>
      </Card>

      {/* THE ONE-TIME PASSWORD. Its own prominent block because it exists
          nowhere else — only the hash is stored — and a credential rendered as
          a toast is a credential somebody loses. */}
      {issued && (
        <Card>
          <div className="card-title">
            <KeyRound size={13} className="inline -mt-0.5 mr-1" />
            One-time password for {issued.username}
          </div>
          <div className="secret-box"><span className="secret-key mono">{issued.password}</span></div>
          <div className="gap-why">
            Shown once and not recoverable. The account is locked to the change
            form until its owner picks their own password. Copy it now.
          </div>
          <button className="btn" onClick={() => setIssued(null)}>Done</button>
        </Card>
      )}

      <Card>
        <div className="card-title"><UserPlus size={13} className="inline -mt-0.5 mr-1" />Grant a role to an existing principal</div>
        <form onSubmit={grant} className="lookup-form">
          <input className="lookup-input" value={principal} disabled={!isAdmin}
                 placeholder="someone@example.com"
                 aria-label="Principal to grant a role to"
                 autoComplete="off" spellCheck={false}
                 onChange={e => setPrincipal(e.target.value)} />
          <select className="lookup-input" style={{ maxWidth: '12rem' }}
                  value={role} disabled={!isAdmin} aria-label="Role"
                  onChange={e => setRole(e.target.value)}>
            {(catalogue?.roles ?? []).map(r => (
              <option key={r.role} value={r.role}>{r.role}</option>
            ))}
          </select>
          <button className="btn btn-primary" disabled={!isAdmin || busy}>
            {busy ? 'Working…' : 'Grant'}
          </button>
        </form>
        {/* Granting an existing member a new role is the same call, so say so
            rather than letting somebody remove-then-re-add to change one. */}
        <div className="gap-why">
          Granting a role to somebody who already has one replaces it.
        </div>
      </Card>

      {error && <div className="banner banner-crit" role="alert">{error}</div>}
      {notice && <div className="banner banner-ok" role="status">{notice}</div>}

      <div className="table-card">
        <div className="card-title">Members of {workspace || '—'}</div>
        {members === null && !error && <Loader />}
        {members !== null && members.length === 0 && (
          <Empty>Nobody is a member of this workspace yet.</Empty>
        )}
        {members !== null && members.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th>Principal</th><th>Role</th><th>Status</th><th></th></tr>
              </thead>
              <tbody>
                {members.map(m => {
                  const isMe = m.principal === me?.username
                  return (
                    <tr key={m.principal}>
                      <td className="mono">
                        {m.principal}
                        {isMe && <span className="text-ink2"> (you)</span>}
                      </td>
                      <td><RoleChip role={m.role} /></td>
                      <td className="text-ink2">{m.status}</td>
                      <td>
                        <button
                          className="btn"
                          // Removing yourself leaves a workspace you can no
                          // longer administer. The API allows it; this does not.
                          disabled={!isAdmin || busy || isMe}
                          title={isMe ? 'You cannot remove your own access' : ''}
                          onClick={() => revoke(m)}
                        >
                          <Trash2 size={12} className="inline -mt-0.5 mr-1" />
                          Remove
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {users !== null && users.length > 0 && (
        <div className="table-card">
          <div className="card-title">Local accounts</div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr><th>Account</th><th>Role here</th><th>Status</th><th>Last sign-in</th><th></th></tr>
              </thead>
              <tbody>
                {users.map(u => {
                  const isMe = u.username === me?.username
                  return (
                    <tr key={u.username}>
                      <td className="mono">
                        {u.username}
                        {isMe && <span className="text-ink2"> (you)</span>}
                        {Boolean(u.must_change_password) && (
                          <span className="text-ink2"> · must change password</span>
                        )}
                      </td>
                      <td>
                        {/* No role here is a real state worth seeing: the
                            account exists and can sign in to nothing. */}
                        {u.role
                          ? <RoleChip role={u.role} />
                          : <span className="text-ink2">no role in this workspace</span>}
                      </td>
                      <td className="text-ink2">{u.status}</td>
                      <td className="text-ink2">
                        {u.last_login_at
                          ? new Date(u.last_login_at * 1000).toLocaleDateString()
                          : 'never'}
                      </td>
                      <td>
                        <button className="btn" disabled={!isAdmin || busy}
                                onClick={() => resetPassword(u)}>
                          Reset password
                        </button>
                        {' '}
                        <button className="btn"
                                disabled={!isAdmin || busy || (isMe && u.status === 'active')}
                                title={isMe ? 'You cannot disable your own account' : ''}
                                onClick={() => toggleStatus(u)}>
                          {u.status === 'active' ? 'Disable' : 'Enable'}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
