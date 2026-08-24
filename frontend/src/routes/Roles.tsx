import { useEffect, useState } from 'react'
import { ShieldCheck, UserPlus, Trash2, Info } from 'lucide-react'
import { me as fetchMe, type Me } from '../api/auth'
import {
  addMember, listMembers, listRoles, removeMember,
  type Member, type RoleCatalogue,
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
    setMembers(null); setError('')
    listMembers(ws).then(setMembers).catch(e => setError(String(e.message ?? e)))
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
        <div className="card-title"><UserPlus size={13} className="inline -mt-0.5 mr-1" />Grant a role</div>
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
    </div>
  )
}
