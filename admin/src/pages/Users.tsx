import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertCircle, Plus, RefreshCw, Trash2, Edit2, ChevronRight, User } from 'lucide-react'
import { usersApi, rolesApi, tenantApi, type User as UserType } from '../api/client'
import { Button } from '../components/ui/Button'
import { Input, Select } from '../components/ui/Input'
import { Badge, RoleBadge } from '../components/ui/Badge'
import { Dialog } from '../components/ui/Dialog'
import { Skeleton } from '../components/ui/Skeleton'
import { EmptyState } from '../components/ui/EmptyState'
import { useToast } from '../components/ui/Toast'

interface UserForm {
  username: string
  email: string
  password: string
  roleIds: string[]
  segments: string[]
  classification: string
  team: string
}

const EMPTY: UserForm = {
  username: '',
  email: '',
  password: '',
  roleIds: [],
  segments: [],
  classification: 'internal',
  team: '',
}

const CLASSIFICATION_COLORS: Record<string, string> = {
  public: 'bg-green-100 text-green-800',
  internal: 'bg-blue-100 text-blue-800',
  confidential: 'bg-amber-100 text-amber-800',
  restricted: 'bg-red-100 text-red-800',
}

function getClassificationColor(classification: string): string {
  return CLASSIFICATION_COLORS[classification] || 'bg-slate-100 text-slate-800'
}

function SkeletonRow() {
  return (
    <tr className="border-b border-slate-100">
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-3">
          <Skeleton className="w-8 h-8 rounded-full" />
          <div className="flex-1">
            <Skeleton className="h-4 w-32 mb-1" />
            <Skeleton className="h-3 w-40" />
          </div>
        </div>
      </td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-24" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-20" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-24" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-28" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-16" /></td>
    </tr>
  )
}

export function Users() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [editing, setEdit] = useState<UserType | null>(null)
  const [uid, setUid] = useState('')
  const [form, setForm] = useState({ ...EMPTY })
  const [detail, setDetail] = useState<UserType | null>(null)
  const [search, setSearch] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<UserType | null>(null)

  const { data: users = [], isLoading, isError, error, refetch } = useQuery({
    queryKey: ['users'],
    queryFn: usersApi.list,
  })
  const { data: roles = [] } = useQuery({
    queryKey: ['roles'],
    queryFn: rolesApi.list,
  })
  const { data: classifications = [] } = useQuery({
    queryKey: ['classifications'],
    queryFn: tenantApi.getClassificationSchema,
  })

  const roleIdByName = useMemo(
    () => new Map(roles.map((role) => [role.name, role.id])),
    [roles],
  )

  const createMut = useMutation({
    mutationFn: async () => {
      if (!uid.trim()) throw new Error('User ID is required')
      if (!form.password.trim()) throw new Error('Password is required')
      const created = await usersApi.create({
        id: uid.trim(),
        username: form.username.trim(),
        email: form.email.trim(),
        password: form.password,
        attributes: {
          classification: form.classification,
          segments: form.segments,
          team: form.team,
        },
      })
      await Promise.all(form.roleIds.map((roleId) => usersApi.assignRole(created.id, roleId)))
      return created
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      close()
      toast('success', 'User created')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const updateMut = useMutation({
    mutationFn: async () => {
      if (!editing) throw new Error('No user selected')
      const beforeRoleIds = editing.roles
        .map((name) => roleIdByName.get(name))
        .filter((roleId): roleId is string => Boolean(roleId))
      const desired = new Set(form.roleIds)
      const before = new Set(beforeRoleIds)

      const updated = await usersApi.update(editing.id, {
        email: form.email.trim(),
        attributes: {
          classification: form.classification,
          segments: form.segments,
          team: form.team,
        },
      })

      await Promise.all([
        ...form.roleIds
          .filter((roleId) => !before.has(roleId))
          .map((roleId) => usersApi.assignRole(editing.id, roleId)),
        ...beforeRoleIds
          .filter((roleId) => !desired.has(roleId))
          .map((roleId) => usersApi.removeRole(editing.id, roleId)),
      ])
      return updated
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      close()
      toast('success', 'User updated')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => usersApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      setDeleteTarget(null)
      toast('success', 'User deleted')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const assignRoleMut = useMutation({
    mutationFn: ({ userId, roleId }: { userId: string; roleId: string }) =>
      usersApi.assignRole(userId, roleId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      toast('success', 'Role assigned')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const removeRoleMut = useMutation({
    mutationFn: ({ userId, roleId }: { userId: string; roleId: string }) =>
      usersApi.removeRole(userId, roleId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['users'] })
      toast('success', 'Role removed')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  function openCreate() {
    setEdit(null)
    setUid('')
    setForm({ ...EMPTY })
    setOpen(true)
  }
  function openEdit(u: UserType) {
    setEdit(u)
    setUid(u.id)
    setForm({
      username: u.username,
      email: u.email,
      password: '',
      roleIds: u.roles
        .map((name) => roleIdByName.get(name))
        .filter((roleId): roleId is string => Boolean(roleId)),
      segments: u.segments,
      classification: u.classification,
      team: u.team || '',
    })
    setOpen(true)
  }
  function close() {
    setOpen(false)
    setEdit(null)
  }

  const filtered = users.filter(
    u =>
      u.username.toLowerCase().includes(search.toLowerCase()) ||
      u.id.toLowerCase().includes(search.toLowerCase()) ||
      u.email.toLowerCase().includes(search.toLowerCase())
  )

  const detailUser = detail ? users.find(u => u.id === detail.id) ?? detail : null

  return (
    <div className="px-8 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Users</h1>
          <p className="text-sm text-slate-500 mt-1">
            {users.length} principal{users.length !== 1 ? 's' : ''} in directory
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus size={15} /> Add user
        </Button>
      </div>

      {/* Search */}
      <div className="mb-4">
        <Input
          placeholder="Search by name, ID, or email…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="max-w-xs"
        />
      </div>

      {isError && (
        <div className="mb-4 flex items-center gap-3 rounded-lg border border-red-200 bg-red-50 p-4" role="alert">
          <AlertCircle size={18} className="shrink-0 text-red-700" />
          <p className="flex-1 text-sm font-medium text-red-900">
            {error instanceof Error ? error.message : 'Users could not be loaded'}
          </p>
          <Button size="sm" variant="secondary" onClick={() => { void refetch() }}>
            <RefreshCw size={14} />
            Retry
          </Button>
        </div>
      )}

      {/* Table */}
      <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
        {isLoading ? (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['User', 'Roles', 'Classification', 'Team', 'Segments', ''].map(h => (
                  <th
                    key={h}
                    className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[...Array(5)].map((_, i) => (
                <SkeletonRow key={i} />
              ))}
            </tbody>
          </table>
        ) : filtered.length === 0 ? (
          <EmptyState
            icon={<User size={40} className="text-slate-300" />}
            title="No users found"
            description={
              users.length === 0
                ? 'Create your first user to get started'
                : 'Try adjusting your search'
            }
            action={
              users.length === 0
                ? { label: 'Create user', onClick: openCreate }
                : undefined
            }
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['User', 'Roles', 'Classification', 'Team', 'Segments', ''].map(h => (
                  <th
                    key={h}
                    className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filtered.map(u => (
                <tr key={u.id} className="hover:bg-slate-50 transition-colors group">
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-axiom-50 flex items-center justify-center shrink-0 ring-1 ring-axiom-600/10">
                        <span className="text-axiom-800 text-sm font-semibold">
                          {u.username.charAt(0)}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-slate-900">{u.username}</p>
                        <p className="text-xs text-slate-500">
                          {u.id} {u.email && `· ${u.email}`}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {u.roles.length > 0 ? (
                        u.roles.map(r => <RoleBadge key={r} role={r} />)
                      ) : (
                        <span className="text-slate-400 text-xs">—</span>
                      )}
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <Badge color={u.classification === 'restricted' ? 'red' : u.classification === 'confidential' ? 'yellow' : u.classification === 'internal' ? 'blue' : 'green'}>
                      {u.classification}
                    </Badge>
                  </td>
                  <td className="px-5 py-3.5 text-slate-600 text-xs">{u.team || '—'}</td>
                  <td className="px-5 py-3.5">
                    <div className="flex gap-1">
                      {u.segments.map(s => (
                        <Badge key={s} color="green">
                          {s}
                        </Badge>
                      ))}
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                      <button
                        onClick={() => setDetail(u)}
                        className="p-1.5 text-slate-400 hover:text-axiom-700 hover:bg-axiom-50 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                        title="View"
                        aria-label={`View ${u.username}`}
                      >
                        <ChevronRight size={14} />
                      </button>
                      <button
                        onClick={() => openEdit(u)}
                        className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                        title="Edit"
                        aria-label={`Edit ${u.username}`}
                      >
                        <Edit2 size={14} />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(u)}
                        className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                        title="Delete"
                        aria-label={`Delete ${u.username}`}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Create / Edit dialog */}
      <Dialog
        open={open}
        onClose={close}
        title={editing ? `Edit ${editing.username}` : 'Add user'}
        description={editing ? `ID: ${editing.id}` : 'Create a new principal'}
      >
        <div className="space-y-4">
          {!editing && (
            <Input
              label="User ID"
              placeholder="rm_alice"
              value={uid}
              onChange={e => setUid(e.target.value)}
              required
              hint="Unique identifier, used in JWT sub claim"
            />
          )}
          <Input
            label="Username"
            value={form.username}
            onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
            disabled={!!editing}
            required
          />
          <Input
            label="Email"
            type="email"
            value={form.email}
            onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
          />
          {!editing && (
            <Input
              label="Password"
              type="password"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              required
            />
          )}
          <Select
            label="Classification"
            value={form.classification}
            onChange={e => setForm(f => ({ ...f, classification: e.target.value }))}
          >
            {classifications.length > 0 ? (
              classifications.map(c => (
                <option key={c.name} value={c.name}>
                  {c.name}
                </option>
              ))
            ) : (
              <>
                <option value="public">Public</option>
                <option value="internal">Internal</option>
                <option value="confidential">Confidential</option>
                <option value="restricted">Restricted</option>
              </>
            )}
          </Select>
          <Input
            label="Team"
            placeholder="wealth-private-banking"
            value={form.team}
            onChange={e => setForm(f => ({ ...f, team: e.target.value }))}
          />
          <Input
            label="Segments (comma-separated)"
            placeholder="wealth, servicing"
            value={form.segments.join(', ')}
            onChange={e =>
              setForm(f => ({
                ...f,
                segments: e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(Boolean),
              }))
            }
          />
          <div className="flex flex-col gap-1">
            <label className="text-sm font-medium text-slate-700">Roles</label>
            <div className="flex flex-wrap gap-2">
              {roles.map(r => (
                <label key={r.id} className="flex items-center gap-1.5 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.roleIds.includes(r.id)}
                    onChange={e =>
                      setForm(f => ({
                        ...f,
                        roleIds: e.target.checked
                          ? [...f.roleIds, r.id]
                          : f.roleIds.filter(x => x !== r.id),
                      }))
                    }
                    className="rounded border-slate-300 text-axiom-700 focus:ring-gold-300"
                  />
                  <span className="text-slate-700">{r.name}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="flex gap-2 pt-2 border-t border-slate-100">
            <Button variant="secondary" onClick={close} className="flex-1">
              Cancel
            </Button>
            <Button
              className="flex-1"
              loading={createMut.isPending || updateMut.isPending}
              onClick={() => (editing ? updateMut.mutate() : createMut.mutate())}
            >
              {editing ? 'Save changes' : 'Create user'}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Detail panel */}
      <Dialog
        open={!!detail}
        onClose={() => setDetail(null)}
        title={detailUser?.username ?? ''}
        description={`${detailUser?.id} · ${detailUser?.email}`}
        size="lg"
      >
        {detailUser && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-50 rounded-lg p-4">
                <p className="text-xs font-medium text-slate-500 mb-2">ROLES</p>
                <div className="flex flex-wrap gap-1.5">
                  {detailUser.roles.map(r => (
                    <RoleBadge key={r} role={r} />
                  ))}
                </div>
                <div className="mt-3 flex flex-wrap gap-1">
                  {roles
                    .filter(r => !detailUser.roles.includes(r.id))
                    .map(r => (
                      <button
                        key={r.id}
                        onClick={() => assignRoleMut.mutate({ userId: detailUser.id, roleId: r.id })}
                        className="text-xs px-2 py-1 border border-dashed border-slate-300 rounded text-slate-500 hover:border-axiom-400 hover:text-axiom-700 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                      >
                        + {r.id}
                      </button>
                    ))}
                </div>
              </div>
              <div className="bg-slate-50 rounded-lg p-4">
                <p className="text-xs font-medium text-slate-500 mb-2">ATTRIBUTES</p>
                <dl className="space-y-1.5 text-sm">
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Classification</dt>
                    <dd className="font-medium capitalize">{detailUser.classification}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Team</dt>
                    <dd className="font-medium">{detailUser.team || '—'}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-slate-500">Segments</dt>
                    <dd className="font-medium">
                      {detailUser.segments.join(', ') || '—'}
                    </dd>
                  </div>
                </dl>
              </div>
            </div>
          </div>
        )}
      </Dialog>

      <Dialog
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title="Delete user"
        description={deleteTarget ? `Deactivate ${deleteTarget.username}` : undefined}
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm leading-6 text-ink-600">
            This will deactivate the user and remove them from active admin workflows.
          </p>
          <div className="flex gap-2 border-t border-line pt-4">
            <Button type="button" variant="secondary" className="flex-1" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="danger"
              className="flex-1"
              loading={deleteMut.isPending}
              onClick={() => deleteTarget && deleteMut.mutate(deleteTarget.id)}
            >
              Delete
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}
