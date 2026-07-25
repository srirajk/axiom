import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Edit2, Shield, X } from 'lucide-react'
import { rolesApi, type Role } from '../api/client'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Dialog } from '../components/ui/Dialog'
import { Skeleton } from '../components/ui/Skeleton'
import { EmptyState } from '../components/ui/EmptyState'
import { useToast } from '../components/ui/Toast'

const EMPTY: Role = {
  id: '',
  name: '',
  description: '',
  permissions: [],
}

function SkeletonRow() {
  return (
    <tr className="border-b border-slate-100">
      <td className="px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Skeleton className="w-7 h-7 rounded-md" />
          <div className="flex-1">
            <Skeleton className="h-4 w-32 mb-1" />
            <Skeleton className="h-3 w-24" />
          </div>
        </div>
      </td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-48" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-32" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-16" /></td>
      <td className="px-5 py-3.5"><Skeleton className="h-4 w-12" /></td>
    </tr>
  )
}

export function Roles() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [editing, setEdit] = useState<Role | null>(null)
  const [form, setForm] = useState<Role>({ ...EMPTY })
  const [permInput, setPermInput] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<Role | null>(null)

  const { data: roles = [], isLoading } = useQuery({
    queryKey: ['roles'],
    queryFn: rolesApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => rolesApi.create(form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles'] })
      close()
      toast('success', 'Role created')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const updateMut = useMutation({
    mutationFn: () => rolesApi.update(editing!.id, form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles'] })
      close()
      toast('success', 'Role updated')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => rolesApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['roles'] })
      setDeleteTarget(null)
      toast('success', 'Role deleted')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  function openCreate() {
    setEdit(null)
    setForm({ ...EMPTY })
    setPermInput('')
    setOpen(true)
  }
  function openEdit(r: Role) {
    setEdit(r)
    setForm({ ...r })
    setPermInput('')
    setOpen(true)
  }
  function close() {
    setOpen(false)
    setEdit(null)
  }

  function addPerm() {
    const p = permInput.trim()
    if (p && !form.permissions.includes(p)) {
      setForm(f => ({ ...f, permissions: [...f.permissions, p] }))
    }
    setPermInput('')
  }

  return (
    <div className="px-8 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Roles</h1>
          <p className="text-sm text-slate-500 mt-1">
            {roles.length} role{roles.length !== 1 ? 's' : ''} defined
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus size={15} /> New role
        </Button>
      </div>

      <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
        {isLoading ? (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['Role', 'Description', 'Permissions', ''].map(h => (
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
        ) : roles.length === 0 ? (
          <EmptyState
            icon={<Shield size={40} className="text-slate-300" />}
            title="No roles defined"
            description="Create your first role to get started"
            action={{ label: 'New role', onClick: openCreate }}
          />
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['Role', 'Description', 'Permissions', ''].map(h => (
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
              {roles.map(r => (
                <tr key={r.id} className="hover:bg-slate-50 transition-colors group">
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-md bg-emerald-50 flex items-center justify-center">
                        <Shield size={13} className="text-emerald-600" />
                      </div>
                      <div>
                        <p className="font-medium text-slate-900">{r.name}</p>
                        <p className="text-xs font-mono text-slate-500">{r.id}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3.5 text-slate-500 text-xs max-w-[200px] truncate">
                    {r.description || '—'}
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex flex-wrap gap-1">
                      {r.permissions.length > 0
                        ? r.permissions.slice(0, 3).map(p => (
                            <Badge key={p} color="slate">
                              {p}
                            </Badge>
                          ))
                        : <span className="text-slate-400 text-xs">—</span>}
                      {r.permissions.length > 3 && (
                        <Badge color="slate">+{r.permissions.length - 3}</Badge>
                      )}
                    </div>
                  </td>
                  <td className="px-5 py-3.5">
                    <div className="flex gap-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                      <button
                        onClick={() => openEdit(r)}
                        aria-label={`Edit ${r.name}`}
                        className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                      >
                        <Edit2 size={14} />
                      </button>
                      <button
                        onClick={() => setDeleteTarget(r)}
                        aria-label={`Delete ${r.name}`}
                        className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
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

      <Dialog open={open} onClose={close} title={editing ? `Edit ${editing.name}` : 'New role'}>
        <div className="space-y-4">
          <Input
            label="Name"
                placeholder="Platform policy steward"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            required
          />
          <Input
            label="Description"
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
          />
          <div className="flex flex-col gap-1">
            <label className="text-sm font-medium text-slate-700">Permissions</label>
            <div className="flex gap-2">
              <input
                className="flex-1 px-3 py-2 text-sm border border-line rounded-md focus:outline-none focus:ring-2 focus:ring-gold-300 focus:border-axiom-700"
                placeholder="platform:read"
                value={permInput}
                onChange={e => setPermInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addPerm())}
              />
              <Button size="sm" variant="secondary" onClick={addPerm}>
                Add
              </Button>
            </div>
            <div className="flex flex-wrap gap-1.5 mt-1">
              {form.permissions.map(p => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 text-slate-700 text-xs rounded-full"
                >
                  {p}
                  <button
                    type="button"
                    aria-label={`Remove ${p}`}
                    onClick={() =>
                      setForm(f => ({
                        ...f,
                        permissions: f.permissions.filter(x => x !== p),
                      }))
                    }
                    className="text-slate-400 hover:text-slate-700"
                  >
                    <X size={11} />
                  </button>
                </span>
              ))}
            </div>
            <p className="text-xs text-slate-500">
              Press Enter to add. These are descriptive labels — Cerbos policies enforce the
              actual access.
            </p>
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
              {editing ? 'Save changes' : 'Create role'}
            </Button>
          </div>
        </div>
      </Dialog>

      <Dialog
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title="Delete role"
        description={deleteTarget ? `Remove ${deleteTarget.name}` : undefined}
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm leading-6 text-ink-600">
            This removes the role definition. Existing policy references should be reviewed before proceeding.
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
