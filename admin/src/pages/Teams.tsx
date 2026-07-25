import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Edit2, Users } from 'lucide-react'
import { teamsApi, usersApi, type Team } from '../api/client'
import { Button } from '../components/ui/Button'
import { Input, Select } from '../components/ui/Input'
import { Badge } from '../components/ui/Badge'
import { Dialog } from '../components/ui/Dialog'
import { Skeleton } from '../components/ui/Skeleton'
import { EmptyState } from '../components/ui/EmptyState'
import { useToast } from '../components/ui/Toast'

const EMPTY: Omit<Team, 'memberCount' | 'members'> = {
  id: '',
  name: '',
  description: '',
  defaultRoles: [],
  segments: [],
  allowedDomains: [],
}

function SkeletonCard() {
  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5">
      <div className="flex items-start justify-between mb-3">
        <Skeleton className="w-9 h-9 rounded-lg" />
        <div className="flex gap-1">
          <Skeleton className="w-8 h-8 rounded-md" />
          <Skeleton className="w-8 h-8 rounded-md" />
        </div>
      </div>
      <Skeleton className="h-5 w-32 mb-2" />
      <Skeleton className="h-3 w-48 mb-3" />
      <div className="flex gap-2 mb-3">
        <Skeleton className="h-6 w-16 rounded-full" />
        <Skeleton className="h-6 w-20 rounded-full" />
      </div>
      <Skeleton className="h-4 w-24" />
    </div>
  )
}

export function Teams() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const [open, setOpen] = useState(false)
  const [editing, setEdit] = useState<Team | null>(null)
  const [form, setForm] = useState({ ...EMPTY })
  const [detail, setDetail] = useState<Team | null>(null)
  const [addMember, setAddMember] = useState('')
  const [deleteTarget, setDeleteTarget] = useState<Team | null>(null)

  const { data: teams = [], isLoading } = useQuery({
    queryKey: ['teams'],
    queryFn: teamsApi.list,
  })
  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: usersApi.list,
  })
  const { data: teamDetail } = useQuery({
    queryKey: ['team', detail?.id],
    queryFn: () => teamsApi.get(detail!.id),
    enabled: !!detail,
  })

  const createMut = useMutation({
    mutationFn: () => teamsApi.create(form as Omit<Team, 'memberCount'>),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['teams'] })
      close()
      toast('success', 'Team created')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const updateMut = useMutation({
    mutationFn: () =>
      teamsApi.update(editing!.id, {
        ...form,
        id: editing!.id,
      } as Omit<Team, 'id' | 'memberCount'>),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['teams'] })
      close()
      toast('success', 'Team updated')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => teamsApi.delete(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['teams'] })
      setDeleteTarget(null)
      toast('success', 'Team deleted')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const addMemberMut = useMutation({
    mutationFn: ({ teamId, userId }: { teamId: string; userId: string }) =>
      teamsApi.addMember(teamId, userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['team', detail?.id] })
      qc.invalidateQueries({ queryKey: ['teams'] })
      setAddMember('')
      toast('success', 'Member added')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  const removeMemberMut = useMutation({
    mutationFn: ({ teamId, userId }: { teamId: string; userId: string }) =>
      teamsApi.removeMember(teamId, userId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['team', detail?.id] })
      qc.invalidateQueries({ queryKey: ['teams'] })
      toast('success', 'Member removed')
    },
    onError: (e: Error) => toast('error', e.message),
  })

  function openCreate() {
    setEdit(null)
    setForm({ ...EMPTY })
    setOpen(true)
  }
  function openEdit(t: Team) {
    setEdit(t)
    setForm({
      id: t.domainId || '',
      name: t.name,
      description: t.description,
      defaultRoles: t.defaultRoles,
      segments: t.segments,
      allowedDomains: t.allowedDomains,
    })
    setOpen(true)
  }
  function close() {
    setOpen(false)
    setEdit(null)
  }
  const isDomainBacked = (team: Team) => Boolean(team.domainId?.trim())

  return (
    <div className="px-8 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Teams</h1>
          <p className="text-sm text-slate-500 mt-1">
            {teams.length} team{teams.length !== 1 ? 's' : ''}
          </p>
        </div>
        <Button onClick={openCreate}>
          <Plus size={15} /> New team
        </Button>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      ) : teams.length === 0 ? (
        <EmptyState
          icon={<Users size={40} className="text-slate-300" />}
          title="No teams yet"
          description="Create a team to group users and assign default roles"
          action={{ label: 'New team', onClick: openCreate }}
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {teams.map(t => (
            <div key={t.id} className="bg-white rounded-lg border border-slate-200 p-5 hover:border-slate-300 transition-colors group">
              <div className="flex items-start justify-between mb-3">
                <div className="w-9 h-9 rounded-lg bg-axiom-50 flex items-center justify-center ring-1 ring-axiom-600/10">
                  <Users size={16} className="text-axiom-700" />
                </div>
                <div className="flex gap-1 opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100">
                  <button
                    onClick={() => openEdit(t)}
                    aria-label={`Edit ${t.name}`}
                    className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                  >
                    <Edit2 size={13} />
                  </button>
                  <button
                    onClick={() => setDeleteTarget(t)}
                    aria-label={`Delete ${t.name}`}
                    className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded-md transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>
              <h3 className="font-semibold text-slate-900 mb-0.5">{t.name}</h3>
              <p className="text-xs text-slate-500 mb-3 line-clamp-2">
                {t.description || 'No description'}
              </p>
              <div className="flex flex-wrap gap-1 mb-3">
                {(t.segments ?? []).map(s => (
                  <Badge key={s} color="green">
                    {s}
                  </Badge>
                ))}
                {(t.defaultRoles ?? []).map(r => (
                  <Badge key={r} color="blue">
                    {r}
                  </Badge>
                ))}
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500">
                  {t.memberCount ?? 0} {isDomainBacked(t) ? 'domain assignment' : 'member'}
                  {(t.memberCount ?? 0) !== 1 ? 's' : ''}
                </span>
                <button
                  onClick={() => setDetail(t)}
                  className="text-xs text-axiom-700 hover:underline font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300 rounded"
                >
                  {isDomainBacked(t) ? 'View assignments →' : 'Manage →'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit dialog */}
      <Dialog
        open={open}
        onClose={close}
        title={editing ? `Edit ${editing.name}` : 'New team'}
      >
        <div className="space-y-4">
          {!editing && (
            <Input
              label="Domain ID"
              placeholder="wealth-private-banking"
              value={form.id}
              onChange={e => setForm(f => ({ ...f, id: e.target.value }))}
              hint="Optional domain association"
            />
          )}
          <Input
            label="Name"
            placeholder="Wealth Private Banking"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            required
          />
          <Input
            label="Description"
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
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
          <Input
            label="Default roles (comma-separated)"
            placeholder="platform_policy_steward"
            value={(form.defaultRoles ?? []).join(', ')}
            onChange={e =>
              setForm(f => ({
                ...f,
                defaultRoles: e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(Boolean),
              }))
            }
            hint="New members inherit these roles automatically"
          />
          <Input
            label="Allowed domains (comma-separated)"
            placeholder="wealth-private-banking"
            value={(form.allowedDomains ?? []).join(', ')}
            onChange={e =>
              setForm(f => ({
                ...f,
                allowedDomains: e.target.value
                  .split(',')
                  .map(s => s.trim())
                  .filter(Boolean),
              }))
            }
          />
          <div className="flex gap-2 pt-2 border-t border-slate-100">
            <Button variant="secondary" onClick={close} className="flex-1">
              Cancel
            </Button>
            <Button
              className="flex-1"
              loading={createMut.isPending || updateMut.isPending}
              onClick={() => (editing ? updateMut.mutate() : createMut.mutate())}
            >
              {editing ? 'Save changes' : 'Create team'}
            </Button>
          </div>
        </div>
      </Dialog>

      {/* Team detail / members */}
      <Dialog
        open={!!detail}
        onClose={() => setDetail(null)}
        title={teamDetail?.name ?? detail?.name ?? ''}
        description={teamDetail && isDomainBacked(teamDetail) ? 'Live domain assignments' : 'Members'}
        size="md"
      >
        {teamDetail && (
          <div className="space-y-4">
            {!isDomainBacked(teamDetail) && <div className="flex gap-2">
              <div className="flex-1">
                <Select
                  aria-label="User to add"
                  value={addMember}
                  onChange={e => setAddMember(e.target.value)}
                >
                  <option value="">Select a user to add…</option>
                  {users
                    .filter(u => !teamDetail.members?.some(m => m.id === u.id))
                    .map(u => (
                      <option key={u.id} value={u.id}>
                        {u.username} ({u.id})
                      </option>
                    ))}
                </Select>
              </div>
              <Button
                size="sm"
                disabled={!addMember}
                loading={addMemberMut.isPending}
                onClick={() =>
                  addMemberMut.mutate({
                    teamId: teamDetail.id,
                    userId: addMember,
                  })
                }
              >
                Add
              </Button>
            </div>}

            {isDomainBacked(teamDetail) && (
              <p className="text-sm text-slate-500">
                These assignments determine live domain scope and are managed through domain administration.
              </p>
            )}

            {teamDetail.members?.length === 0 ? (
              <EmptyState
                icon={<Users size={32} className="text-slate-300" />}
                title={isDomainBacked(teamDetail) ? 'No domain assignments' : 'No members yet'}
                description={isDomainBacked(teamDetail)
                  ? 'No principal currently has this domain assignment.'
                  : 'Add team members from the selector above'}
              />
            ) : (
              <div className="divide-y divide-slate-100">
                {teamDetail.members?.map(m => (
                  <div key={m.id} className="flex items-center justify-between py-2.5 group">
                    <div className="flex items-center gap-2.5">
                      <div className="w-7 h-7 rounded-full bg-axiom-50 flex items-center justify-center">
                        <span className="text-axiom-700 text-xs font-semibold">
                          {m.name.charAt(0)}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-slate-900">{m.name}</p>
                        <p className="text-xs text-slate-500">{m.id}</p>
                      </div>
                    </div>
                    {!isDomainBacked(teamDetail) && <button
                      onClick={() =>
                        removeMemberMut.mutate({
                          teamId: teamDetail.id,
                          userId: m.id,
                        })
                      }
                      className="opacity-0 transition-opacity group-hover:opacity-100 group-focus-within:opacity-100 text-xs text-red-500 hover:text-red-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gold-300 rounded"
                    >
                      Remove
                    </button>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </Dialog>

      <Dialog
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title="Delete team"
        description={deleteTarget ? `Remove ${deleteTarget.name}` : undefined}
        size="sm"
      >
        <div className="space-y-4">
          <p className="text-sm leading-6 text-ink-600">
            This removes the team grouping. User accounts remain active.
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
