import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Boxes, Check, Clipboard, Plus, ShieldCheck, Trash2 } from 'lucide-react'
import {
  applicationsApi,
  type Application,
  type ApplicationClient,
  type ApplicationClientType,
  type ApplicationMembership,
  type ApplicationRole,
} from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { EmptyState } from '../components/ui/EmptyState'
import { Input, Textarea } from '../components/ui/Input'
import { Skeleton } from '../components/ui/Skeleton'
import { useToast } from '../components/ui/Toast'

const BROWSER_SCOPES = ['openid', 'profile', 'email', 'roles'] as const
const SERVICE_SCOPES = ['axiom.application.read'] as const
type Scope = typeof BROWSER_SCOPES[number] | typeof SERVICE_SCOPES[number]

const EMPTY_APPLICATION = { applicationKey: '', displayName: '', description: '', audience: '' }
const EMPTY_CLIENT = {
  clientId: '',
  clientType: 'PUBLIC_BROWSER' as ApplicationClientType,
  redirectUris: '',
  postLogoutRedirectUris: '',
  scopes: [...BROWSER_SCOPES] as Scope[],
}

function lines(value: string): string[] {
  return value.split(/\r?\n/).map(item => item.trim()).filter(Boolean)
}

function statusColor(status: string): 'green' | 'red' | 'slate' {
  return status === 'ACTIVE' ? 'green' : status === 'DISABLED' ? 'red' : 'slate'
}

function clientTypeLabel(type: ApplicationClientType): string {
  return type === 'PUBLIC_BROWSER' ? 'Browser' : 'Service'
}

function clientPosture(client: ApplicationClient): string {
  return client.grantTypes.length
    ? client.grantTypes.join(', ')
    : client.clientType === 'PUBLIC_BROWSER' ? 'Authorization Code' : 'Client Credentials'
}

function ClientField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium uppercase tracking-wide text-ink-500">{label}</dt>
      <dd className="mt-1 text-sm text-ink-900 break-words">{value}</dd>
    </div>
  )
}

function ClientCard({ client, onDisable, onRotate, onRevoke }: { client: ApplicationClient; onDisable: () => void; onRotate: () => void; onRevoke: () => void }) {
  return (
    <article className="surface-card p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="font-semibold text-ink-900">{client.clientId}</h3>
            <Badge color={client.clientType === 'PUBLIC_BROWSER' ? 'blue' : 'purple'}>{clientTypeLabel(client.clientType)}</Badge>
            <Badge color={statusColor(client.status)}>{client.status.toLowerCase()}</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-500">Client record revision {client.revision}</p>
        </div>
        {client.status === 'ACTIVE' && (
          <div className="flex flex-wrap justify-end gap-2">
            {client.clientType === 'CONFIDENTIAL_SERVICE' && <a href="/identity-controls" className="rounded-md border border-line px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50">Request credential change</a>}
            <a href="/identity-controls" className="rounded-md px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50" aria-label={`Request a change for ${client.clientId}`}>Request change</a>
          </div>
        )}
      </div>
      <dl className="mt-5 grid gap-4 sm:grid-cols-2">
        <ClientField label="Grant posture" value={clientPosture(client)} />
        <ClientField label="Scopes" value={client.scopes.length ? client.scopes.join(', ') : 'None reported'} />
        <ClientField label="PKCE" value={client.pkceRequired ? 'Required (S256)' : 'Not required'} />
        <ClientField label="Redirect URIs" value={client.redirectUris.length ? client.redirectUris.join(', ') : 'None'} />
        <ClientField label="Post-logout URIs" value={client.postLogoutRedirectUris.length ? client.postLogoutRedirectUris.join(', ') : 'None'} />
        <ClientField label="Created" value={client.createdAt} />
        <ClientField label="Updated" value={client.updatedAt} />
      </dl>
      <p className="mt-4 text-xs text-ink-500">
        {client.clientType === 'CONFIDENTIAL_SERVICE' ? 'Secret material is never displayed from a stored client record. A new service secret is shown only once after creation or rotation.' : 'Public browser clients have no secret actions.'}
      </p>
    </article>
  )
}

function permissionDenied(error: unknown): boolean {
  return error instanceof Error && /403|forbidden|denied|not authorized/i.test(error.message)
}

function AccessPanel({ tenantId, applicationId, applicationStatus }: { tenantId: string; applicationId: string; applicationStatus: string }) {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [selectedMembershipId, setSelectedMembershipId] = useState<string | null>(null)
  const [principalId, setPrincipalId] = useState('')
  const [assignmentSource, setAssignmentSource] = useState('admin_console')
  const [roleKey, setRoleKey] = useState('')
  const [roleName, setRoleName] = useState('')
  const [roleDescription, setRoleDescription] = useState('')
  const [rolePermissions, setRolePermissions] = useState('')
  const [attributeText, setAttributeText] = useState('')

  const rolesQuery = useQuery({
    queryKey: ['application-access-roles', tenantId, applicationId],
    queryFn: () => applicationsApi.accessRoles(tenantId, applicationId),
    retry: false,
  })
  const membershipsQuery = useQuery({
    queryKey: ['application-memberships', tenantId, applicationId],
    queryFn: () => applicationsApi.memberships(tenantId, applicationId),
    retry: false,
  })
  const memberships = membershipsQuery.data ?? []
  const selectedMembership = memberships.find(item => item.id === selectedMembershipId) ?? memberships[0]

  const refresh = () => qc.invalidateQueries({ queryKey: ['application-memberships', tenantId, applicationId] })
  const createMembership = useMutation({
    mutationFn: () => applicationsApi.createMembership(tenantId, applicationId, { principalId: principalId.trim(), assignmentSource: assignmentSource.trim() }),
    onSuccess: membership => {
      refresh()
      setSelectedMembershipId(membership.id)
      setPrincipalId('')
      toast('success', 'Membership added to this application')
    },
    onError: (error: Error) => toast('error', error.message),
  })
  const createRole = useMutation({
    mutationFn: () => applicationsApi.createRole(tenantId, applicationId, {
      roleKey: roleKey.trim(), displayName: roleName.trim(), description: roleDescription.trim(),
      permissions: rolePermissions.split(',').map(item => item.trim()).filter(Boolean),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['application-access-roles', tenantId, applicationId] })
      setRoleKey(''); setRoleName(''); setRoleDescription(''); setRolePermissions('')
      toast('success', 'Application role created')
    },
    onError: (error: Error) => toast('error', error.message),
  })
  const assignRole = useMutation({
    mutationFn: (roleId: string) => {
      if (!selectedMembership) throw new Error('Select a membership first.')
      return applicationsApi.assignRole(tenantId, applicationId, selectedMembership.id, { roleId, assignmentSource: assignmentSource.trim() })
    },
    onSuccess: () => { refresh(); toast('success', 'Role assigned in this application') },
    onError: (error: Error) => toast('error', error.message),
  })
  const revokeRole = useMutation({
    mutationFn: (roleId: string) => {
      if (!selectedMembership) throw new Error('Select a membership first.')
      return applicationsApi.revokeRole(tenantId, applicationId, selectedMembership.id, roleId)
    },
    onSuccess: () => { refresh(); toast('success', 'Role removed from this application') },
    onError: (error: Error) => toast('error', error.message),
  })
  const updateAttributes = useMutation({
    mutationFn: () => {
      if (!selectedMembership) throw new Error('Select a membership first.')
      return applicationsApi.updateAttributes(tenantId, applicationId, selectedMembership.id, JSON.parse(attributeText) as Record<string, unknown>)
    },
    onSuccess: () => { refresh(); toast('success', 'Attributes saved') },
    onError: (error: Error) => toast('error', error.message.includes('JSON') ? 'Attributes must be valid JSON.' : error.message),
  })
  const setMembershipStatus = useMutation({
    mutationFn: async () => {
      if (!selectedMembership) throw new Error('Select a membership first.')
      if (selectedMembership.status === 'ACTIVE') {
        await applicationsApi.disableMembership(tenantId, applicationId, selectedMembership.id)
      } else {
        await applicationsApi.enableMembership(tenantId, applicationId, selectedMembership.id)
      }
    },
    onSuccess: () => { refresh(); toast('success', selectedMembership.status === 'ACTIVE' ? 'Membership disabled' : 'Membership enabled') },
    onError: (error: Error) => toast('error', error.message),
  })

  function selectMembership(membership: ApplicationMembership) {
    setSelectedMembershipId(membership.id)
    setAttributeText(JSON.stringify(membership.attributes ?? {}, null, 2))
  }

  if (rolesQuery.isError || membershipsQuery.isError) {
    const error = rolesQuery.error ?? membershipsQuery.error
    return <EmptyState icon={<ShieldCheck size={36} className="text-red-300" />} title={permissionDenied(error) ? 'Access management unavailable' : 'Access data unavailable'} description={permissionDenied(error) ? 'Your signed-in role cannot manage access for this application.' : (error as Error).message} />
  }

  return (
    <div className="space-y-5">
      <div className="rounded-md border border-axiom-200 bg-axiom-50 px-4 py-3 text-sm text-axiom-900">
        Access here applies to this application only. It does not change tenant-wide roles or user identity records.
      </div>
      {applicationStatus !== 'ACTIVE' && <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">This application is disabled. Access changes are unavailable until it is active.</div>}

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(20rem,0.9fr)]">
        <section aria-label="Application memberships" className="min-w-0">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div><h3 className="font-semibold text-ink-900">Members</h3><p className="text-sm text-ink-500">People with access to this application.</p></div>
            <span className="text-xs text-ink-500">{memberships.length} listed</span>
          </div>
          {membershipsQuery.isLoading ? <Skeleton className="h-56 rounded-lg" /> : memberships.length === 0 ? <EmptyState icon={<ShieldCheck size={34} className="text-slate-300" />} title="No application members" description="Add a principal to establish the first application membership." /> : (
            <div className="overflow-x-auto rounded-lg border border-line">
              <table className="w-full text-left text-sm">
                <thead className="bg-slate-50 text-xs uppercase tracking-wide text-ink-500"><tr><th className="px-3 py-3 font-medium">Principal</th><th className="px-3 py-3 font-medium">Roles</th><th className="px-3 py-3 font-medium">State</th><th className="px-3 py-3 font-medium">Revision</th></tr></thead>
                <tbody className="divide-y divide-line bg-white">
                  {memberships.map(membership => <tr key={membership.id} className={`cursor-pointer hover:bg-axiom-50 ${selectedMembership?.id === membership.id ? 'bg-axiom-50' : ''}`} onClick={() => selectMembership(membership)}>
                    <td className="px-3 py-3 font-medium text-ink-900">{membership.principalId}</td>
                    <td className="px-3 py-3 text-ink-600">{membership.roles.length ? membership.roles.join(', ') : 'No roles'}</td>
                    <td className="px-3 py-3"><Badge color={membership.status === 'ACTIVE' ? 'green' : 'red'}>{membership.status.toLowerCase()}</Badge></td>
                    <td className="px-3 py-3 font-mono text-xs text-ink-500">{membership.entitlementRevision}</td>
                  </tr>)}
                </tbody>
              </table>
            </div>
          )}
          <details className="mt-4 rounded-lg border border-line bg-white p-4" open={memberships.length === 0}>
            <summary className="cursor-pointer text-sm font-semibold text-ink-900">Add membership</summary>
            <form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={event => { event.preventDefault(); createMembership.mutate() }}>
              <Input label="Principal ID" required value={principalId} onChange={event => setPrincipalId(event.target.value)} hint="Use an existing Axiom principal ID." />
              <Input label="Assignment source" required value={assignmentSource} onChange={event => setAssignmentSource(event.target.value)} hint="Recorded as provenance on the membership." />
              <Button type="submit" size="sm" loading={createMembership.isPending} disabled={applicationStatus !== 'ACTIVE'}>Add to application</Button>
            </form>
          </details>
        </section>

        <section aria-label="Selected membership details" className="rounded-lg border border-line bg-white p-4">
          {!selectedMembership ? <EmptyState icon={<ShieldCheck size={34} className="text-slate-300" />} title="Select a member" description="Role and attribute details will appear here." /> : <>
            <div className="flex items-start justify-between gap-3 border-b border-line pb-4"><div><h3 className="font-semibold text-ink-900">{selectedMembership.principalId}</h3><p className="mt-1 text-xs text-ink-500">Assigned by {selectedMembership.assignedBy || '—'} · source {selectedMembership.assignmentSource || '—'}</p></div><Button variant={selectedMembership.status === 'ACTIVE' ? 'danger' : 'secondary'} size="sm" loading={setMembershipStatus.isPending} disabled={applicationStatus !== 'ACTIVE'} onClick={() => setMembershipStatus.mutate()}>{selectedMembership.status === 'ACTIVE' ? 'Disable' : 'Enable'}</Button></div>
            <dl className="grid gap-3 border-b border-line py-4 sm:grid-cols-2"><ClientField label="State" value={selectedMembership.status.toLowerCase()} /><ClientField label="Entitlement revision" value={String(selectedMembership.entitlementRevision)} /><ClientField label="Created" value={selectedMembership.createdAt} /><ClientField label="Updated" value={selectedMembership.updatedAt} /></dl>
            <div className="space-y-3 border-b border-line py-4"><div><h4 className="text-sm font-semibold text-ink-900">Application roles</h4><p className="text-xs text-ink-500">These roles exist only in this application.</p></div><div className="flex flex-wrap gap-2">{selectedMembership.roles.length ? selectedMembership.roles.map(role => <span key={role} className="inline-flex items-center gap-2 rounded-full bg-axiom-50 px-2.5 py-1 text-xs text-axiom-900">{role}<button type="button" className="font-bold hover:text-red-700" aria-label={`Remove ${role}`} onClick={() => { const found = rolesQuery.data?.find(item => item.roleKey === role); if (found) revokeRole.mutate(found.id) }}>×</button></span>) : <span className="text-sm text-ink-500">No application roles assigned.</span>}</div><select className="w-full rounded-md border border-line bg-white px-3 py-2 text-sm" value="" disabled={applicationStatus !== 'ACTIVE' || rolesQuery.isLoading} onChange={event => { if (event.target.value) assignRole.mutate(event.target.value) }} aria-label="Assign application role"><option value="">Assign a role…</option>{(rolesQuery.data ?? []).filter(role => !selectedMembership.roles.includes(role.roleKey)).map(role => <option key={role.id} value={role.id}>{role.displayName} ({role.roleKey})</option>)}</select></div>
            <div className="space-y-3 pt-4"><div><h4 className="text-sm font-semibold text-ink-900">Typed attributes</h4><p className="text-xs text-ink-500">JSON values attached to this application membership.</p></div><Textarea aria-label="Membership attributes JSON" rows={5} value={attributeText || JSON.stringify(selectedMembership.attributes ?? {}, null, 2)} onChange={event => setAttributeText(event.target.value)} /><Button size="sm" loading={updateAttributes.isPending} disabled={applicationStatus !== 'ACTIVE'} onClick={() => updateAttributes.mutate()}>Save attributes</Button></div>
          </>}
        </section>
      </div>

      <details className="rounded-lg border border-line bg-white p-4">
        <summary className="cursor-pointer text-sm font-semibold text-ink-900">Application roles</summary>
        <div className="mt-4 space-y-3">{rolesQuery.data?.length ? rolesQuery.data.map((role: ApplicationRole) => <div key={role.id} className="rounded-md border border-line p-3"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium text-ink-900">{role.displayName}</span><span className="font-mono text-xs text-ink-500">{role.roleKey}</span></div><p className="mt-1 text-xs text-ink-500">{role.description || 'No description'} · {role.permissions.join(', ') || 'No permissions listed'}</p></div>) : <p className="text-sm text-ink-500">No application roles defined.</p>}<form className="grid gap-3 border-t border-line pt-4 sm:grid-cols-2" onSubmit={event => { event.preventDefault(); createRole.mutate() }}><Input label="Role key" required value={roleKey} onChange={event => setRoleKey(event.target.value)} /><Input label="Display name" required value={roleName} onChange={event => setRoleName(event.target.value)} /><Input label="Permissions" required value={rolePermissions} onChange={event => setRolePermissions(event.target.value)} hint="Comma-separated application actions." /><Input label="Description" value={roleDescription} onChange={event => setRoleDescription(event.target.value)} /><Button type="submit" size="sm" loading={createRole.isPending} disabled={applicationStatus !== 'ACTIVE'}>Create application role</Button></form></div>
      </details>
    </div>
  )
}

export function Applications() {
  const { user } = useAuth()
  const { toast } = useToast()
  const qc = useQueryClient()
  const tenantId = user?.tenantId || ''
  const [selected, setSelected] = useState<Application | null>(null)
  const [tab, setTab] = useState<'overview' | 'clients' | 'access'>('overview')
  const [applicationDialog, setApplicationDialog] = useState(false)
  const [clientDialog, setClientDialog] = useState(false)
  const [applicationForm, setApplicationForm] = useState({ ...EMPTY_APPLICATION })
  const [clientForm, setClientForm] = useState({ ...EMPTY_CLIENT })
  const [secret, setSecret] = useState<string | null>(null)
  const [secretPurpose, setSecretPurpose] = useState<'created' | 'rotated'>('created')
  const [secretCopied, setSecretCopied] = useState(false)
  const [clientActionError, setClientActionError] = useState<string | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', tenantId],
    queryFn: () => applicationsApi.list(tenantId),
    enabled: Boolean(tenantId),
  })
  const clientsQuery = useQuery({
    queryKey: ['application-clients', tenantId, selected?.id],
    queryFn: () => applicationsApi.clients(tenantId, selected!.id),
    enabled: Boolean(tenantId && selected),
  })

  const createApplication = useMutation({
    mutationFn: () => applicationsApi.create(tenantId, applicationForm),
    onSuccess: app => {
      qc.invalidateQueries({ queryKey: ['applications', tenantId] })
      setSelected(app)
      setTab('overview')
      setApplicationDialog(false)
      setApplicationForm({ ...EMPTY_APPLICATION })
      toast('success', 'Application created')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const createClient = useMutation({
    mutationFn: () => applicationsApi.createClient(tenantId, selected!.id, {
      clientId: clientForm.clientId.trim(),
      clientType: clientForm.clientType,
      scopes: clientForm.scopes,
      ...(clientForm.clientType === 'PUBLIC_BROWSER' ? {
        redirectUris: lines(clientForm.redirectUris),
        postLogoutRedirectUris: lines(clientForm.postLogoutRedirectUris),
      } : {}),
    }),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ['application-clients', tenantId, selected?.id] })
      setClientDialog(false)
      setClientForm({ ...EMPTY_CLIENT })
      setTab('clients')
      if (result.serviceSecret) {
        setSecretCopied(false)
        setSecretPurpose('created')
        setSecret(result.serviceSecret)
      }
      toast('success', 'Client created')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const disableApplication = useMutation({
    mutationFn: () => applicationsApi.disable(tenantId, selected!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['applications', tenantId] })
      setSelected(current => current ? { ...current, status: 'DISABLED' } : null)
      toast('success', 'Application disabled')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const disableClient = useMutation({
    mutationFn: (clientId: string) => applicationsApi.disableClient(tenantId, selected!.id, clientId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['application-clients', tenantId, selected?.id] })
      toast('success', 'Client disabled')
    },
    onError: (error: Error) => { setClientActionError(error.message); toast('error', error.message) },
  })

  const rotateClientSecret = useMutation({
    mutationFn: (client: ApplicationClient) => applicationsApi.rotateClientSecret(tenantId, selected!.id, client.id, client.revision),
    onSuccess: result => {
      qc.invalidateQueries({ queryKey: ['application-clients', tenantId, selected?.id] })
      setClientActionError(null)
      setSecretPurpose('rotated')
      setSecretCopied(false)
      setSecret(result.serviceSecret || null)
      toast('success', 'Confidential client secret rotated')
    },
    onError: (error: Error) => { setClientActionError(error.message); toast('error', error.message) },
  })
  const revokeClientSecret = useMutation({
    mutationFn: (client: ApplicationClient) => applicationsApi.revokeClientSecret(tenantId, selected!.id, client.id, client.revision),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['application-clients', tenantId, selected?.id] })
      setClientActionError(null)
      toast('success', 'Confidential client credential revoked')
    },
    onError: (error: Error) => { setClientActionError(error.message); toast('error', error.message) },
  })

  function openApplication(app: Application) {
    setSelected(app)
    setTab('overview')
  }

  function requestDisableApplication() {
    if (selected && window.confirm(`Disable application “${selected.displayName}”? New authentication and tokens should fail closed.`)) {
      disableApplication.mutate()
    }
  }

  function requestDisableClient(client: ApplicationClient) {
    if (window.confirm(`Disable client “${client.clientId}”? This cannot be undone from this screen.`)) {
      disableClient.mutate(client.id)
    }
  }

  function requestRotateClient(client: ApplicationClient) {
    setClientActionError(null)
    if (window.confirm(`Rotate the credential for “${client.clientId}”? The current credential will be replaced and the new plaintext will be shown once.`)) {
      rotateClientSecret.mutate(client)
    }
  }

  function requestRevokeClient(client: ApplicationClient) {
    setClientActionError(null)
    if (window.confirm(`Revoke the credential for “${client.clientId}”? Authentication for this confidential client will fail immediately.`)) {
      revokeClientSecret.mutate(client)
    }
  }

  function selectClientType(clientType: ApplicationClientType) {
    setClientForm(form => ({
      ...form,
      clientType,
      scopes: clientType === 'PUBLIC_BROWSER' ? [...BROWSER_SCOPES] : [...SERVICE_SCOPES],
      redirectUris: '',
      postLogoutRedirectUris: '',
    }))
  }

  async function copySecret() {
    if (!secret) return
    await navigator.clipboard.writeText(secret)
    setSecretCopied(true)
  }

  const applications = applicationsQuery.data ?? []
  const clients = clientsQuery.data ?? []

  return (
    <div className="px-8 py-8">
      <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-axiom-700">Identity administration</p>
          <h1 className="text-2xl font-bold text-ink-900">Applications</h1>
          <p className="text-sm text-ink-500 mt-1">Tenant applications and their browser or service entry points.</p>
        </div>
        <Button onClick={() => setApplicationDialog(true)}><Plus size={15} /> New application</Button>
      </div>

      {!tenantId ? (
        <EmptyState icon={<ShieldCheck size={40} className="text-slate-300" />} title="Tenant context unavailable" description="Applications cannot be loaded without an authenticated tenant context." />
      ) : applicationsQuery.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[1, 2, 3].map(item => <Skeleton key={item} className="h-40 rounded-lg" />)}</div>
      ) : applicationsQuery.isError ? (
        <EmptyState icon={<Boxes size={40} className="text-red-300" />} title="Applications unavailable" description={applicationsQuery.error.message} />
      ) : applications.length === 0 ? (
        <EmptyState icon={<Boxes size={40} className="text-slate-300" />} title="No applications yet" description="Register an application to give a product its own tenant-scoped identity boundary." action={{ label: 'New application', onClick: () => setApplicationDialog(true) }} />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)]">
          <section aria-label="Applications list" className="space-y-3">
            {applications.map(app => (
              <button key={app.id} type="button" onClick={() => openApplication(app)} className={`w-full text-left surface-card p-5 transition-colors ${selected?.id === app.id ? 'border-axiom-700 ring-2 ring-gold-300/60' : 'hover:border-axiom-300'}`}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h2 className="font-semibold text-ink-900">{app.displayName}</h2>
                    <p className="mt-1 text-xs font-mono text-ink-500">{app.applicationKey}</p>
                  </div>
                  <Badge color={statusColor(app.status)}>{app.status.toLowerCase()}</Badge>
                </div>
                <p className="mt-4 text-xs text-ink-500">Audience <span className="font-mono text-ink-700">{app.audience}</span></p>
                <div className="mt-3 flex flex-wrap gap-2 text-xs text-ink-500">
                  <span>Open to inspect clients</span><span>Revision {app.revision}</span>
                </div>
                <p className="mt-2 text-xs text-ink-500">Last change: {app.updatedAt}</p>
              </button>
            ))}
          </section>

          {selected ? (
            <section className="surface-card min-h-[32rem]">
              <div className="border-b border-line px-6 pt-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div><h2 className="text-xl font-bold text-ink-900">{selected.displayName}</h2><p className="mt-1 font-mono text-xs text-ink-500">{selected.applicationKey} · {selected.audience}</p></div>
                  {selected.status === 'ACTIVE' && <a href="/identity-controls" className="rounded-md border border-line px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50">Request application change</a>}
                </div>
                <div className="mt-6 flex gap-5">
                  {(['overview', 'clients', 'access'] as const).map(item => <button key={item} type="button" onClick={() => setTab(item)} className={`border-b-2 px-1 pb-3 text-sm font-medium capitalize ${tab === item ? 'border-gold-500 text-axiom-900' : 'border-transparent text-ink-500 hover:text-ink-900'}`}>{item === 'access' ? 'Access' : item}</button>)}
                </div>
              </div>
              <div className="p-6">
                {tab === 'overview' ? (
                  <div className="space-y-5">
                    <div><p className="text-xs font-semibold uppercase tracking-wide text-ink-500">Application posture</p><p className="mt-2 text-sm text-ink-700">{selected.description || 'No description provided.'}</p></div>
                    <dl className="grid gap-5 sm:grid-cols-2"><ClientField label="State" value={selected.status.toLowerCase()} /><ClientField label="Audience" value={selected.audience} /><ClientField label="Configuration revision" value={String(selected.revision)} /><ClientField label="Created" value={selected.createdAt} /><ClientField label="Last change" value={selected.updatedAt} /></dl>
                    <div className="rounded-md border border-axiom-200 bg-axiom-50 p-4 text-sm text-axiom-900">Use the Access tab to manage this application’s members, application-scoped roles, and typed membership attributes.</div>
                  </div>
                ) : tab === 'clients' ? (
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="font-semibold text-ink-900">Clients</h3><p className="text-sm text-ink-500">OAuth/OIDC entry points owned by this application.</p></div><Button size="sm" onClick={() => setClientDialog(true)} disabled={selected.status !== 'ACTIVE'}><Plus size={14} /> New client</Button></div>
                    {clientActionError && <div role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">{clientActionError}</div>}
                    {clientsQuery.isLoading ? <Skeleton className="h-48 rounded-lg" /> : clientsQuery.isError ? <EmptyState icon={<ShieldCheck size={36} className="text-red-300" />} title="Clients unavailable" description={clientsQuery.error.message} /> : clients.length === 0 ? <EmptyState icon={<ShieldCheck size={36} className="text-slate-300" />} title="No clients yet" description="Add a browser or service client to this application." action={{ label: 'New client', onClick: () => setClientDialog(true) }} /> : clients.map(client => <ClientCard key={client.id} client={client} onDisable={() => requestDisableClient(client)} onRotate={() => requestRotateClient(client)} onRevoke={() => requestRevokeClient(client)} />)}
                  </div>
                ) : (
                  <AccessPanel tenantId={tenantId} applicationId={selected.id} applicationStatus={selected.status} />
                )}
              </div>
            </section>
          ) : <EmptyState icon={<Boxes size={40} className="text-slate-300" />} title="Select an application" description="Open an application to inspect its posture and clients." />}
        </div>
      )}

      <Dialog open={applicationDialog} onClose={() => setApplicationDialog(false)} title="New application" description="Create a tenant-scoped identity boundary.">
        <form className="space-y-4" onSubmit={event => { event.preventDefault(); createApplication.mutate() }}>
          <Input label="Display name" required value={applicationForm.displayName} onChange={event => setApplicationForm(form => ({ ...form, displayName: event.target.value }))} />
          <Input label="Application key" required pattern="[a-z][a-z0-9-]{1,62}" hint="Lowercase letters, numbers, and hyphens." value={applicationForm.applicationKey} onChange={event => setApplicationForm(form => ({ ...form, applicationKey: event.target.value }))} />
          <Input label="Audience" required pattern="[a-z][a-z0-9.-]{1,127}" hint="The server-derived resource audience." value={applicationForm.audience} onChange={event => setApplicationForm(form => ({ ...form, audience: event.target.value }))} />
          <Textarea label="Description" rows={3} value={applicationForm.description} onChange={event => setApplicationForm(form => ({ ...form, description: event.target.value }))} />
          <div className="flex justify-end gap-2 pt-2"><Button type="button" variant="secondary" onClick={() => setApplicationDialog(false)}>Cancel</Button><Button type="submit" loading={createApplication.isPending}>Create application</Button></div>
        </form>
      </Dialog>

      <Dialog open={clientDialog} onClose={() => setClientDialog(false)} title="New client" description="Choose a fixed OAuth posture; the server remains authoritative.">
        <form className="space-y-4" onSubmit={event => { event.preventDefault(); createClient.mutate() }}>
          <Input label="Client ID" required pattern="[a-z][a-z0-9-]{1,98}" value={clientForm.clientId} onChange={event => setClientForm(form => ({ ...form, clientId: event.target.value }))} />
          <div className="flex flex-col gap-2"><span className="text-sm font-medium text-ink-700">Client type</span><div className="grid grid-cols-2 gap-2">{(['PUBLIC_BROWSER', 'CONFIDENTIAL_SERVICE'] as const).map(type => <button key={type} type="button" className={`rounded-md border p-3 text-left ${clientForm.clientType === type ? 'border-axiom-700 bg-axiom-50' : 'border-line'}`} onClick={() => selectClientType(type)}><span className="block text-sm font-medium text-ink-900">{clientTypeLabel(type)}</span><span className="mt-1 block text-xs text-ink-500">{type === 'PUBLIC_BROWSER' ? 'Authorization Code + S256 PKCE' : 'Client Credentials + one-time secret'}</span></button>)}</div></div>
          {clientForm.clientType === 'PUBLIC_BROWSER' && <><Textarea label="Exact redirect URIs" required rows={3} hint="One exact URI per line; HTTPS is required in production." value={clientForm.redirectUris} onChange={event => setClientForm(form => ({ ...form, redirectUris: event.target.value }))} /><Textarea label="Exact post-logout URIs" rows={2} hint="One exact URI per line." value={clientForm.postLogoutRedirectUris} onChange={event => setClientForm(form => ({ ...form, postLogoutRedirectUris: event.target.value }))} /></>}
          <fieldset><legend className="text-sm font-medium text-ink-700">Approved scopes</legend><div className="mt-2 flex flex-wrap gap-3">{(clientForm.clientType === 'PUBLIC_BROWSER' ? BROWSER_SCOPES : SERVICE_SCOPES).map(scope => <label key={scope} className="flex items-center gap-2 text-sm text-ink-700"><input type="checkbox" checked={clientForm.scopes.includes(scope)} onChange={event => setClientForm(form => ({ ...form, scopes: event.target.checked ? [...form.scopes, scope] : form.scopes.filter(item => item !== scope) }))} /> {scope}</label>)}</div></fieldset>
          {clientForm.clientType === 'CONFIDENTIAL_SERVICE' && <p className="rounded-md border border-gold-200 bg-gold-50 p-3 text-sm text-gold-900">The generated service secret will be shown exactly once after creation. It is not recoverable from Axiom.</p>}
          <div className="flex justify-end gap-2 pt-2"><Button type="button" variant="secondary" onClick={() => setClientDialog(false)}>Cancel</Button><Button type="submit" loading={createClient.isPending}>Create client</Button></div>
        </form>
      </Dialog>

      <Dialog open={Boolean(secret)} onClose={() => { setSecret(null); setSecretCopied(false) }} title={`Service secret ${secretPurpose} — show once`} description="Copy this secret now. Axiom will not display it again.">
        <div className="space-y-4"><p className="text-sm text-red-800">Treat this value like a password. Do not paste it into source control, tickets, or chat.</p><div className="rounded-md border border-line bg-slate-50 p-3 font-mono text-sm break-all select-all">{secret}</div><div className="flex justify-end gap-2"><Button variant="secondary" onClick={() => { setSecret(null); setSecretCopied(false) }}>I stored it securely</Button><Button onClick={() => void copySecret()}>{secretCopied ? <Check size={14} /> : <Clipboard size={14} />}{secretCopied ? 'Copied' : 'Copy secret'}</Button></div></div>
      </Dialog>
    </div>
  )
}
