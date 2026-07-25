import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Globe2, KeyRound, Link2, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'
import {
  identitySourcesApi,
  type ExternalIdentityLink,
  type IdentitySource,
  type IdentitySourceStatus,
  type IdentitySourceValidation,
} from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { EmptyState } from '../components/ui/EmptyState'
import { Input, Textarea } from '../components/ui/Input'
import { Skeleton } from '../components/ui/Skeleton'
import { useToast } from '../components/ui/Toast'

const EMPTY_SOURCE = {
  displayName: '', issuer: '', discoveryUri: '', clientId: '', clientSecret: '',
  requestedScopes: 'openid, profile, email',
  allowedSigningAlgorithms: 'RS256',
  requiredClaims: 'sub, iss, aud, exp, iat, nonce',
  requiredAcrValues: '',
}

function csv(value: string): string[] {
  return value.split(',').map(item => item.trim()).filter(Boolean)
}

function statusColor(status: IdentitySourceStatus): 'green' | 'red' | 'yellow' | 'slate' {
  if (status === 'ACTIVE') return 'green'
  if (status === 'DISABLED') return 'red'
  if (status === 'DRAFT') return 'yellow'
  return 'slate'
}

function denied(error: unknown): boolean {
  return error instanceof Error && /403|forbidden|denied|not authorized/i.test(error.message)
}

function Info({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs font-medium uppercase tracking-wide text-ink-500">{label}</dt><dd className="mt-1 break-words text-sm text-ink-900">{value || '—'}</dd></div>
}

function SourceDetails({ source, tenantId, onChanged }: { source: IdentitySource; tenantId: string; onChanged: () => void }) {
  const { toast } = useToast()
  const [validation, setValidation] = useState<IdentitySourceValidation | null>(null)
  const [rotateOpen, setRotateOpen] = useState(false)
  const [newSecret, setNewSecret] = useState('')
  const [rotateConfirmed, setRotateConfirmed] = useState(false)
  const [linkForm, setLinkForm] = useState({ issuer: source.issuer, subject: '', principalId: '' })
  const qc = useQueryClient()
  const linksQuery = useQuery({
    queryKey: ['identity-source-links', tenantId, source.id],
    queryFn: () => identitySourcesApi.links(tenantId, source.id),
    retry: false,
  })

  const validate = useMutation({
    mutationFn: () => identitySourcesApi.validate(tenantId, source.id),
    onSuccess: result => { setValidation(result); onChanged(); toast('success', 'Customer identity provider validated') },
    onError: (error: Error) => toast('error', error.message),
  })
  const activate = useMutation({
    mutationFn: () => identitySourcesApi.activate(tenantId, source.id),
    onSuccess: () => { onChanged(); toast('success', 'Customer identity source activated') },
    onError: (error: Error) => toast('error', error.message),
  })
  const disable = useMutation({
    mutationFn: () => identitySourcesApi.disable(tenantId, source.id),
    onSuccess: () => { onChanged(); toast('success', 'Customer identity source disabled') },
    onError: (error: Error) => toast('error', error.message),
  })
  const rotate = useMutation({
    mutationFn: () => identitySourcesApi.rotateSecret(tenantId, source.id, newSecret),
    onSuccess: () => { setRotateOpen(false); setNewSecret(''); setRotateConfirmed(false); onChanged(); toast('success', 'Client secret rotated') },
    onError: (error: Error) => toast('error', error.message),
  })
  const createLink = useMutation({
    mutationFn: () => identitySourcesApi.createLink(tenantId, source.id, linkForm),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['identity-source-links', tenantId, source.id] })
      setLinkForm({ issuer: source.issuer, subject: '', principalId: '' })
      toast('success', 'External identity linked to the Axiom principal')
    },
    onError: (error: Error) => toast('error', error.message),
  })
  const disableLink = useMutation({
    mutationFn: (linkId: string) => identitySourcesApi.disableLink(tenantId, source.id, linkId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['identity-source-links', tenantId, source.id] }); toast('success', 'External identity link disabled') },
    onError: (error: Error) => toast('error', error.message),
  })

  const links = linksQuery.data ?? []
  const validationState = validation ?? (source.lastValidatedAt ? { issuer: source.issuer } as IdentitySourceValidation : null)

  return <div className="space-y-5">
    <div className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
      <div><div className="flex flex-wrap items-center gap-2"><h2 className="text-xl font-bold text-ink-900">{source.displayName}</h2><Badge color={statusColor(source.status)}>{source.status.toLowerCase()}</Badge></div><p className="mt-1 break-all font-mono text-xs text-ink-500">{source.issuer}</p></div>
      <div className="flex flex-wrap gap-2">
        <Button variant="secondary" size="sm" loading={validate.isPending} onClick={() => validate.mutate()}><RefreshCw size={14} /> Validate</Button>
        {source.status !== 'ACTIVE' && <a href="/identity-controls" className="rounded-md border border-line px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50">Use Identity Controls for activation</a>}
        {source.status === 'ACTIVE' && <a href="/identity-controls" className="rounded-md border border-line px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50">Request source change</a>}
      </div>
    </div>

    <div className="rounded-md border border-axiom-200 bg-axiom-50 px-4 py-3 text-sm text-axiom-900">This source authenticates customer identities. Axiom links an exact provider issuer and subject to an existing local principal; it never creates a principal automatically.</div>

    <div className="grid gap-5 lg:grid-cols-2">
      <section className="surface-card p-5"><h3 className="font-semibold text-ink-900">Provider configuration</h3><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Info label="Issuer" value={source.issuer} /><Info label="Discovery URI" value={source.discoveryUri} /><Info label="Client ID" value={source.clientId} /><Info label="Revision" value={String(source.revision)} /><Info label="Authorization endpoint" value={source.authorizationEndpoint} /><Info label="Token endpoint" value={source.tokenEndpoint} /><Info label="Userinfo endpoint" value={source.userinfoEndpoint} /><Info label="JWKS endpoint" value={source.jwksUri} /></dl></section>
      <section className="surface-card p-5"><div className="flex items-center justify-between gap-3"><h3 className="font-semibold text-ink-900">Validation and requirements</h3><Badge color={validationState ? 'green' : 'slate'}>{validationState ? 'validated' : 'not validated'}</Badge></div><dl className="mt-4 grid gap-4 sm:grid-cols-2"><Info label="Last validated" value={source.lastValidatedAt || 'Not yet validated'} /><Info label="Requested scopes" value={source.requestedScopes.join(', ')} /><Info label="Allowed algorithms" value={source.allowedSigningAlgorithms.join(', ')} /><Info label="Required claims" value={source.requiredClaims.join(', ')} /><Info label="Required ACR values" value={source.requiredAcrValues.join(', ')} /></dl>{validation && <p className="mt-4 text-xs text-emerald-800">Discovery confirms {validation.supportedSigningAlgorithms.join(', ') || 'no listed signing algorithms'} and {validation.supportedClaims.length} supported claims.</p>}</section>
    </div>

    <section className="surface-card p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h3 className="font-semibold text-ink-900">External identity links</h3><p className="mt-1 text-sm text-ink-500">Exact issuer + subject links to existing Axiom principals.</p></div><span className="text-xs text-ink-500">{links.length} listed</span></div>{linksQuery.isError ? <EmptyState icon={<Link2 size={34} className="text-red-300" />} title={denied(linksQuery.error) ? 'Links unavailable' : 'Could not load links'} description={denied(linksQuery.error) ? 'Your signed-in role cannot view links for this source.' : (linksQuery.error as Error).message} /> : linksQuery.isLoading ? <Skeleton className="mt-4 h-40 rounded-lg" /> : links.length === 0 ? <EmptyState icon={<Link2 size={34} className="text-slate-300" />} title="No linked identities" description="Create an exact link to let a known customer identity sign in as an existing principal." /> : <div className="mt-4 overflow-x-auto rounded-lg border border-line"><table className="w-full text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-ink-500"><tr><th className="px-3 py-3 font-medium">Subject</th><th className="px-3 py-3 font-medium">Axiom principal</th><th className="px-3 py-3 font-medium">State</th><th className="px-3 py-3 font-medium">Action</th></tr></thead><tbody className="divide-y divide-line">{links.map((link: ExternalIdentityLink) => <tr key={link.id}><td className="max-w-[16rem] break-all px-3 py-3 font-mono text-xs text-ink-700">{link.subject}</td><td className="px-3 py-3 font-medium text-ink-900">{link.principalId}</td><td className="px-3 py-3"><Badge color={link.status === 'ACTIVE' ? 'green' : 'red'}>{link.status.toLowerCase()}</Badge></td><td className="px-3 py-3">{link.status === 'ACTIVE' && <Button variant="ghost" size="sm" onClick={() => { if (window.confirm('Disable this external identity link?')) disableLink.mutate(link.id) }}>Disable</Button>}</td></tr>)}</tbody></table></div>}
      <details className="mt-4 rounded-md border border-line p-4" open={links.length === 0}><summary className="cursor-pointer text-sm font-semibold text-ink-900">Create exact identity link</summary><form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={event => { event.preventDefault(); createLink.mutate() }}><Input label="Issuer" required value={linkForm.issuer} onChange={event => setLinkForm(form => ({ ...form, issuer: event.target.value }))} hint="Must exactly match the source issuer." /><Input label="Provider subject" required value={linkForm.subject} onChange={event => setLinkForm(form => ({ ...form, subject: event.target.value }))} /><Input label="Axiom principal ID" required value={linkForm.principalId} onChange={event => setLinkForm(form => ({ ...form, principalId: event.target.value }))} hint="Must already exist." /><Button type="submit" size="sm" loading={createLink.isPending} disabled={source.status !== 'ACTIVE'}>Create link</Button></form></details>
    </section>

    <section className="surface-card p-5"><div className="flex items-center justify-between gap-3"><div><h3 className="font-semibold text-ink-900">Client secret</h3><p className="mt-1 text-sm text-ink-500">Stored secret material is never displayed. Secret changes must go through Identity Controls.</p></div><a href="/identity-controls" className="rounded-md border border-line px-3 py-2 text-sm font-medium text-ink-700 hover:bg-slate-50">Request secret change</a></div></section>

    <Dialog open={rotateOpen} onClose={() => { setRotateOpen(false); setNewSecret(''); setRotateConfirmed(false) }} title="Rotate customer IdP client secret" description="Enter the replacement secret. The previous secret will no longer be used."><form className="space-y-4" onSubmit={event => { event.preventDefault(); rotate.mutate() }}><Input label="New client secret" type="password" required value={newSecret} onChange={event => setNewSecret(event.target.value)} autoComplete="new-password" /><label className="flex items-start gap-2 text-sm text-ink-700"><input type="checkbox" required checked={rotateConfirmed} onChange={event => setRotateConfirmed(event.target.checked)} className="mt-0.5 rounded border-line text-axiom-800 focus:ring-gold-300" />I understand this changes the credential used for customer sign-in.</label><div className="flex justify-end gap-2"><Button type="button" variant="secondary" onClick={() => setRotateOpen(false)}>Cancel</Button><Button type="submit" loading={rotate.isPending} disabled={!rotateConfirmed}>Rotate secret</Button></div></form></Dialog>
  </div>
}

export function IdentitySources() {
  const { user } = useAuth()
  const { toast } = useToast()
  const qc = useQueryClient()
  const tenantId = user?.tenantId || ''
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState({ ...EMPTY_SOURCE })
  const sourcesQuery = useQuery({ queryKey: ['identity-sources', tenantId], queryFn: () => identitySourcesApi.list(tenantId), enabled: Boolean(tenantId), retry: false })
  const sources = sourcesQuery.data ?? []
  const selected = sources.find(source => source.id === selectedId) ?? sources[0]
  const create = useMutation({
    mutationFn: () => identitySourcesApi.create(tenantId, { ...form, requestedScopes: csv(form.requestedScopes), allowedSigningAlgorithms: csv(form.allowedSigningAlgorithms), requiredClaims: csv(form.requiredClaims), requiredAcrValues: csv(form.requiredAcrValues) }),
    onSuccess: source => { qc.invalidateQueries({ queryKey: ['identity-sources', tenantId] }); setSelectedId(source.id); setCreateOpen(false); setForm({ ...EMPTY_SOURCE }); toast('success', 'Customer identity source created'); },
    onError: (error: Error) => toast('error', error.message),
  })
  function changed() { qc.invalidateQueries({ queryKey: ['identity-sources', tenantId] }) }

  return <div className="page-shell w-full"><header className="mb-6 flex flex-wrap items-start justify-between gap-4"><div><p className="page-kicker">Customer identity administration</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-ink-900">Customer identity sources</h1><p className="mt-1 max-w-2xl text-sm leading-6 text-ink-500">Configure trusted customer OIDC providers and link their exact identities to existing Axiom principals.</p></div><Button onClick={() => setCreateOpen(true)} disabled={!tenantId}><Plus size={15} /> Add identity source</Button></header>
    {!tenantId ? <EmptyState icon={<ShieldCheck size={40} className="text-slate-300" />} title="Tenant context unavailable" description="Customer identity sources require an authenticated tenant context." /> : sourcesQuery.isLoading ? <div className="grid gap-4 lg:grid-cols-2"><Skeleton className="h-44 rounded-lg" /><Skeleton className="h-44 rounded-lg" /></div> : sourcesQuery.isError ? <EmptyState icon={<Globe2 size={40} className="text-red-300" />} title={denied(sourcesQuery.error) ? 'Identity sources unavailable' : 'Could not load identity sources'} description={denied(sourcesQuery.error) ? 'Your signed-in role cannot manage customer identity sources.' : (sourcesQuery.error as Error).message} /> : sources.length === 0 ? <EmptyState icon={<Globe2 size={40} className="text-slate-300" />} title="No customer identity sources" description="Add a customer OIDC provider to configure federated sign-in." action={{ label: 'Add identity source', onClick: () => setCreateOpen(true) }} /> : <div className="grid gap-4 lg:grid-cols-[minmax(18rem,0.75fr)_minmax(0,1.65fr)]"><section aria-label="Customer identity sources" className="space-y-3">{sources.map(source => <button key={source.id} type="button" onClick={() => setSelectedId(source.id)} className={`surface-card w-full p-5 text-left transition-colors ${selected?.id === source.id ? 'border-axiom-700 ring-2 ring-gold-300/60' : 'hover:border-axiom-300'}`}><div className="flex items-start justify-between gap-3"><div><h2 className="font-semibold text-ink-900">{source.displayName}</h2><p className="mt-1 break-all font-mono text-xs text-ink-500">{source.issuer}</p></div><Badge color={statusColor(source.status)}>{source.status.toLowerCase()}</Badge></div><div className="mt-4 flex flex-wrap gap-3 text-xs text-ink-500"><span>Revision {source.revision}</span><span>{source.lastValidatedAt ? 'Validated' : 'Not validated'}</span></div></button>)}</section><section className="surface-card min-h-[36rem] p-6">{selected ? <SourceDetails key={selected.id} source={selected} tenantId={tenantId} onChanged={changed} /> : <EmptyState icon={<Globe2 size={40} className="text-slate-300" />} title="Select an identity source" description="Open a source to inspect configuration, validation, and exact identity links." />}</section></div>}
    <Dialog open={createOpen} onClose={() => setCreateOpen(false)} title="Add customer OIDC identity source" description="Secrets are used for provider communication and are never displayed after submission."><form className="space-y-4" onSubmit={event => { event.preventDefault(); create.mutate() }}><Input label="Display name" required value={form.displayName} onChange={event => setForm(value => ({ ...value, displayName: event.target.value }))} /><Input label="Exact issuer" required type="url" value={form.issuer} onChange={event => setForm(value => ({ ...value, issuer: event.target.value }))} /><Input label="Discovery URI" required type="url" value={form.discoveryUri} onChange={event => setForm(value => ({ ...value, discoveryUri: event.target.value }))} /><Input label="Client ID" required value={form.clientId} onChange={event => setForm(value => ({ ...value, clientId: event.target.value }))} /><Input label="Client secret" required type="password" autoComplete="new-password" value={form.clientSecret} onChange={event => setForm(value => ({ ...value, clientSecret: event.target.value }))} /><Textarea label="Requested scopes" required rows={2} value={form.requestedScopes} onChange={event => setForm(value => ({ ...value, requestedScopes: event.target.value }))} hint="Comma-separated values." /><div className="grid gap-4 sm:grid-cols-2"><Input label="Allowed signing algorithms" required value={form.allowedSigningAlgorithms} onChange={event => setForm(value => ({ ...value, allowedSigningAlgorithms: event.target.value }))} /><Input label="Required ACR values" value={form.requiredAcrValues} onChange={event => setForm(value => ({ ...value, requiredAcrValues: event.target.value }))} /></div><Textarea label="Required claims" required rows={2} value={form.requiredClaims} onChange={event => setForm(value => ({ ...value, requiredClaims: event.target.value }))} hint="Comma-separated claim names." /><div className="flex justify-end gap-2"><Button type="button" variant="secondary" onClick={() => setCreateOpen(false)}>Cancel</Button><Button type="submit" loading={create.isPending}>Create source</Button></div></form></Dialog>
  </div>
}
