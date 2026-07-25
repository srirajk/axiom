import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, ClipboardCheck, Plus, ShieldAlert, XCircle } from 'lucide-react'
import {
  identityControlsApi,
  type IdentityControlAction,
  type IdentityControlRequest,
  type IdentityControlStatus,
  type IdentityControlTargetType,
} from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { EmptyState } from '../components/ui/EmptyState'
import { Input } from '../components/ui/Input'
import { Skeleton } from '../components/ui/Skeleton'
import { useToast } from '../components/ui/Toast'

const PAGE_SIZE = 50
type FilterStatus = 'ALL' | IdentityControlStatus

const ACTIONS: Array<{ value: IdentityControlAction; label: string; targetType: IdentityControlTargetType; secret: boolean }> = [
  { value: 'EMERGENCY_RETIRE_SIGNING_KEY', label: 'Emergency retire signing key', targetType: 'SIGNING_KEY', secret: false },
  { value: 'DISABLE_IDENTITY_SOURCE', label: 'Disable customer identity source', targetType: 'IDENTITY_SOURCE', secret: false },
  { value: 'ROTATE_IDENTITY_SOURCE_SECRET', label: 'Rotate customer identity source secret', targetType: 'IDENTITY_SOURCE', secret: true },
  { value: 'REVOKE_APPLICATION_CLIENT_SECRET', label: 'Revoke application client secret', targetType: 'APPLICATION_CLIENT', secret: false },
  { value: 'ROTATE_APPLICATION_CLIENT_SECRET', label: 'Rotate application client secret', targetType: 'APPLICATION_CLIENT', secret: true },
  { value: 'REVOKE_SCIM_SOURCE', label: 'Revoke SCIM source', targetType: 'SCIM_SOURCE', secret: false },
  { value: 'ROTATE_SCIM_SOURCE_CREDENTIAL', label: 'Rotate SCIM source credential', targetType: 'SCIM_SOURCE', secret: false },
]

function denied(error: unknown): boolean { return error instanceof Error && /403|forbidden|denied|not authorized/i.test(error.message) }
function time(value?: string | null): string { return value ? new Date(value).toLocaleString() : '—' }
function expired(request: IdentityControlRequest): boolean {
  return (request.status === 'PENDING' || request.status === 'APPROVED') && new Date(request.expiresAt).getTime() <= Date.now()
}
function visibleStatus(request: IdentityControlRequest): IdentityControlStatus {
  return expired(request) ? 'EXPIRED' : request.status
}
function statusColor(status: IdentityControlStatus): 'green' | 'yellow' | 'red' | 'blue' | 'slate' {
  if (status === 'APPROVED' || status === 'APPLIED') return 'green'
  if (status === 'PENDING') return 'blue'
  if (status === 'EXPIRED') return 'yellow'
  return 'red'
}
function label(value: string): string { return value.toLowerCase().replace(/_/g, ' ') }
function requestReference(id: string): string { return `${id.slice(0, 8)}…` }
function conflictMessage(error: unknown, operation: string): string {
  const message = error instanceof Error ? error.message : ''
  if (/stale|revision|changed/i.test(message)) return 'This request or its target changed. Refresh the workbench and review the current revision before trying again.'
  if (/expired/i.test(message)) return 'This request has expired and cannot be changed.'
  if (/not approved|approved/i.test(message)) return 'Only an approved request can be applied.'
  if (/not found|tenant|forbidden|denied/i.test(message)) return 'This request is not available in the current tenant or role.'
  return `Unable to ${operation}. The server rejected the request without exposing protected details.`
}

function ProposeDialog({ tenantId, open, onClose, onDone }: { tenantId: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const { toast } = useToast()
  const [action, setAction] = useState<IdentityControlAction>(ACTIONS[0].value)
  const [targetId, setTargetId] = useState('')
  const [targetRevision, setTargetRevision] = useState('')
  const [replacementSecret, setReplacementSecret] = useState('')
  const selected = ACTIONS.find(item => item.value === action) ?? ACTIONS[0]
  const propose = useMutation({
    mutationFn: () => identityControlsApi.propose(tenantId, {
      action,
      targetType: selected.targetType,
      targetId: targetId.trim(),
      ...(replacementSecret ? { payload: { clientSecret: replacementSecret } } : {}),
      ...(targetRevision.trim() ? { expectedTargetRevision: Number(targetRevision) } : {}),
    }),
    onSuccess: () => { setReplacementSecret(''); onDone(); onClose(); toast('success', 'Identity control request proposed') },
    onError: (error: Error) => toast('error', error.message),
  })
  return <Dialog open={open} onClose={onClose} title="Propose identity control" description="Step 1 records a bounded identity action for review. The server sets the request expiry; no application action is performed here.">
    <form className="space-y-4" onSubmit={event => { event.preventDefault(); propose.mutate() }}>
      <label className="flex flex-col gap-1 text-sm font-medium text-ink-700" htmlFor="identity-control-action"><span>Supported action</span><select id="identity-control-action" className="rounded-md border border-line bg-white px-3 py-2 text-sm font-normal" value={action} onChange={event => { setAction(event.target.value as IdentityControlAction); setReplacementSecret('') }}>{ACTIONS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
      <Input label={`Target ${selected.targetType.toLowerCase().replace(/_/g, ' ')} ID`} required value={targetId} onChange={event => setTargetId(event.target.value)} placeholder="UUID" />
      <Input label="Expected target revision" type="number" min={0} required value={targetRevision} onChange={event => setTargetRevision(event.target.value)} hint="Required by the server to prevent stale targeting." />
      {selected.secret && <Input label="Replacement secret" type="password" required value={replacementSecret} onChange={event => setReplacementSecret(event.target.value)} autoComplete="new-password" hint="Used only for this request and never displayed after submission." />}
      <div className="rounded-md border border-axiom-200 bg-axiom-50 p-3 text-sm text-axiom-900">The request stores only a payload hash in the workbench. Sensitive payload values are not returned or displayed after submission.</div>
      <div className="flex justify-end gap-2"><Button type="button" variant="secondary" onClick={onClose}>Cancel</Button><Button type="submit" loading={propose.isPending}>Propose request</Button></div>
    </form>
  </Dialog>
}

function RequestRow({ request, tenantId, onChanged, onSecret }: { request: IdentityControlRequest; tenantId: string; onChanged: () => void; onSecret: (secret: string) => void }) {
  const { toast } = useToast()
  const current = visibleStatus(request)
  const transition = useMutation({
    mutationFn: (kind: 'approve' | 'reject' | 'cancel') => identityControlsApi[kind](tenantId, request.id, request.revision),
    onSuccess: (_, kind) => { onChanged(); toast('success', `Request ${kind === 'approve' ? 'approved' : kind === 'reject' ? 'rejected' : 'cancelled'}`) },
    onError: (error: Error) => toast('error', conflictMessage(error, 'change this request')),
  })
  const apply = useMutation({
    mutationFn: () => identityControlsApi.apply(tenantId, request.id, request.revision),
    onSuccess: result => { onChanged(); if (result.oneTimeSecret) onSecret(result.oneTimeSecret); toast('success', result.oneTimeSecret ? 'Applied. The generated credential is shown once.' : 'Identity control applied.') },
    onError: (error: Error) => toast('error', conflictMessage(error, 'apply this request')),
  })
  function transitionWithConfirm(kind: 'approve' | 'reject' | 'cancel') {
    if (kind === 'approve' || kind === 'reject') {
      const decision = kind === 'approve' ? 'approve' : 'reject'
      if (!window.confirm(`Distinct-person SoD is required: you must not be the initiator (${request.initiatorPrincipalId}). Confirm that you are a different authorized person and ${decision} this request?`)) return
    } else if (!window.confirm('Cancel this identity control request? No application action will be performed from this request.')) return
    transition.mutate(kind)
  }
  return <tr><td className="px-4 py-3"><div className="font-medium text-ink-900" title={`${label(request.action)} · ${label(request.targetType)}`}>{label(request.action)}</div><div className="mt-1 text-xs text-ink-500">Target: {label(request.targetType)}</div><div className="font-mono text-[10px] text-ink-500" title={request.id}>Request {requestReference(request.id)}</div></td><td className="px-4 py-3 font-mono text-xs text-ink-700" title={request.targetId}>{request.targetId}</td><td className="px-4 py-3"><div className="text-xs text-ink-700">{request.initiatorPrincipalId}</div><div className="mt-1 text-xs text-ink-500">Approver: {request.approverPrincipalId || '—'}</div></td><td className="whitespace-nowrap px-4 py-3 text-xs text-ink-600">{time(request.createdAt)}<br />expires {time(request.expiresAt)}</td><td className="px-4 py-3"><div className="font-mono text-xs text-ink-600">target {request.expectedTargetRevision ?? '—'}</div><div className="mt-1 font-mono text-xs text-ink-500">record {request.revision}</div></td><td className="px-4 py-3"><Badge color={statusColor(current)}>{label(current)}</Badge>{request.applicationResultReference && <p className="mt-2 max-w-[18rem] break-all text-xs text-ink-500">Result: {request.applicationResultReference}</p>}</td><td className="px-4 py-3"><div className="flex flex-wrap gap-2">{current === 'PENDING' && <><Button size="sm" loading={transition.isPending} onClick={() => transitionWithConfirm('approve')}><CheckCircle2 size={14} /> Approve</Button><Button size="sm" variant="secondary" loading={transition.isPending} onClick={() => transitionWithConfirm('reject')}><XCircle size={14} /> Reject</Button></>}{current === 'APPROVED' && <Button size="sm" loading={apply.isPending} onClick={() => { if (window.confirm('Apply this approved identity request now? The backend will perform the supported action and may issue a one-time credential.')) apply.mutate() }}>Apply</Button>}{(current === 'PENDING' || current === 'APPROVED') && <Button size="sm" variant="ghost" loading={transition.isPending || apply.isPending} onClick={() => transitionWithConfirm('cancel')}>Cancel</Button>}{current !== 'PENDING' && current !== 'APPROVED' && <span className="text-xs text-ink-500">Terminal</span>}</div></td></tr>
}

function OneTimeSecretDialog({ secret, onClose }: { secret: string | null; onClose: () => void }) {
  const [acknowledged, setAcknowledged] = useState(false)
  const [copied, setCopied] = useState(false)
  if (!secret) return null
  return <Dialog open onClose={() => { if (acknowledged) onClose() }} title="One-time credential" description="This credential is shown once. Copy it to the intended secure store before acknowledging; it will not be available after closing or refreshing.">
    <div className="space-y-4"><div className="rounded-md border border-amber-300 bg-amber-50 p-4"><p className="mb-2 text-xs font-semibold uppercase tracking-wide text-amber-900">Sensitive value</p><code className="block break-all rounded bg-white p-3 font-mono text-sm text-ink-900">{secret}</code></div><Button variant="secondary" onClick={() => { void navigator.clipboard.writeText(secret); setCopied(true) }}>{copied ? 'Copied' : 'Copy credential'}</Button><label className="flex items-start gap-2 text-sm text-ink-700"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} className="mt-0.5 rounded border-line text-axiom-800 focus:ring-gold-300" />I have stored this credential securely and understand it cannot be retrieved from this console.</label><div className="flex justify-end"><Button disabled={!acknowledged} onClick={onClose}>Acknowledge and close</Button></div></div>
  </Dialog>
}

export function IdentityControls() {
  const { user } = useAuth()
  const qc = useQueryClient()
  const tenantId = user?.tenantId || ''
  const [page, setPage] = useState(0)
  const [status, setStatus] = useState<FilterStatus>('ALL')
  const [proposeOpen, setProposeOpen] = useState(false)
  const [oneTimeSecret, setOneTimeSecret] = useState<string | null>(null)
  const query = useQuery({
    queryKey: ['identity-control-requests', tenantId, page, status],
    queryFn: () => identityControlsApi.list(tenantId, page, PAGE_SIZE, status === 'ALL' ? undefined : status),
    enabled: Boolean(tenantId),
    retry: false,
  })
  function changed() { void qc.invalidateQueries({ queryKey: ['identity-control-requests', tenantId] }) }
  return <div className="page-shell w-full">
    <header className="mb-6 flex flex-wrap items-start justify-between gap-4"><div><p className="page-kicker">Identity platform operations</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-ink-900">Identity Controls</h1><p className="mt-1 max-w-3xl text-sm leading-6 text-ink-500">Review bounded identity actions with clear ownership, expiry, revision, and two-person approval. Approved requests can be applied here; no direct target-page action bypasses this workflow.</p></div><Button onClick={() => setProposeOpen(true)} disabled={!tenantId}><Plus size={15} /> Propose request</Button></header>
    {!tenantId ? <EmptyState icon={<ShieldAlert size={40} className="text-slate-300" />} title="Tenant context unavailable" description="Identity control requests require an authenticated tenant context." /> : <>
      <section className="surface-card mb-5 space-y-3 p-4" aria-label="Identity control filters"><div className="flex flex-wrap gap-2" role="tablist" aria-label="Request status"><button type="button" role="tab" aria-selected={status === 'ALL'} className={`rounded-md px-3 py-2 text-sm ${status === 'ALL' ? 'bg-axiom-900 text-white' : 'border border-line text-ink-700'}`} onClick={() => { setStatus('ALL'); setPage(0) }}>All</button>{(['PENDING', 'APPROVED', 'APPLIED'] as IdentityControlStatus[]).map(value => <button type="button" role="tab" key={value} aria-selected={status === value} className={`rounded-md px-3 py-2 text-sm ${status === value ? 'bg-axiom-900 text-white' : 'border border-line text-ink-700'}`} onClick={() => { setStatus(value); setPage(0) }}>{label(value)}</button>)}</div><div className="flex flex-wrap items-end justify-between gap-3"><label className="flex min-w-48 flex-col gap-1 text-sm font-medium text-ink-700" htmlFor="control-status"><span>All statuses</span><select id="control-status" className="rounded-md border border-line bg-white px-3 py-2 text-sm font-normal" value={status} onChange={event => { setStatus(event.target.value as FilterStatus); setPage(0) }}><option value="ALL">All requests</option>{(['PENDING', 'APPROVED', 'APPLIED', 'REJECTED', 'EXPIRED', 'CANCELLED'] as IdentityControlStatus[]).map(value => <option key={value} value={value}>{label(value)}</option>)}</select></label><div className="max-w-xl text-xs text-ink-500">Approved requests expose Apply. APPLIED requests keep their terminal result reference; no records are fabricated when a status has no results.</div></div></section>
      {query.isLoading ? <Skeleton className="h-64 rounded-lg" /> : query.isError ? <EmptyState icon={<ShieldAlert size={40} className="text-red-300" />} title={denied(query.error) ? 'Identity controls unavailable' : 'Could not load identity controls'} description={denied(query.error) ? 'Your signed-in role cannot view identity control requests.' : (query.error as Error).message} action={{ label: 'Retry', onClick: () => void query.refetch() }} /> : (query.data?.content.length ?? 0) === 0 ? <EmptyState icon={<ClipboardCheck size={40} className="text-slate-300" />} title={status === 'APPROVED' ? 'No approved requests' : status === 'APPLIED' ? 'No applied requests' : 'No identity control requests'} description={status === 'APPROVED' ? 'Apply becomes available when an approved request exists. No approved record is present in the current tenant.' : status === 'APPLIED' ? 'Completed requests will show their terminal result here.' : status === 'ALL' ? 'Propose a supported identity action to begin a review trail.' : `No ${label(status)} requests found.`} action={{ label: 'Propose request', onClick: () => setProposeOpen(true) }} /> : <>
        <div className="surface-card overflow-x-auto"><table className="w-full min-w-[80rem] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-ink-500"><tr><th className="px-4 py-3 font-medium">Action / target type</th><th className="px-4 py-3 font-medium">Target ID</th><th className="px-4 py-3 font-medium">Initiator / approver</th><th className="px-4 py-3 font-medium">Created / expires</th><th className="px-4 py-3 font-medium">Expected / record revision</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3 font-medium">Actions</th></tr></thead><tbody className="divide-y divide-line">{query.data?.content.map(request => <RequestRow key={request.id} request={request} tenantId={tenantId} onChanged={changed} onSecret={setOneTimeSecret} />)}</tbody></table></div>
        <div className="mt-4 flex items-center justify-between text-sm text-ink-500"><span>Page {(query.data?.page ?? page) + 1} of {query.data?.totalPages ?? 1}</span><div className="flex gap-2"><Button size="sm" variant="secondary" disabled={page === 0 || query.isFetching} onClick={() => setPage(current => current - 1)}>Previous</Button><Button size="sm" variant="secondary" disabled={!query.data || page + 1 >= query.data.totalPages || query.isFetching} onClick={() => setPage(current => current + 1)}>Next</Button></div></div>
      </>}
      <ProposeDialog tenantId={tenantId} open={proposeOpen} onClose={() => setProposeOpen(false)} onDone={changed} />
      <OneTimeSecretDialog secret={oneTimeSecret} onClose={() => setOneTimeSecret(null)} />
    </>}
  </div>
}
