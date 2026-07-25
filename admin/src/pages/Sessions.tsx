import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Clock3, Filter, RefreshCw, ShieldCheck, XCircle } from 'lucide-react'
import { sessionsApi, type IamSession, type IamSessionStatus } from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { EmptyState } from '../components/ui/EmptyState'
import { Input } from '../components/ui/Input'
import { Skeleton } from '../components/ui/Skeleton'
import { useToast } from '../components/ui/Toast'

type DisplayStatus = IamSessionStatus | 'EXPIRED'
const PAGE_SIZE = 50

function denied(error: unknown): boolean { return error instanceof Error && /403|forbidden|denied|not authorized/i.test(error.message) }
function time(value?: string | null): string { return value ? new Date(value).toLocaleString() : '—' }
function displayStatus(session: IamSession): DisplayStatus {
  return session.status === 'REVOKED' ? 'REVOKED' : new Date(session.expiresAt).getTime() <= Date.now() ? 'EXPIRED' : 'ACTIVE'
}
function statusColor(status: DisplayStatus): 'green' | 'yellow' | 'red' { return status === 'ACTIVE' ? 'green' : status === 'EXPIRED' ? 'yellow' : 'red' }
function statusLabel(status: DisplayStatus): string { return status.toLowerCase() }

export function Sessions() {
  const { user } = useAuth()
  const { toast } = useToast()
  const qc = useQueryClient()
  const tenantId = user?.tenantId || ''
  const [page, setPage] = useState(0)
  const [principalId, setPrincipalId] = useState('')
  const [clientId, setClientId] = useState('')
  const [status, setStatus] = useState<'ALL' | DisplayStatus>('ALL')
  const query = useQuery({
    queryKey: ['sessions', tenantId, page, principalId, clientId, status],
    queryFn: () => sessionsApi.list(tenantId, {
      page,
      size: PAGE_SIZE,
      principalId: principalId.trim() || undefined,
      clientId: clientId.trim() || undefined,
      status: status === 'ACTIVE' || status === 'REVOKED' ? status : undefined,
    }),
    enabled: Boolean(tenantId),
    retry: false,
  })
  const revoke = useMutation({
    mutationFn: (session: IamSession) => sessionsApi.revoke(tenantId, session.id, session.revision),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['sessions', tenantId] }); toast('success', 'Session revoked; access fails immediately.') },
    onError: (error: Error) => toast('error', error.message),
  })
  const rawRows = query.data?.content ?? []
  const rows = status === 'EXPIRED' ? rawRows.filter(session => displayStatus(session) === 'EXPIRED') : rawRows
  function resetFilters() { setPrincipalId(''); setClientId(''); setStatus('ALL'); setPage(0) }
  function requestRevoke(session: IamSession) {
    if (displayStatus(session) !== 'ACTIVE') return
    if (window.confirm(`Revoke this session now? Access will fail immediately. The request is protected by record revision ${session.revision}.`)) revoke.mutate(session)
  }

  return <div className="page-shell w-full">
    <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div><p className="page-kicker">Identity platform operations</p><h1 className="mt-1 text-2xl font-semibold tracking-tight text-ink-900">Sessions</h1><p className="mt-1 max-w-2xl text-sm leading-6 text-ink-500">Review tenant-scoped Axiom identity sessions. Revoke a session when access should stop immediately; bearer tokens and sensitive claims are never shown.</p></div>
      <Button variant="secondary" onClick={() => void query.refetch()} disabled={!tenantId || query.isFetching}><RefreshCw size={15} /> Refresh</Button>
    </header>
    {!tenantId ? <EmptyState icon={<ShieldCheck size={40} className="text-slate-300" />} title="Tenant context unavailable" description="Session inventory requires an authenticated tenant context." /> : <>
      <section className="surface-card mb-5 p-4" aria-label="Session filters"><div className="mb-3 flex items-center gap-2 text-sm font-semibold text-ink-900"><Filter size={15} /> Filter sessions</div><div className="grid gap-3 md:grid-cols-[minmax(12rem,1fr)_minmax(12rem,1fr)_10rem_auto_auto]"><Input label="Principal ID" value={principalId} onChange={event => { setPrincipalId(event.target.value); setPage(0) }} placeholder="Filter by principal" /><Input label="Client ID" value={clientId} onChange={event => { setClientId(event.target.value); setPage(0) }} placeholder="Filter by client" /><label className="flex flex-col gap-1 text-sm font-medium text-ink-700" htmlFor="session-status"><span>Status</span><select id="session-status" className="rounded-md border border-line bg-white px-3 py-2 text-sm font-normal" value={status} onChange={event => { setStatus(event.target.value as 'ALL' | DisplayStatus); setPage(0) }}><option value="ALL">All statuses</option><option value="ACTIVE">Active</option><option value="REVOKED">Revoked</option><option value="EXPIRED">Expired</option></select></label><Button className="self-end" variant="secondary" onClick={resetFilters}>Reset</Button><span className="self-end pb-2 text-xs text-ink-500">Page size: {PAGE_SIZE}</span></div></section>
      {query.isLoading ? <Skeleton className="h-64 rounded-lg" /> : query.isError ? <EmptyState icon={<XCircle size={40} className="text-red-300" />} title={denied(query.error) ? 'Sessions unavailable' : 'Could not load sessions'} description={denied(query.error) ? 'Your signed-in role cannot view tenant session metadata.' : (query.error as Error).message} action={{ label: 'Retry', onClick: () => void query.refetch() }} /> : rows.length === 0 ? <EmptyState icon={<Clock3 size={40} className="text-slate-300" />} title="No sessions found" description={status === 'EXPIRED' ? 'No expired sessions are present on this page.' : 'No sessions match the current filters.'} /> : <>
        <div className="surface-card overflow-x-auto"><table className="w-full min-w-[60rem] text-left text-sm"><thead className="bg-slate-50 text-xs uppercase tracking-wide text-ink-500"><tr><th className="px-4 py-3 font-medium">Principal</th><th className="px-4 py-3 font-medium">Application / client</th><th className="px-4 py-3 font-medium">Issued</th><th className="px-4 py-3 font-medium">Last seen</th><th className="px-4 py-3 font-medium">Expires</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3 font-medium">Revision</th><th className="px-4 py-3 font-medium">Action</th></tr></thead><tbody className="divide-y divide-line">{rows.map(session => { const current = displayStatus(session); return <tr key={session.id}><td className="px-4 py-3"><span className="font-mono text-xs text-ink-800">{session.principalId}</span></td><td className="px-4 py-3"><div className="text-ink-800">{session.applicationId || '—'}</div><div className="font-mono text-xs text-ink-500">{session.clientId || '—'}</div></td><td className="whitespace-nowrap px-4 py-3 text-xs text-ink-600">{time(session.issuedAt)}</td><td className="whitespace-nowrap px-4 py-3 text-xs text-ink-600">{time(session.lastSeenAt)}</td><td className="whitespace-nowrap px-4 py-3 text-xs text-ink-600">{time(session.expiresAt)}</td><td className="px-4 py-3"><Badge color={statusColor(current)}>{statusLabel(current)}</Badge></td><td className="px-4 py-3 font-mono text-xs text-ink-600">{session.revision}</td><td className="px-4 py-3">{current === 'ACTIVE' ? <Button size="sm" variant="danger" loading={revoke.isPending} onClick={() => requestRevoke(session)}>Revoke</Button> : <span className="text-xs text-ink-500">No action</span>}</td></tr> })}</tbody></table></div>
        <div className="mt-4 flex items-center justify-between text-sm text-ink-500"><span>Page {(query.data?.page ?? page) + 1} of {query.data?.totalPages ?? 1}</span><div className="flex gap-2"><Button size="sm" variant="secondary" disabled={page === 0 || query.isFetching} onClick={() => setPage(current => current - 1)}>Previous</Button><Button size="sm" variant="secondary" disabled={!query.data || page + 1 >= query.data.totalPages || query.isFetching} onClick={() => setPage(current => current + 1)}>Next</Button></div></div>
      </>}
    </>}
  </div>
}
