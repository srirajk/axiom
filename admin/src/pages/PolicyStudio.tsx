import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle, Clock, Code, FileCheck,
  GitCompare, History, Lock, RefreshCw, Search, ShieldAlert, Siren, UserCheck,
} from 'lucide-react'
import {
  studioApi,
  type BreakGlassRequest,
  type ConsequenceReview,
  type DraftRequest,
  type ReviewHandoff,
} from '../api/client'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Dialog } from '../components/ui/Dialog'
import { Input, Textarea } from '../components/ui/Input'
import { useToast } from '../components/ui/Toast'
import { useAuth } from '../hooks/useAuth'

type StudioTab = 'author' | 'lifecycle' | 'emergency'

const EMPTY_BUNDLE = JSON.stringify({
  bundleId: 'b_replace', tenantId: 'replace', files: [], manifestRefs: [],
  testMetadata: { fixtureSetHash: 'replace', testCount: 0, oracle: 'independent-c3', pdpSourceId: 'cerbos-0.53.0' },
  canonicalContent: 'replace',
}, null, 2)

function formatTime(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

function TabButton({ active, icon: Icon, children, onClick }: {
  active: boolean
  icon: typeof GitCompare
  children: React.ReactNode
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex items-center gap-2 border-b-2 px-1 py-3 text-sm font-medium transition-colors ${
        active ? 'border-gold-500 text-axiom-950' : 'border-transparent text-ink-500 hover:text-ink-900'
      }`}
    >
      <Icon size={15} /> {children}
    </button>
  )
}

function AdvancedJson({ title, hint, value, onChange, rows = 12 }: {
  title: string
  hint: string
  value: string
  onChange?: (value: string) => void
  rows?: number
}) {
  return (
    <details className="rounded-md border border-line bg-slate-50/70">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2.5 text-sm font-medium text-ink-700">
        <Code size={14} className="text-gold-700" /> {title}
        <span className="ml-auto text-xs font-normal text-ink-500">Advanced</span>
      </summary>
      <div className="border-t border-line p-3">
        <p className="mb-2 text-xs leading-5 text-ink-500">{hint}</p>
        <textarea
          aria-label={title}
          value={value}
          onChange={onChange ? (event) => onChange(event.target.value) : undefined}
          readOnly={!onChange}
          rows={rows}
          spellCheck={false}
          className="w-full resize-y rounded-md border border-slate-300 bg-axiom-950 p-3 font-mono text-xs leading-5 text-slate-100 focus:border-gold-400 focus:outline-none focus:ring-2 focus:ring-gold-300"
        />
      </div>
    </details>
  )
}

function ConsequencePanel({ review }: { review: ConsequenceReview }) {
  return (
    <section className="surface-panel" aria-label="Consequence review">
      <div className={`border-b px-5 py-4 ${review.overPermissionAlarm ? 'border-red-200 bg-red-50' : 'border-emerald-200 bg-emerald-50'}`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            {review.overPermissionAlarm
              ? <ShieldAlert className="mt-0.5 text-red-700" size={20} />
              : <CheckCircle className="mt-0.5 text-emerald-700" size={20} />}
            <div>
              <h2 className="text-sm font-semibold text-ink-900">
                {review.overPermissionAlarm ? 'Access widens — human attention required' : 'No sampled access widening detected'}
              </h2>
              <p className="mt-1 text-xs text-ink-600">
                {review.deltas.length} changed decision{review.deltas.length === 1 ? '' : 's'} · {review.principalsGainingAccess} sampled principal{review.principalsGainingAccess === 1 ? '' : 's'} gain access
              </p>
            </div>
          </div>
          <Badge color="navy">{review.provenance?.sourceId || 'PDP source unavailable'}</Badge>
        </div>
      </div>

      <div className="divide-y divide-line">
        {review.deltas.length === 0 ? (
          <div className="px-5 py-8 text-center text-sm text-ink-500">No decision changes in the sampled matrix.</div>
        ) : review.deltas.map((delta, index) => (
          <div key={`${delta.cell?.label || 'delta'}-${index}`} className="px-5 py-4">
            <div className="flex items-start gap-3">
              <div className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${delta.direction === 'WIDENED' ? 'bg-red-100 text-red-700' : 'bg-sky-100 text-sky-700'}`}>
                <ArrowRight size={14} />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge color={delta.direction === 'WIDENED' ? 'red' : 'blue'}>{delta.direction}</Badge>
                  <span className="font-mono text-xs text-ink-500">{delta.from} → {delta.to}</span>
                  {delta.cell?.label && <span className="text-xs text-ink-500">{delta.cell.label}</span>}
                </div>
                <p className="mt-2 text-sm leading-6 text-ink-800">{delta.businessConsequence}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="border-t border-line bg-slate-50 px-5 py-3">
        <div className="flex items-start gap-2 text-xs leading-5 text-ink-600">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-gold-700" />
          <span>{review.disclosure?.statement || 'This is a sampled consequence review, not a formal proof.'}</span>
        </div>
        <p className="mt-2 break-all font-mono text-[11px] text-ink-500">Review hash: {review.consequenceReviewHash}</p>
      </div>
    </section>
  )
}

export function PolicyStudio() {
  const { user } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const tenant = user?.tenantId || 'tenant from verified token'
  const identityScope = `${user?.tenantId || 'none'}:${user?.id || 'anonymous'}`
  const canDraft = user?.roles.some((role) => role === 'policy_author') ?? false
  const canApprove = user?.roles.some((role) => role === 'policy_approver') ?? false
  const [tab, setTab] = useState<StudioTab>('author')

  const [intent, setIntent] = useState('')
  const [resourceKind] = useState('iam-resource')
  const [subscopesEnabled, setSubscopesEnabled] = useState(false)
  const [draft, setDraft] = useState<Awaited<ReturnType<typeof studioApi.createDraft>> | null>(null)
  const [review, setReview] = useState<ConsequenceReview | null>(null)
  const [candidateJson, setCandidateJson] = useState(EMPTY_BUNDLE)
  const [idempotencyKey, setIdempotencyKey] = useState(() => `studio-${Date.now()}`)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [consequencesConfirmed, setConsequencesConfirmed] = useState(false)
  useEffect(() => {
    setIntent('')
    setSubscopesEnabled(false)
    setDraft(null)
    setReview(null)
    setCandidateJson(EMPTY_BUNDLE)
    setIdempotencyKey(`studio-${Date.now()}`)
    setConfirmOpen(false)
    setConsequencesConfirmed(false)
  }, [identityScope])
  const grounding = useQuery({
    queryKey: ['studio-grounding', identityScope, resourceKind],
    queryFn: () => studioApi.getVocabulary(resourceKind),
    enabled: Boolean(user),
    retry: false,
  })
  const pendingReviews = useQuery({
    queryKey: ['studio-pending-reviews', identityScope],
    queryFn: studioApi.listPendingReviews,
    enabled: canApprove,
    retry: false,
  })

  const loadHandoff = (handoff: ReviewHandoff) => {
    setReview(handoff.review)
    setCandidateJson(JSON.stringify(handoff.candidate, null, 2))
    setIdempotencyKey(`studio-${Date.now()}`)
    toast('success', `Loaded review from ${handoff.authorId}`)
  }

  const draftMutation = useMutation({
    mutationFn: async () => {
      const payload: DraftRequest = { intent, resourceKind, subscopesEnabled }
      return studioApi.createDraft(payload)
    },
    onSuccess: (result) => {
      setDraft(result)
      toast(result.accepted ? 'success' : 'error', result.accepted ? 'Draft passed the deterministic gate' : 'Draft was rejected by the deterministic gate')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const reviewMutation = useMutation({
    mutationFn: async () => {
      if (!draft?.canonicalYaml) throw new Error('Generate an accepted draft first.')
      const result = await studioApi.createAssembledReview(resourceKind, draft.canonicalYaml)
      const candidate = await studioApi.assembleCandidateBundle(resourceKind, draft.canonicalYaml, result.fixtureSetHash)
      return { result, candidate }
    },
    onSuccess: ({ result, candidate }) => {
      setReview(result)
      setCandidateJson(JSON.stringify(candidate, null, 2))
      toast('success', 'Consequences computed by pinned Cerbos')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const promotionMutation = useMutation({
    mutationFn: () => studioApi.promote(review?.consequenceReviewHash || '', idempotencyKey),
    onSuccess: (receipt) => {
      setConfirmOpen(false)
      setConsequencesConfirmed(false)
      void queryClient.invalidateQueries({ queryKey: ['studio-bundles'] })
      void queryClient.invalidateQueries({ queryKey: ['studio-pending-reviews'] })
      toast('success', `${receipt.kind === 'ROLLBACK' ? 'Rollback' : 'Promotion'} committed at directory version ${receipt.directoryVersion}`)
    },
    onError: (error: Error) => toast('error', error.message),
  })

  return (
    <div className="page-shell w-full">
      <header className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="page-kicker">Axiom authorization control plane</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-ink-900">Policy Studio</h1>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-ink-500">
            Propose policy intent, review real Cerbos consequences, then require a separate human approval before promotion.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Badge color="slate">Tenant: {tenant}</Badge>
          <Badge color="green">Cerbos 0.53.0 · fail closed</Badge>
        </div>
      </header>

      <div className="mb-6 border-b border-line">
        <div className="flex gap-6">
          <TabButton active={tab === 'author'} icon={GitCompare} onClick={() => setTab('author')}>Author & review</TabButton>
          <TabButton active={tab === 'lifecycle'} icon={History} onClick={() => setTab('lifecycle')}>Lifecycle & evidence</TabButton>
          <TabButton active={tab === 'emergency'} icon={Siren} onClick={() => setTab('emergency')}>Break glass</TabButton>
        </div>
      </div>

      {tab === 'author' && (
        <div className="space-y-6">
          {canApprove && (
            <section className="surface-card p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h2 className="section-heading">Pending approvals</h2>
                  <p className="mt-1 text-xs leading-5 text-ink-500">Same-tenant reviews submitted by a separate verified author.</p>
                </div>
                <Button variant="ghost" size="sm" onClick={() => void pendingReviews.refetch()} loading={pendingReviews.isFetching}>
                  <RefreshCw size={14} /> Refresh
                </Button>
              </div>
              {pendingReviews.isError ? (
                <p className="mt-4 text-sm text-red-700">{(pendingReviews.error as Error).message}</p>
              ) : pendingReviews.data?.length ? (
                <div className="mt-4 space-y-2">
                  {pendingReviews.data.map((handoff) => (
                    <div key={handoff.reviewId} className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-slate-50 p-3">
                      <div>
                        <p className="text-sm font-medium text-ink-900">Review by {handoff.authorId}</p>
                        <p className="mt-1 font-mono text-[11px] text-ink-500">{handoff.reviewId}</p>
                        <p className="mt-1 text-xs text-ink-500">{formatTime(handoff.storedAt)} · {handoff.review.deltas.length} changed decisions</p>
                      </div>
                      <Button size="sm" onClick={() => loadHandoff(handoff)}>
                        <UserCheck size={14} /> Load for approval
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="mt-4 text-sm text-ink-500">No pending reviews for this tenant.</p>
              )}
            </section>
          )}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3" aria-label="Platform authorization policy workflow">
            {[
              ['1', 'Draft', 'Authoring assistant proposes; deterministic gate decides'],
              ['2', 'Review consequences', 'Pinned Cerbos evaluates both snapshots'],
              ['3', 'Approve & promote', 'A different human signs the exact review'],
            ].map(([number, title, copy], index) => (
              <div key={number} className="surface-card flex gap-3 p-4">
                <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-axiom-900 text-xs font-semibold text-white">{number}</div>
                <div>
                  <p className="text-sm font-semibold text-ink-900">{title}</p>
                  <p className="mt-0.5 text-xs leading-5 text-ink-500">{copy}</p>
                </div>
                {index < 2 && <ArrowRight size={15} className="ml-auto hidden self-center text-slate-300 md:block" />}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.9fr_1.1fr]">
            <section className="surface-card p-5">
              <div className="mb-4 flex items-start justify-between gap-3">
                <div>
                  <h2 className="section-heading">1. Describe the access change</h2>
                  <p className="mt-1 text-xs leading-5 text-ink-500">The authoring assistant proposes platform authorization policy. It cannot approve or enforce it.</p>
                </div>
                <Badge color={canDraft ? 'green' : 'slate'}>{canDraft ? 'Drafter' : 'View only'}</Badge>
              </div>
              <div className="space-y-4">
                <Textarea
                  label="Policy intent"
                  placeholder="Describe who should gain or lose which action, on what resource, and under which conditions."
                  value={intent}
                  onChange={(event) => setIntent(event.target.value)}
                  rows={5}
                />
                <Input
                  label="Resource kind"
                  value={resourceKind}
                  readOnly
                />
                <label className="flex items-start gap-2 text-sm text-ink-700">
                  <input
                    type="checkbox"
                    checked={subscopesEnabled}
                    onChange={(event) => setSubscopesEnabled(event.target.checked)}
                    className="mt-0.5 rounded border-line text-axiom-800 focus:ring-gold-300"
                  />
                  <span>Permit explicitly declared subscopes <span className="block text-xs text-ink-500">Leave off unless this policy intentionally targets a child scope.</span></span>
                </label>
                <div className="rounded-md border border-line bg-slate-50 px-3 py-2.5 text-xs leading-5 text-ink-600">
                  {grounding.isError
                    ? (grounding.error as Error).message
                    : grounding.data
                      ? `${grounding.data.vocabulary.actions.length} actions, ${grounding.data.vocabulary.roles.length} roles, ${grounding.data.matrix.cells.length} sampled cells grounded from the platform contract.`
                      : 'Loading platform contract grounding...'}
                </div>
                <Button
                  onClick={() => draftMutation.mutate()}
                  loading={draftMutation.isPending}
                  disabled={!canDraft || !intent.trim()}
                  className="w-full"
                >
                  <FileCheck size={15} /> Generate and validate draft
                </Button>
              </div>

              {draft && (
                <div className={`mt-4 rounded-md border p-4 ${draft.accepted ? 'border-emerald-200 bg-emerald-50' : 'border-red-200 bg-red-50'}`}>
                  <div className="flex items-center gap-2">
                    {draft.accepted ? <CheckCircle size={16} className="text-emerald-700" /> : <ShieldAlert size={16} className="text-red-700" />}
                    <p className="text-sm font-semibold text-ink-900">{draft.accepted ? 'Deterministic gate accepted the draft' : `Rejected at ${draft.validation.stage}`}</p>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-ink-500">{draft.draftId}</p>
                  {draft.validation.violations.length > 0 && (
                    <ul className="mt-3 space-y-1 text-xs text-red-800">
                      {draft.validation.violations.map((violation) => <li key={violation}>• {violation}</li>)}
                    </ul>
                  )}
                  {draft.canonicalYaml && (
                    <details className="mt-3">
                      <summary className="cursor-pointer text-xs font-medium text-ink-700">Inspect canonical policy</summary>
                      <pre className="mt-2 max-h-64 overflow-auto rounded-md bg-axiom-950 p-3 text-xs text-slate-100">{draft.canonicalYaml}</pre>
                    </details>
                  )}
                </div>
              )}
            </section>

            <section className="surface-card p-5">
              <div className="mb-4 flex items-start justify-between gap-3">
                <div>
                  <h2 className="section-heading">2. Compute business consequences</h2>
                  <p className="mt-1 text-xs leading-5 text-ink-500">Both immutable snapshots are evaluated by pinned Cerbos. If Cerbos is unavailable, this action fails closed.</p>
                </div>
                <Badge color="navy">No LLM truth</Badge>
              </div>
              <div className="rounded-md border border-line bg-slate-50 p-4">
                <p className="text-sm font-medium text-ink-900">Server-assembled review input</p>
                <p className="mt-1 text-xs leading-5 text-ink-500">
                  The current snapshot, base ceiling, sampled matrix, and fixture hash come from the platform contract and policy package.
                </p>
                {draft?.canonicalYaml && <p className="mt-3 break-all font-mono text-[11px] text-ink-500">Candidate: {draft.draftId}</p>}
              </div>
              <Button
                onClick={() => reviewMutation.mutate()}
                loading={reviewMutation.isPending}
                disabled={!draft?.accepted || !draft.canonicalYaml}
                className="mt-4 w-full"
              >
                <GitCompare size={15} /> Run real-Cerbos consequence review
              </Button>
            </section>
          </div>

          {review && (
            <>
              {review.displayProse && (
                <section className="surface-card p-5">
                  <div className="flex items-start gap-3">
                    <FileCheck size={17} className="mt-0.5 text-gold-700" />
                    <div>
                      <h2 className="section-heading">Plain-English consequence summary</h2>
                      <p className="mt-2 text-sm leading-6 text-ink-700">{review.displayProse}</p>
                    </div>
                  </div>
                </section>
              )}
              <ConsequencePanel review={review} />
              <section className="surface-card p-5">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <UserCheck size={17} className="text-gold-700" />
                      <h2 className="section-heading">3. Human approval and atomic promotion</h2>
                    </div>
                    <p className="mt-1 max-w-2xl text-xs leading-5 text-ink-500">Approval signs this exact consequence-review hash. The author cannot approve their own review.</p>
                  </div>
                  <Button disabled={!canApprove} onClick={() => setConfirmOpen(true)}>
                    <Lock size={14} /> Review promotion
                  </Button>
                </div>
                {!canApprove && <p className="mt-3 text-xs text-amber-700">A verified policy_approver must perform this step.</p>}
              </section>
            </>
          )}
        </div>
      )}

      {tab === 'lifecycle' && <LifecyclePanel canApprove={canApprove} identityScope={identityScope} />}
      {tab === 'emergency' && <BreakGlassPanel canDraft={canDraft} canApprove={canApprove} tenant={user?.tenantId || ''} identityScope={identityScope} />}

      <Dialog
        open={confirmOpen}
        onClose={() => { setConfirmOpen(false); setConsequencesConfirmed(false) }}
        title="Approve the reviewed consequences"
        description="This signs the exact review and atomically promotes the candidate bundle."
        size="xl"
      >
        <div className="space-y-4">
          <div className={`rounded-md border p-3 text-sm ${review?.overPermissionAlarm ? 'border-red-200 bg-red-50 text-red-900' : 'border-emerald-200 bg-emerald-50 text-emerald-900'}`}>
            {review?.overPermissionAlarm
              ? `${review.principalsGainingAccess} sampled principal(s) gain access. Review every widening consequence before continuing.`
              : 'The sampled matrix found no access widening.'}
          </div>
          <AdvancedJson
            title="Immutable candidate bundle"
            hint="Display-only evidence. Promotion loads this exact reviewed bundle from the server; browser edits are not accepted."
            value={candidateJson}
            rows={11}
          />
          <Input label="Idempotency key" value={idempotencyKey} onChange={(event) => setIdempotencyKey(event.target.value)} />
          <label className="flex items-start gap-2 rounded-md border border-line p-3 text-sm text-ink-700">
            <input
              type="checkbox"
              checked={consequencesConfirmed}
              onChange={(event) => setConsequencesConfirmed(event.target.checked)}
              className="mt-0.5 rounded border-line text-axiom-800 focus:ring-gold-300"
            />
            <span>I reviewed the machine-computed consequences and approve this exact review hash.</span>
          </label>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setConfirmOpen(false)}>Cancel</Button>
            <Button
              onClick={() => promotionMutation.mutate()}
              loading={promotionMutation.isPending}
              disabled={!consequencesConfirmed || !idempotencyKey.trim()}
            >
              <Lock size={14} /> Approve and promote
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}

function LifecyclePanel({ canApprove, identityScope }: { canApprove: boolean; identityScope: string }) {
  const { toast } = useToast()
  const [callId, setCallId] = useState('')
  const [examiner, setExaminer] = useState<Awaited<ReturnType<typeof studioApi.getExaminerChain>> | null>(null)
  useEffect(() => {
    setCallId('')
    setExaminer(null)
  }, [identityScope])
  const bundles = useQuery({ queryKey: ['studio-bundles', identityScope], queryFn: studioApi.listBundles, retry: false })
  const examinerMutation = useMutation({
    mutationFn: () => studioApi.getExaminerChain(callId),
    onSuccess: setExaminer,
    onError: (error: Error) => toast('error', error.message),
  })

  return (
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <section className="surface-panel">
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div>
            <h2 className="section-heading">Immutable bundle history</h2>
            <p className="mt-1 text-xs text-ink-500">Certified policy snapshots for the verified tenant.</p>
          </div>
          <Button variant="ghost" size="sm" onClick={() => void bundles.refetch()} loading={bundles.isFetching}><RefreshCw size={14} /> Refresh</Button>
        </div>
        {bundles.isError ? (
          <div className="px-5 py-8 text-center text-sm text-red-700">{(bundles.error as Error).message}</div>
        ) : bundles.isLoading ? (
          <div className="px-5 py-8 text-center text-sm text-ink-500">Loading bundle history…</div>
        ) : (bundles.data?.length || 0) === 0 ? (
          <div className="px-5 py-10 text-center"><History className="mx-auto text-slate-300" /><p className="mt-2 text-sm text-ink-500">No certified bundles yet.</p></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs text-ink-500"><tr><th className="px-5 py-3 font-medium">Bundle</th><th className="px-4 py-3 font-medium">Evidence</th><th className="px-4 py-3 font-medium">Created</th></tr></thead>
              <tbody className="divide-y divide-line">
                {bundles.data?.map((bundle) => (
                  <tr key={bundle.bundleId} className="hover:bg-slate-50/70">
                    <td className="px-5 py-3"><p className="font-mono text-xs font-medium text-ink-800">{bundle.bundleId}</p><p className="mt-1 text-xs text-ink-500">Git {bundle.gitCommit}</p></td>
                    <td className="px-4 py-3"><Badge color="green">{bundle.testCount} tests</Badge><p className="mt-1 text-xs text-ink-500">{bundle.pdpSourceId}</p></td>
                    <td className="px-4 py-3 text-xs text-ink-600">{formatTime(bundle.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="surface-card p-5">
        <div className="flex items-center gap-2"><Activity size={17} className="text-gold-700" /><h2 className="section-heading">Examiner chain</h2></div>
        <p className="mt-1 text-xs leading-5 text-ink-500">Reconstruct one authorization decision without an LLM: transaction → Cerbos decision → bundle → Git → human approval.</p>
        <div className="mt-4 flex gap-2">
          <div className="flex-1"><Input aria-label="Cerbos call ID" placeholder="Cerbos call ID" value={callId} onChange={(event) => setCallId(event.target.value)} /></div>
          <Button onClick={() => examinerMutation.mutate()} disabled={!callId.trim()} loading={examinerMutation.isPending}><Search size={14} /> Trace</Button>
        </div>
        {examiner && (
          <div className="mt-4 space-y-3 rounded-md border border-line bg-slate-50 p-4 text-xs">
            <div className="flex items-center justify-between"><span className="text-ink-500">Integrity</span><Badge color={examiner.complete && examiner.approvalSignatureValid ? 'green' : 'red'}>{examiner.complete ? 'Complete' : 'Incomplete'}</Badge></div>
            <div className="flex items-center justify-between gap-4"><span className="text-ink-500">Decision</span><span className="font-mono text-ink-900">{examiner.decision}</span></div>
            <div className="flex items-center justify-between gap-4"><span className="text-ink-500">Bundle</span><span className="truncate font-mono text-ink-900">{examiner.bundleId}</span></div>
            <div className="flex items-center justify-between gap-4"><span className="text-ink-500">Approver</span><span className="text-ink-900">{examiner.approverId}</span></div>
            <div className="flex items-center justify-between gap-4"><span className="text-ink-500">Action</span><span className="text-ink-900">{examiner.resourceKind}:{examiner.action}</span></div>
          </div>
        )}
        {!canApprove && <p className="mt-4 text-xs text-ink-500">History and evidence are read-only for your current roles.</p>}
      </section>
    </div>
  )
}

function BreakGlassPanel({ canDraft, canApprove, tenant, identityScope }: { canDraft: boolean; canApprove: boolean; tenant: string; identityScope: string }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [resourceKind] = useState('iam-resource')
  const [action, setAction] = useState('')
  const [role, setRole] = useState('')
  const [ttl, setTtl] = useState(30)
  const [justification, setJustification] = useState('')
  useEffect(() => {
    setAction('')
    setRole('')
    setTtl(30)
    setJustification('')
  }, [identityScope])
  const grants = useQuery({ queryKey: ['studio-break-glass', identityScope], queryFn: studioApi.listBreakGlass, retry: false })
  const grounding = useQuery({
    queryKey: ['studio-grounding', identityScope, resourceKind],
    queryFn: () => studioApi.getVocabulary(resourceKind),
    enabled: Boolean(tenant && resourceKind),
    retry: false,
  })

  const requestMutation = useMutation({
    mutationFn: async () => {
      if (!grounding.data) throw new Error('Platform contract grounding is not loaded yet.')
      const payload: BreakGlassRequest = {
        scope: tenant, resourceKind, action, role, ttlMinutes: ttl, justification,
      }
      return studioApi.requestBreakGlass(payload)
    },
    onSuccess: (grant) => {
      void queryClient.invalidateQueries({ queryKey: ['studio-break-glass'] })
      toast(grant.admissible ? 'success' : 'error', grant.admissible ? 'Emergency grant is ready for a second-person approval' : 'Emergency grant was rejected')
    },
    onError: (error: Error) => toast('error', error.message),
  })

  const approveMutation = useMutation({
    mutationFn: (grantId: string) => studioApi.approveBreakGlass(grantId),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['studio-break-glass'] }); toast('success', 'Emergency grant approved and audited') },
    onError: (error: Error) => toast('error', error.message),
  })

  const activeCount = useMemo(() => grants.data?.filter((grant) => grant.issued).length || 0, [grants.data])

  return (
    <div className="space-y-6">
      <div className="rounded-md border border-red-200 bg-red-50 px-4 py-3">
        <div className="flex items-start gap-3"><ShieldAlert size={18} className="mt-0.5 text-red-700" /><div><p className="text-sm font-semibold text-red-950">Emergency access remains two-person and time bounded</p><p className="mt-1 text-xs leading-5 text-red-800">Maximum 60 minutes. The expiry condition is enforced inside Cerbos; every issuance and use is audited.</p></div></div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.85fr_1.15fr]">
        <section className="surface-card p-5">
          <div className="flex items-start justify-between"><div><h2 className="section-heading">Request emergency access</h2><p className="mt-1 text-xs text-ink-500">Requester identity and tenant come from the verified token.</p></div><Badge color={canDraft ? 'yellow' : 'slate'}>{canDraft ? 'Drafter' : 'View only'}</Badge></div>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <Input label="Resource kind" value={resourceKind} readOnly />
            <Input label="Action" value={action} onChange={(event) => setAction(event.target.value)} />
            <Input label="Role" value={role} onChange={(event) => setRole(event.target.value)} />
            <Input label="TTL minutes" type="number" min={1} max={60} value={ttl} onChange={(event) => setTtl(Number(event.target.value))} />
          </div>
          <div className="mt-3"><Textarea label="Incident justification" value={justification} onChange={(event) => setJustification(event.target.value)} rows={3} placeholder="Incident or operational reason" /></div>
          <div className="mt-3 rounded-md border border-line bg-slate-50 px-3 py-2.5 text-xs leading-5 text-ink-600">
            {grounding.isError
              ? (grounding.error as Error).message
              : grounding.data
                ? `Emergency grounding loaded from the platform policy package for ${grounding.data.vocabulary.resourceKind}.`
                : 'Loading emergency grounding...'}
          </div>
          <Button className="mt-4 w-full" variant="danger" loading={requestMutation.isPending} disabled={!canDraft || !tenant || !resourceKind || !action || !role || !justification.trim() || ttl < 1 || ttl > 60 || !grounding.data} onClick={() => requestMutation.mutate()}><Siren size={14} /> Request break-glass grant</Button>
        </section>

        <section className="surface-panel">
          <div className="flex items-center justify-between border-b border-line px-5 py-4"><div><h2 className="section-heading">Active and pending grants</h2><p className="mt-1 text-xs text-ink-500">{activeCount} currently issued</p></div><Button variant="ghost" size="sm" onClick={() => void grants.refetch()} loading={grants.isFetching}><RefreshCw size={14} /> Refresh</Button></div>
          {grants.isError ? <div className="px-5 py-8 text-center text-sm text-red-700">{(grants.error as Error).message}</div>
            : (grants.data?.length || 0) === 0 ? <div className="px-5 py-10 text-center"><Siren className="mx-auto text-slate-300" /><p className="mt-2 text-sm text-ink-500">No active emergency grants.</p></div>
              : <div className="divide-y divide-line">{grants.data?.map((grant) => (
                <div key={grant.grantId} className="px-5 py-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div><div className="flex items-center gap-2"><Badge color={grant.issued ? 'red' : grant.admissible ? 'yellow' : 'slate'}>{grant.issued ? 'ACTIVE' : grant.admissible ? 'PENDING APPROVAL' : 'REJECTED'}</Badge><span className="font-mono text-xs text-ink-500">{grant.grantId}</span></div><p className="mt-2 text-sm text-ink-800">Requested by <span className="font-medium">{grant.requestedBy}</span></p><div className="mt-1 flex items-center gap-1.5 text-xs text-ink-500"><Clock size={13} /> Expires {formatTime(grant.expiresAt)}</div></div>
                    {!grant.issued && grant.admissible && <Button size="sm" disabled={!canApprove} loading={approveMutation.isPending} onClick={() => approveMutation.mutate(grant.grantId)}><UserCheck size={14} /> Approve</Button>}
                  </div>
                  {[...grant.boundsViolations, ...grant.c2Violations].map((violation) => <p key={violation} className="mt-2 text-xs text-red-700">• {violation}</p>)}
                </div>
              ))}</div>}
        </section>
      </div>
    </div>
  )
}
