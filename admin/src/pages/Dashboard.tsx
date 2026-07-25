import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Users, UsersRound, Shield, Activity, ArrowRight } from 'lucide-react'
import { statsApi, auditApi } from '../api/client'
import { useAuth } from '../hooks/useAuth'
import { Skeleton } from '../components/ui/Skeleton'
import { EmptyState } from '../components/ui/EmptyState'

const STAT_TONES = {
  navy: {
    icon: 'bg-axiom-900 text-gold-200 ring-1 ring-gold-400/30',
    accent: 'bg-gold-400',
  },
  gold: {
    icon: 'bg-gold-100 text-gold-800 ring-1 ring-gold-500/25',
    accent: 'bg-gold-500',
  },
  emerald: {
    icon: 'bg-emerald-100 text-emerald-800 ring-1 ring-emerald-600/20',
    accent: 'bg-emerald-500',
  },
  sky: {
    icon: 'bg-sky-100 text-sky-800 ring-1 ring-sky-600/20',
    accent: 'bg-sky-500',
  },
}

function StatCard({
  label,
  value,
  icon: Icon,
  tone,
  onClick,
}: {
  label: string
  value: number | string
  icon: React.ElementType
  tone: keyof typeof STAT_TONES
  onClick?: () => void
}) {
  const toneClasses = STAT_TONES[tone]

  return (
    <button
      onClick={onClick}
      className="surface-card relative w-full overflow-hidden p-4 text-left flex items-center gap-4 hover:border-axiom-300 transition-colors group"
    >
      <div className={`absolute left-0 top-0 h-full w-1 ${toneClasses.accent}`} />
      <div className={`w-10 h-10 rounded-md flex items-center justify-center ${toneClasses.icon}`}>
        <Icon size={18} />
      </div>
      <div className="flex-1">
        <p className="text-2xl font-semibold text-ink-900 tabular-nums">{value}</p>
        <p className="text-sm text-ink-500 group-hover:text-ink-700 transition-colors">{label}</p>
      </div>
      <ArrowRight size={16} className="text-slate-300 group-hover:text-gold-600 transition-colors opacity-0 group-hover:opacity-100" />
    </button>
  )
}

function SkeletonCard() {
  return (
    <div className="surface-card p-4 flex items-center gap-4">
      <Skeleton className="w-10 h-10 rounded-md" />
      <div className="flex-1">
        <Skeleton className="h-7 w-16 mb-2" />
        <Skeleton className="h-4 w-24" />
      </div>
    </div>
  )
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)

  if (seconds < 60) return 'just now'
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-600/20',
  update: 'bg-sky-50 text-sky-800 ring-1 ring-sky-600/20',
  delete: 'bg-red-50 text-red-800 ring-1 ring-red-600/20',
  assign: 'bg-gold-50 text-gold-800 ring-1 ring-gold-600/25',
  deploy: 'bg-axiom-50 text-axiom-800 ring-1 ring-axiom-600/20',
}

function getActionColor(action: string): string {
  const normalized = action.toLowerCase()
  for (const [key, color] of Object.entries(ACTION_COLORS)) {
    if (normalized.includes(key)) return color
  }
  return 'bg-slate-100 text-slate-700'
}

export function Dashboard() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { data: stats, isLoading: statsLoading, isError: statsError } = useQuery({
    queryKey: ['stats'],
    queryFn: statsApi.get,
    retry: false,
  })
  const { data: auditData, isLoading: auditLoading, isError: auditError } = useQuery({
    queryKey: ['audit', 0, 5],
    queryFn: () => auditApi.list(0, 5),
    retry: false,
  })
  const [loadingTimedOut, setLoadingTimedOut] = useState(false)
  const dashboardLoading = statsLoading || auditLoading
  useEffect(() => {
    if (!dashboardLoading) { setLoadingTimedOut(false); return }
    const timer = window.setTimeout(() => setLoadingTimedOut(true), 5000)
    return () => window.clearTimeout(timer)
  }, [dashboardLoading])

  return (
    <div className="page-shell">
      {/* Header */}
      <div className="mb-6 flex flex-col gap-3 border-b border-line pb-5 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="page-kicker mb-2">Axiom Admin</p>
          <h1 className="text-2xl font-semibold text-ink-900">Identity Overview</h1>
          <p className="muted-copy mt-1">
            Signed in as {user?.username ?? 'administrator'}
          </p>
        </div>
        <div className="inline-flex items-center gap-2 self-start rounded-md border border-line bg-white px-3 py-2 text-xs font-medium text-ink-700 sm:self-auto">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          Axiom platform services
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 gap-3 mb-6 sm:grid-cols-2 xl:grid-cols-4">
        {dashboardLoading && !loadingTimedOut ? (
          <>
            {[...Array(4)].map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </>
        ) : stats ? (
          <>
            <StatCard
              label="Users"
              value={stats.totalUsers}
              icon={Users}
              tone="navy"
              onClick={() => navigate('/users')}
            />
            <StatCard
              label="Teams"
              value={stats.totalTeams}
              icon={UsersRound}
              tone="sky"
              onClick={() => navigate('/teams')}
            />
            <StatCard
              label="Roles"
              value={stats.totalRoles}
              icon={Shield}
              tone="emerald"
              onClick={() => navigate('/roles')}
            />
          </>
        ) : (
          <EmptyState icon={<Users size={32} />} title={statsError || loadingTimedOut ? 'Identity metrics unavailable' : 'No identity metrics'} description={loadingTimedOut ? 'The metrics service did not respond within the bounded wait window.' : 'Identity metrics will appear when the service returns them.'} />
        )}
      </div>

      {/* Recent Activity Card */}
      <div className="surface-panel">
        <div className="px-5 py-4 border-b border-line flex items-center gap-2 bg-slate-50/70">
          <Activity size={16} className="text-gold-600" />
          <h2 className="section-heading">Recent Activity</h2>
        </div>

        {auditLoading && !loadingTimedOut ? (
          <div className="space-y-0">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="px-5 py-3 border-b border-slate-100 last:border-b-0">
                <div className="space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </div>
            ))}
          </div>
        ) : auditData?.content && auditData.content.length > 0 ? (
          <>
            <div className="divide-y divide-slate-100">
              {auditData.content.map((entry) => (
                <div key={entry.id} className="px-5 py-3.5 hover:bg-axiom-50/50 transition-colors group">
                  <div className="flex items-center gap-3 mb-1">
                    <div className="w-7 h-7 rounded-md bg-axiom-50 ring-1 ring-axiom-600/10 flex items-center justify-center text-xs font-semibold text-axiom-800 shrink-0">
                      {entry.actorId.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-ink-900">
                        <span className="font-medium">{entry.actorId}</span>
                        {' '}
                        <span className="text-ink-700">{entry.action}</span>
                        {' '}
                        <span className={`inline-flex px-1.5 py-0.5 rounded-md text-xs font-medium ${getActionColor(entry.action)}`}>
                          {entry.resourceType}
                        </span>
                      </p>
                      <p className="text-xs text-ink-500 mt-0.5">
                        {entry.resourceId} · {formatRelativeTime(entry.occurredAt)}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            <button
              onClick={() => navigate('/audit')}
              className="w-full px-5 py-3 text-sm font-medium text-axiom-800 hover:bg-axiom-50 border-t border-line transition-colors"
            >
              View all activity →
            </button>
          </>
        ) : (
          <div className="px-5 py-10">
            <EmptyState
              icon={<Activity size={32} />}
              title={auditError || loadingTimedOut ? 'Activity unavailable' : 'No activity yet'}
              description={loadingTimedOut ? 'The activity service did not respond within the bounded wait window.' : auditError ? 'Recent activity could not be loaded from the audit service.' : 'Activity will appear here as changes are made'}
            />
          </div>
        )}
      </div>
    </div>
  )
}
