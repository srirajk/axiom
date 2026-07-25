import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Clock, ChevronDown, ChevronUp, Download, AlertCircle, RefreshCw } from 'lucide-react'
import { auditApi, type AuditEntry } from '../api/client'
import { Button } from '../components/ui/Button'
import { Input, Select } from '../components/ui/Input'
import { Skeleton } from '../components/ui/Skeleton'
import { EmptyState } from '../components/ui/EmptyState'
import { useToast } from '../components/ui/Toast'

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-100 text-green-800 border-green-300',
  update: 'bg-blue-100 text-blue-800 border-blue-300',
  delete: 'bg-red-100 text-red-800 border-red-300',
  assign: 'bg-purple-100 text-purple-800 border-purple-300',
  deploy: 'bg-orange-100 text-orange-800 border-orange-300',
}

function getActionColor(action: string): string {
  const normalized = action.toLowerCase()
  for (const [key, color] of Object.entries(ACTION_COLORS)) {
    if (normalized.includes(key)) return color
  }
  return 'bg-slate-100 text-slate-800 border-slate-300'
}

function formatTime(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function getRelativeTime(dateStr: string): string {
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

function AuditRow({ entry, isExpanded, onToggle }: {
  entry: AuditEntry
  isExpanded: boolean
  onToggle: () => void
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="border-b border-slate-100 hover:bg-slate-50 transition-colors cursor-pointer group"
      >
        <td className="px-5 py-3.5">
          <div className="flex items-center gap-3">
            <button
              onClick={(e) => {
                e.stopPropagation()
                onToggle()
              }}
              className="text-slate-400 hover:text-slate-600 transition-colors"
            >
              {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            <div>
              <p className="text-sm font-mono text-slate-700">{entry.occurredAt.split('T')[0]}</p>
              <p className="text-xs text-slate-500" title={formatTime(entry.occurredAt)}>
                {getRelativeTime(entry.occurredAt)}
              </p>
            </div>
          </div>
        </td>
        <td className="px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-slate-200 flex items-center justify-center text-xs font-semibold text-slate-700">
              {entry.actorId.charAt(0).toUpperCase()}
            </div>
            <div>
              <p className="text-sm font-medium text-slate-900">{entry.actorId}</p>
              <p className="text-xs font-mono text-slate-500">{entry.sourceIp}</p>
            </div>
          </div>
        </td>
        <td className="px-5 py-3.5">
          <span className={`inline-flex px-2.5 py-1 rounded-full text-xs font-semibold border ${getActionColor(entry.action)}`}>
            {entry.action}
          </span>
        </td>
        <td className="px-5 py-3.5">
          <span className="inline-flex px-2 py-1 rounded text-xs font-medium bg-slate-100 text-slate-700">
            {entry.resourceType}
          </span>
        </td>
        <td className="px-5 py-3.5 font-mono text-xs text-slate-600 max-w-[200px] truncate">
          {entry.resourceId}
        </td>
      </tr>

      {isExpanded && (
        <tr className="bg-slate-50 border-b border-slate-100">
          <td colSpan={5} className="px-5 py-4">
            <div className="grid grid-cols-2 gap-6">
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase mb-2">Before State</p>
                <pre className="bg-slate-900 text-slate-100 p-3 rounded text-xs overflow-auto max-h-48 font-mono">
                  {entry.beforeState
                    ? JSON.stringify(entry.beforeState, null, 2)
                    : 'No previous state'}
                </pre>
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-500 uppercase mb-2">After State</p>
                <pre className="bg-slate-900 text-slate-100 p-3 rounded text-xs overflow-auto max-h-48 font-mono">
                  {entry.afterState
                    ? JSON.stringify(entry.afterState, null, 2)
                    : 'No changes'}
                </pre>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function AuditLog() {
  const pageSize = 10
  const { toast } = useToast()
  const [page, setPage] = useState(0)
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['audit', page, pageSize],
    queryFn: () => auditApi.list(page, pageSize),
    retry: false,
  })
  const queryError = isError
    ? error instanceof Error ? error.message : 'Failed to load audit entries'
    : null

  const handleExport = async () => {
    try {
      const entries = await auditApi.export()
      const json = JSON.stringify(entries, null, 2)
      const blob = new Blob([json], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `audit-log-${new Date().toISOString().split('T')[0]}.json`
      a.click()
      URL.revokeObjectURL(url)
      toast('success', 'Audit log exported')
    } catch (err) {
      toast('error', (err as Error).message)
    }
  }

  // Filter entries on client side (simplified demo)
  const filtered = useMemo(() => {
    if (!data?.content) return []
    return data.content.filter(e => {
      const occurredAt = new Date(e.occurredAt).getTime()
      if (dateFrom) {
        const from = new Date(`${dateFrom}T00:00:00.000Z`).getTime()
        if (occurredAt < from) return false
      }
      if (dateTo) {
        const to = new Date(`${dateTo}T23:59:59.999Z`).getTime()
        if (occurredAt > to) return false
      }
      if (actor && !e.actorId.toLowerCase().includes(actor.toLowerCase())) return false
      if (action && !e.action.toLowerCase().includes(action.toLowerCase())) return false
      return true
    })
  }, [data, dateFrom, dateTo, actor, action])

  return (
    <div className="px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center">
                <Clock size={16} className="text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-900">Audit Log</h1>
              </div>
            </div>
            <p className="text-sm text-slate-500 mt-2">Immutable record of all changes to this tenant</p>
          </div>
          <Button onClick={handleExport} variant="secondary" size="sm">
            <Download size={14} /> Export
          </Button>
        </div>
      </div>

      {/* Error state */}
      {queryError && (
        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3" role="alert">
          <AlertCircle size={18} className="text-red-600 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-medium text-red-900">{queryError}</p>
          </div>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => { void refetch() }}
          >
            <RefreshCw size={14} /> Retry
          </Button>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg border border-slate-200 p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Input
            label="Date from"
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
          />
          <Input
            label="Date to"
            type="date"
            value={dateTo}
            onChange={e => setDateTo(e.target.value)}
          />
          <Input
            label="Actor"
            placeholder="Filter by actor ID…"
            value={actor}
            onChange={e => setActor(e.target.value)}
          />
          <Select
            label="Action"
            value={action}
            onChange={e => setAction(e.target.value)}
          >
            <option value="">All actions</option>
            <option value="create">Create</option>
            <option value="update">Update</option>
            <option value="delete">Delete</option>
            <option value="assign">Assign</option>
            <option value="deploy">Deploy</option>
          </Select>
        </div>
        <div className="flex gap-2 mt-4">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => { setDateFrom(''); setDateTo(''); setActor(''); setAction('') }}
          >
            Clear filters
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
        {isLoading ? (
          <div className="space-y-0">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="px-5 py-3.5 border-b border-slate-100">
                <div className="space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </div>
            ))}
          </div>
        ) : queryError ? (
          <EmptyState
            icon={<AlertCircle size={48} />}
            title="Audit log unavailable"
            description="Retry the request after the service recovers"
          />
        ) : filtered.length === 0 ? (
          <>
            <EmptyState
              icon={<Clock size={48} />}
              title="No audit entries found"
              description="Try adjusting your filters or move between pages"
            />
            {data && (
              <div className="px-5 py-4 border-t border-slate-200 flex items-center justify-between bg-slate-50">
                <p className="text-sm text-slate-600">
                  Page {page + 1} of {data.totalPages} · {data.totalElements} total entries
                </p>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page === 0}
                    onClick={() => setPage(Math.max(0, page - 1))}
                  >
                    Previous
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page >= data.totalPages - 1}
                    onClick={() => setPage(Math.min(data.totalPages - 1, page + 1))}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        ) : (
          <>
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide" style={{ width: '200px' }}>
                    Time
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">
                    Actor
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide" style={{ width: '120px' }}>
                    Action
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide" style={{ width: '100px' }}>
                    Resource Type
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-medium text-slate-500 uppercase tracking-wide">
                    Resource ID
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(entry => (
                  <AuditRow
                    key={entry.id}
                    entry={entry}
                    isExpanded={expandedId === entry.id}
                    onToggle={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                  />
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            {data && (
              <div className="px-5 py-4 border-t border-slate-200 flex items-center justify-between bg-slate-50">
                <p className="text-sm text-slate-600">
                  Page {page + 1} of {data.totalPages} · {data.totalElements} total entries
                </p>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page === 0}
                    onClick={() => setPage(Math.max(0, page - 1))}
                  >
                    Previous
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={page >= data.totalPages - 1}
                    onClick={() => setPage(Math.min(data.totalPages - 1, page + 1))}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
