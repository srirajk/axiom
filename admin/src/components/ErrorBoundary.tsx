import React from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { Button } from './ui/Button'

interface Props {
  children: React.ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('Axiom route crashed', error, info)
  }

  render() {
    if (!this.state.error) return this.props.children

    return (
      <div className="page-shell">
        <div className="surface-panel px-6 py-8">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-md bg-red-50 text-red-700 ring-1 ring-red-600/20">
                <AlertTriangle size={18} />
              </div>
              <div>
                <h1 className="text-base font-semibold text-ink-900">This view could not render</h1>
                <p className="mt-1 text-sm text-ink-500">
                  The rest of Axiom is still available. Reload this view after the latest data settles.
                </p>
                <p className="mt-2 max-w-2xl truncate font-mono text-xs text-red-700">
                  {this.state.error.message}
                </p>
              </div>
            </div>
            <Button type="button" variant="secondary" onClick={() => window.location.reload()}>
              <RefreshCw size={14} />
              Reload
            </Button>
          </div>
        </div>
      </div>
    )
  }
}
