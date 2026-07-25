import { useState } from 'react'
import { beginAuthorization } from '../auth/oidc'
import { Button } from '../components/ui/Button'
import { LockKeyhole, ShieldCheck } from 'lucide-react'

export function Login() {
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  async function submit() {
    setError('')
    setLoading(true)
    try {
      await beginAuthorization()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-axiom-950 flex items-center justify-center px-4 py-8">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-axiom-700 via-gold-400 to-axiom-500" />
      <div className="w-full max-w-4xl grid overflow-hidden rounded-lg border border-white/10 bg-panel shadow-enterprise md:grid-cols-[0.9fr_1fr]">
        <div className="hidden md:flex flex-col justify-between bg-axiom-900 px-8 py-8 text-white">
          <div className="flex items-center gap-3">
            <div className="axiom-mark w-10 h-10">
              <span className="font-bold">A</span>
            </div>
            <div>
              <p className="text-base font-semibold">Axiom</p>
              <p className="text-xs text-slate-400">Identity & platform policy</p>
            </div>
          </div>

          <div>
            <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-md border border-gold-300/30 bg-white/5 text-gold-200">
              <ShieldCheck size={20} />
            </div>
            <h1 className="text-2xl font-semibold text-white">Admin Console</h1>
            <p className="mt-2 text-sm leading-6 text-slate-300">Authorized administrators only.</p>
          </div>

          <p className="text-xs text-slate-400">Axiom Identity Platform</p>
        </div>

        <div className="px-6 py-8 sm:px-8">
          <div className="mb-7 flex items-center gap-3 md:hidden">
            <div className="axiom-mark w-9 h-9">
              <span className="font-bold">A</span>
            </div>
            <div>
              <p className="text-base font-semibold text-ink-900">Axiom</p>
              <p className="text-xs text-ink-500">Identity & platform policy</p>
            </div>
          </div>

          <p className="page-kicker mb-2">Axiom Identity Platform</p>
          <h1 className="text-xl font-semibold text-ink-900 mb-1">Admin Console</h1>
          <p className="text-sm text-ink-500 mb-6">Continue with your Axiom identity provider.</p>

          {error && (
            <div className="mb-4 px-3 py-2.5 bg-red-50 border border-red-200 rounded-md text-sm text-red-700">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <Button type="button" onClick={() => void submit()} loading={loading} className="w-full mt-2">
              <LockKeyhole size={14} />
              Continue securely
            </Button>
            <p className="text-xs leading-5 text-ink-500">Authorization Code + S256 PKCE. This console never stores a browser client secret or password.</p>
          </div>

        </div>
      </div>
    </div>
  )
}
