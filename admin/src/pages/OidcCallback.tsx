import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { completeAuthorization } from '../auth/oidc'
import { writeAdminIdToken } from '../auth/tokenStorage'
import { decodePayload, hasAdminRole, useAuth } from '../hooks/useAuth'

export function OidcCallback() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    void completeAuthorization(new URL(window.location.href))
      .then(({ accessToken, idToken }) => {
        // Access-token decoding supplies display chrome only; Axiom independently verifies API authority.
        const user = decodePayload(accessToken)
        if (!user || !hasAdminRole(user)) throw new Error('This account is not authorized for the admin console.')
        if (active) {
          writeAdminIdToken(idToken)
          login(accessToken, user)
          navigate('/', { replace: true })
        }
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : 'Authorization failed.')
      })
    return () => { active = false }
  }, [login, navigate])

  return (
    <main className="min-h-screen bg-axiom-950 flex items-center justify-center px-4 text-white">
      <div className="w-full max-w-md rounded-lg border border-white/10 bg-axiom-900 p-6">
        <p className="text-sm font-medium">Axiom Admin</p>
        {error ? <p className="mt-3 text-sm text-red-200">{error}</p> : <p className="mt-3 text-sm text-slate-300">Completing secure sign-in…</p>}
      </div>
    </main>
  )
}
