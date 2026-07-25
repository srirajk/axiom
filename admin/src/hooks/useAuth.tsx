import React, { createContext, useContext, useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { User } from '../api/client'
import { normalizeSegments } from '../api/client'
import { AUTH_LOGOUT_EVENT, clearAdminToken, readAdminIdToken, readAdminToken, writeAdminToken } from '../auth/tokenStorage'
import { endAuthorization } from '../auth/oidc'

/** Roles that may enter the admin console shell. Studio users are still method-gated per endpoint. */
export const ADMIN_ROLES = ['platform_admin', 'tenant_admin', 'domain_admin', 'policy_author', 'policy_approver']
export function hasAdminRole(user: User | null): boolean {
  return user?.roles?.some((r) => ADMIN_ROLES.includes(r)) ?? false
}

interface AuthCtx {
  user: User | null
  token: string
  login: (token: string, user: User) => void
  logout: () => void
  isAdmin: boolean
}

const Ctx = createContext<AuthCtx | null>(null)

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=')
  const binary = atob(padded)
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
  return new TextDecoder().decode(bytes)
}

export function decodePayload(token: string): User | null {
  try {
    const part = token.split('.')[1]
    if (!part) return null
    const json = decodeBase64Url(part)
    const p = JSON.parse(json)
    const now = Math.floor(Date.now() / 1000)
    if (p.exp && p.exp < now) return null
    return {
      id: p.sub,
      username: p.username || p.name || p.sub,
      email: p.email || '',
      roles: p.roles || [],
      segments: normalizeSegments(p.segments),
      clearance: p.clearance || 1,
      classification: p.classification || 'public',
      team: p.team || '',
      adminDomains: p.admin_domains || p.adminDomains || [],
      tenantId: p.tenant_id || '',
    }
  } catch {
    return null
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const [token, setToken] = useState(() => readAdminToken())
  const [user, setUser] = useState<User | null>(() => {
    const t = readAdminToken()
    return t ? decodePayload(t) : null
  })
  const identityRef = useRef(user ? `${user.tenantId}:${user.id}` : '')

  const login = useCallback((t: string, u: User) => {
    queryClient.clear()
    writeAdminToken(t)
    const verifiedClaims = decodePayload(t)
    setToken(t)
    setUser(verifiedClaims ? { ...u, ...verifiedClaims } : u)
  }, [queryClient])

  const logout = useCallback(() => {
    const idTokenHint = readAdminIdToken()
    queryClient.clear()
    clearAdminToken()
    setToken('')
    setUser(null)
    void endAuthorization(idTokenHint)
  }, [queryClient])

  const syncFromStorage = useCallback(() => {
    const nextToken = readAdminToken()
    const nextUser = nextToken ? decodePayload(nextToken) : null
    if (nextToken && !nextUser) {
      clearAdminToken()
      setToken('')
      setUser(null)
      return
    }
    setToken(nextToken)
    setUser(nextUser)
  }, [])

  useEffect(() => {
    syncFromStorage()
    const onLogout = () => {
      queryClient.clear()
      setToken('')
      setUser(null)
    }
    window.addEventListener(AUTH_LOGOUT_EVENT, onLogout)
    return () => {
      window.removeEventListener(AUTH_LOGOUT_EVENT, onLogout)
    }
  }, [queryClient, syncFromStorage])

  useEffect(() => {
    const identity = user ? `${user.tenantId}:${user.id}` : ''
    if (identityRef.current !== identity) {
      queryClient.clear()
      identityRef.current = identity
    }
  }, [queryClient, user])

  const isAdmin = useMemo(() => user?.roles.includes('platform_admin') ?? false, [user?.roles])
  const value = useMemo(
    () => ({ user, token, login, logout, isAdmin }),
    [user, token, login, logout, isAdmin],
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useAuth must be inside AuthProvider')
  return ctx
}
