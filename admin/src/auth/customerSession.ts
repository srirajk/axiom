const TOKEN_KEY = 'axiom_customer_access_token'

export interface CustomerSessionClaims {
  sub: string
  tenantId: string
  clientId: string
  scopes: string[]
  expiresAt: number
}

function decodeBase64Url(value: string): string {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '=')
  const binary = atob(padded)
  return new TextDecoder().decode(Uint8Array.from(binary, char => char.charCodeAt(0)))
}

export function customerClaims(token: string): CustomerSessionClaims | null {
  try {
    const payload = JSON.parse(decodeBase64Url(token.split('.')[1] || '')) as Record<string, unknown>
    if (payload.identity_kind !== 'customer' || typeof payload.sub !== 'string'
      || typeof payload.tenant_id !== 'string' || typeof payload.client_id !== 'string'
      || typeof payload.exp !== 'number' || payload.exp <= Math.floor(Date.now() / 1000)) return null
    const rawScopes = typeof payload.scope === 'string' ? payload.scope.split(/\s+/).filter(Boolean) : []
    return { sub: payload.sub, tenantId: payload.tenant_id, clientId: payload.client_id,
      scopes: rawScopes, expiresAt: payload.exp }
  } catch {
    return null
  }
}

export function readCustomerToken(): string {
  const value = sessionStorage.getItem(TOKEN_KEY) || ''
  if (value && !customerClaims(value)) {
    sessionStorage.removeItem(TOKEN_KEY)
    return ''
  }
  return value
}

export function writeCustomerToken(value: string): void {
  sessionStorage.setItem(TOKEN_KEY, value)
}

export function clearCustomerToken(): void {
  sessionStorage.removeItem(TOKEN_KEY)
}
