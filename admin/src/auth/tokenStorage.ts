// Access tokens are process-memory only. The Admin client does not request refresh tokens: after a
// reload it reauthorizes through the issuer rather than persisting credentials in a browser.
let adminToken = ''
let adminIdToken = ''
export const AUTH_LOGOUT_EVENT = 'axiom-auth:logout'

export function readAdminToken(): string {
  return adminToken
}

export function writeAdminToken(token: string): void {
  adminToken = token
}

export function readAdminIdToken(): string {
  return adminIdToken
}

export function writeAdminIdToken(token: string): void {
  adminIdToken = token
}

export function clearAdminToken(): void {
  adminToken = ''
  adminIdToken = ''
}

export function notifyAuthLogout(): void {
  window.dispatchEvent(new CustomEvent(AUTH_LOGOUT_EVENT))
}
