const TRANSACTION_KEY = 'axiom-admin.pkce.transaction.v1'
const CLIENT_ID = 'axiom-admin'

type Transaction = {
  state: string
  nonce: string
  verifier: string
}

function issuer(): string {
  return (import.meta.env.VITE_AXIOM_ISSUER || 'http://localhost:8085').replace(/\/$/, '')
}

function redirectUri(): string {
  return `${window.location.origin}/callback`
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((value) => { binary += String.fromCharCode(value) })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomValue(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return base64Url(bytes)
}

async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64Url(new Uint8Array(digest))
}

export async function beginAuthorization(): Promise<void> {
  const transaction: Transaction = { state: randomValue(), nonce: randomValue(), verifier: randomValue() }
  sessionStorage.setItem(TRANSACTION_KEY, JSON.stringify(transaction))
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: redirectUri(),
    scope: 'openid profile email roles',
    state: transaction.state,
    nonce: transaction.nonce,
    code_challenge: await s256(transaction.verifier),
    code_challenge_method: 'S256',
  })
  const metadata = await discovery()
  window.location.assign(`${metadata.authorization_endpoint}?${params}`)
}

type TokenResponse = { access_token?: string, id_token?: string }
type CompletedAuthorization = { accessToken: string, idToken: string }
type SigningJwk = JsonWebKey & { kid?: string, alg?: string, use?: string, key_ops?: string[] }
type DiscoveryDocument = {
  issuer?: string
  authorization_endpoint?: string
  token_endpoint?: string
  jwks_uri?: string
  end_session_endpoint?: string
}
type RequiredDiscovery = Required<Pick<DiscoveryDocument,
  'authorization_endpoint' | 'token_endpoint' | 'jwks_uri'>> & DiscoveryDocument

let discoveryPromise: Promise<RequiredDiscovery> | undefined

function trustedIssuerEndpoint(endpoint: string): string {
  const parsed = new URL(endpoint)
  if (parsed.origin !== new URL(issuer()).origin) throw new Error('Issuer discovery returned an untrusted endpoint.')
  return parsed.toString()
}

async function discovery(): Promise<RequiredDiscovery> {
  discoveryPromise ??= fetch(`${issuer()}/.well-known/openid-configuration`, { cache: 'no-store' })
    .then(async (response) => {
      if (!response.ok) throw new Error('Unable to retrieve issuer configuration.')
      const document = await response.json() as DiscoveryDocument
      if (document.issuer !== issuer() || !document.authorization_endpoint || !document.token_endpoint || !document.jwks_uri) {
        throw new Error('Issuer configuration is incomplete or does not match the configured issuer.')
      }
      return {
        ...document,
        authorization_endpoint: trustedIssuerEndpoint(document.authorization_endpoint),
        token_endpoint: trustedIssuerEndpoint(document.token_endpoint),
        jwks_uri: trustedIssuerEndpoint(document.jwks_uri),
        ...(document.end_session_endpoint
          ? { end_session_endpoint: trustedIssuerEndpoint(document.end_session_endpoint) }
          : {}),
      }
    })
  return discoveryPromise
}

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = Uint8Array.from(bytes)
  return copy.buffer as ArrayBuffer
}

export async function completeAuthorization(url: URL): Promise<CompletedAuthorization> {
  const error = url.searchParams.get('error')
  if (error) throw new Error(url.searchParams.get('error_description') || error)
  const code = url.searchParams.get('code')
  const state = url.searchParams.get('state')
  const serialized = sessionStorage.getItem(TRANSACTION_KEY)
  sessionStorage.removeItem(TRANSACTION_KEY)
  if (!code || !state || !serialized) throw new Error('Authorization response is incomplete or expired.')
  const transaction = JSON.parse(serialized) as Transaction
  if (state !== transaction.state || !transaction.verifier) throw new Error('Authorization state validation failed.')

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    redirect_uri: redirectUri(),
    code_verifier: transaction.verifier,
  })
  const metadata = await discovery()
  const response = await fetch(metadata.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })
  if (!response.ok) throw new Error('Authorization code exchange was rejected.')
  const payload = await response.json() as TokenResponse
  if (!payload.access_token || !payload.id_token) throw new Error('Authorization server did not return the required tokens.')
  await verifyIdToken(payload.id_token, transaction.nonce, metadata.jwks_uri)
  return { accessToken: payload.access_token, idToken: payload.id_token }
}

function decodePart(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(value.length + ((4 - value.length % 4) % 4), '=')
  const binary = atob(padded)
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

async function verifyIdToken(idToken: string, expectedNonce: string, jwksUri: string): Promise<void> {
  const [encodedHeader, encodedPayload, encodedSignature, ...extra] = idToken.split('.')
  if (!encodedHeader || !encodedPayload || !encodedSignature || extra.length) throw new Error('Malformed ID token.')
  const header = JSON.parse(new TextDecoder().decode(decodePart(encodedHeader))) as { alg?: string, kid?: string }
  const claims = JSON.parse(new TextDecoder().decode(decodePart(encodedPayload))) as {
    iss?: string, aud?: string | string[], exp?: number, nonce?: string
  }
  if (header.alg !== 'RS256' || !header.kid) throw new Error('Unsupported ID token signing algorithm.')
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (claims.iss !== issuer() || !audience.includes(CLIENT_ID) || claims.nonce !== expectedNonce
      || !claims.exp || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('ID token issuer, audience, nonce, or expiry validation failed.')
  }
  const jwksResponse = await fetch(jwksUri, { cache: 'no-store' })
  if (!jwksResponse.ok) throw new Error('Unable to retrieve issuer signing keys.')
  const jwks = await jwksResponse.json() as { keys?: SigningJwk[] }
  const key = jwks.keys?.find((candidate) => candidate.kid === header.kid && candidate.kty === 'RSA'
    && candidate.alg === 'RS256' && candidate.use === 'sig'
    && (!candidate.key_ops || candidate.key_ops.includes('verify')))
  if (!key) throw new Error('ID token signing key is not trusted.')
  const cryptoKey = await crypto.subtle.importKey('jwk', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey,
    asArrayBuffer(decodePart(encodedSignature)),
    asArrayBuffer(new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)))
  if (!valid) throw new Error('ID token signature validation failed.')
}

export async function endAuthorization(idTokenHint: string): Promise<void> {
  sessionStorage.removeItem(TRANSACTION_KEY)
  const params = new URLSearchParams({
    id_token_hint: idTokenHint,
    post_logout_redirect_uri: `${window.location.origin}/login`,
  })
  const metadata = await discovery()
  const endSessionEndpoint = metadata.end_session_endpoint || `${issuer()}/connect/logout`
  window.location.assign(`${endSessionEndpoint}?${params}`)
}
