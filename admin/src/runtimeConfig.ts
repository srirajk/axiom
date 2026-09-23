type AxiomRuntimeConfig = {
  apiUrl?: string
  issuer?: string
  ciamTenantId?: string
  ciamCustomerClientId?: string
  ciamCustomerScopes?: string
}

declare global {
  interface Window {
    __AXIOM_RUNTIME_CONFIG__?: AxiomRuntimeConfig
  }
}

const runtime = window.__AXIOM_RUNTIME_CONFIG__ ?? {}

export function runtimeValue(
  key: keyof AxiomRuntimeConfig,
  buildValue: string | undefined,
  fallback: string,
): string {
  const candidate = runtime[key] ?? buildValue
  return typeof candidate === 'string' && candidate.trim() ? candidate.trim() : fallback
}
