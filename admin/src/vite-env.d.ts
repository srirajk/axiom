/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AXIOM_ISSUER?: string
  readonly VITE_AXIOM_API_URL?: string
  readonly VITE_CIAM_TENANT_ID?: string
  readonly VITE_CIAM_CUSTOMER_CLIENT_ID?: string
  readonly VITE_CIAM_CUSTOMER_SCOPES?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
