import { clearAdminToken, notifyAuthLogout, readAdminToken } from '../auth/tokenStorage'

const BASE = import.meta.env.VITE_AXIOM_API_URL || '/api'

/**
 * ABAC segments arrive from the backend as a {segment: data_classification} MAP
 * (e.g. {"platform":"internal"}), not an array — the UI models them as string[]. Coerce to the
 * list of segment names so `.map`/`.length` never blow up on an object. The per-segment
 * classification is carried separately on `classification`.
 */
export function normalizeSegments(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw as string[]
  if (raw && typeof raw === 'object') return Object.keys(raw as Record<string, unknown>)
  return []
}

function withNormalizedSegments<T extends { segments?: unknown }>(entity: T): T {
  return { ...entity, segments: normalizeSegments(entity.segments) }
}

function token(): string {
  return readAdminToken()
}

function broadcastLogout(): void {
  clearAdminToken()
  notifyAuthLogout()
}

function errorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== 'object') return fallback
  const err = payload as Record<string, unknown>
  const detail = err.detail
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object') {
    const message = (detail as Record<string, unknown>).message
    if (typeof message === 'string') return message
  }
  if (typeof err.message === 'string') return err.message
  if (typeof err.error === 'string') return err.error
  return fallback
}

async function req<T>(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
  const authToken = token()
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...headers,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })
  if (!res.ok) {
    if (res.status === 401) broadcastLogout()
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(errorMessage(err, res.statusText || `Request failed (${res.status})`))
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

// ── Types ─────────────────────────────────────────────────────────────────────
export interface User {
  id: string
  username: string
  email: string
  roles: string[]
  segments: string[]
  clearance?: number
  classification: string
  team?: string
  adminDomains: string[]
  isActive?: boolean
  createdAt?: string
  tenantId?: string
}

export interface CreateUserInput {
  id: string
  username: string
  email: string
  password: string
  attributes: Record<string, unknown>
}

export interface UpdateUserInput {
  email?: string
  isActive?: boolean
  attributes?: Record<string, unknown>
}

export interface AuditEntry {
  id: string
  tenantId: string
  actorId: string
  action: string
  resourceType: string
  resourceId: string
  beforeState?: Record<string, unknown>
  afterState?: Record<string, unknown>
  sourceIp: string
  occurredAt: string
}

export interface PageResponse<T> {
  content: T[]
  page: number
  size: number
  totalElements: number
  totalPages: number
}

export type IdentityControlAction =
  | 'EMERGENCY_RETIRE_SIGNING_KEY'
  | 'DISABLE_IDENTITY_SOURCE'
  | 'ROTATE_IDENTITY_SOURCE_SECRET'
  | 'REVOKE_APPLICATION_CLIENT_SECRET'
  | 'ROTATE_APPLICATION_CLIENT_SECRET'
  | 'REVOKE_SCIM_SOURCE'
  | 'ROTATE_SCIM_SOURCE_CREDENTIAL'

export type IdentityControlTargetType = 'SIGNING_KEY' | 'IDENTITY_SOURCE' | 'APPLICATION_CLIENT' | 'SCIM_SOURCE'
export type IdentityControlStatus = 'PENDING' | 'APPROVED' | 'APPLIED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED'

export interface IdentityControlRequest {
  id: string
  tenantId: string
  action: IdentityControlAction
  targetType: IdentityControlTargetType
  targetId: string
  payloadHash: string
  initiatorPrincipalId: string
  createdAt: string
  expiresAt: string
  expectedTargetRevision?: number | null
  status: IdentityControlStatus
  approverPrincipalId?: string | null
  approvedAt?: string | null
  applicationResultReference?: string | null
  revision: number
}

export interface IdentityControlApplyResponse {
  request: IdentityControlRequest
  resultReference: string
  oneTimeSecret?: string | null
}

export type RecoveryOperatorStatus = 'PENDING_ACTIVATION' | 'ACTIVE' | 'PENDING_ROTATION' | 'DISABLED'
export interface RecoveryOperator {
  id: string
  tenantId: string
  principalId: string
  status: RecoveryOperatorStatus
  revision: number
  createdAt: string
  updatedAt: string
  initiatorPrincipalId?: string | null
  activationActorId?: string | null
  activationAt?: string | null
  oneTimeCredential?: string | null
}

export type IamSessionStatus = 'ACTIVE' | 'REVOKED'

export interface IamSession {
  id: string
  tenantId: string
  principalId: string
  applicationId?: string | null
  clientId?: string | null
  issuedAt: string
  lastSeenAt?: string | null
  expiresAt: string
  status: IamSessionStatus
  revision: number
}

export interface Stats {
  totalUsers: number
  totalRoles: number
  totalTeams: number
}

export interface ClassificationTier {
  name: string
  rank: number
}

export interface Team {
  id: string
  name: string
  domainId?: string
  description: string
  defaultRoles: string[]
  segments: string[]
  allowedDomains: string[]
  memberCount: number
  members?: TeamMember[]
}

export interface TeamMember {
  id: string
  name: string
  email: string
  roles?: string[]
}

export interface Role {
  id: string
  name: string
  description: string
  permissions: string[]
}

export type ApplicationStatus = 'ACTIVE' | 'DISABLED'
export type ApplicationClientType = 'PUBLIC_BROWSER' | 'CONFIDENTIAL_SERVICE'
export type ApplicationClientStatus = 'ACTIVE' | 'DISABLED'

export interface Application {
  id: string
  tenantId: string
  applicationKey: string
  displayName: string
  description?: string
  audience: string
  status: ApplicationStatus
  revision: number
  createdAt: string
  updatedAt: string
}

export interface ApplicationClient {
  id: string
  clientId: string
  clientType: ApplicationClientType
  status: ApplicationClientStatus
  scopes: string[]
  redirectUris: string[]
  postLogoutRedirectUris: string[]
  grantTypes: string[]
  pkceRequired: boolean
  revision: number
  createdAt: string
  updatedAt: string
}

export type ApplicationMembershipStatus = 'ACTIVE' | 'DISABLED'

export interface ApplicationRole {
  id: string
  roleKey: string
  displayName: string
  description?: string
  permissions: string[]
  createdAt: string
  updatedAt: string
}

export interface ApplicationMembership {
  id: string
  principalId: string
  status: ApplicationMembershipStatus
  attributes: Record<string, unknown>
  roles: string[]
  assignmentSource: string
  assignedBy: string
  entitlementRevision: number
  createdAt: string
  updatedAt: string
}

export type IdentitySourceStatus = 'DRAFT' | 'ACTIVE' | 'DISABLED'

export interface IdentitySource {
  id: string
  tenantId: string
  displayName: string
  issuer: string
  discoveryUri: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  jwksUri: string
  clientId: string
  requestedScopes: string[]
  allowedSigningAlgorithms: string[]
  requiredClaims: string[]
  requiredAcrValues: string[]
  status: IdentitySourceStatus
  revision: number
  lastValidatedAt?: string
  createdAt: string
  updatedAt: string
}

export interface IdentitySourceValidation {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  jwksUri: string
  supportedSigningAlgorithms: string[]
  supportedClaims: string[]
  supportedAcrValues: string[]
}

export interface ExternalIdentityLink {
  id: string
  sourceId: string
  issuer: string
  subject: string
  principalId: string
  status: 'ACTIVE' | 'DISABLED'
  createdAt: string
  updatedAt: string
}

export interface ScimSource {
  id: string
  tenantId: string
  displayName: string
  identitySourceId?: string
  selector: string
  status: 'ACTIVE' | 'REVOKED'
  revision: number
  createdAt: string
  updatedAt: string
  bearerCredential?: string | null
}

export interface ScimReconciliation {
  sourceId: string
  tenantId: string
  sourceLinkedUsers: number
  sourceLinkedGroups: number
  missingBackingResources: string[]
  ownershipMismatches: string[]
  duplicateExternalIds: string[]
  checkedAt: string
}

export type SigningKeyState = 'STAGED' | 'ACTIVE' | 'VERIFICATION_ONLY' | 'RETIRED'

export interface SigningKey {
  id: string
  kid: string
  algorithm: string
  state: SigningKeyState
  createdAt: string
  activatedAt?: string
  verificationExpiresAt?: string
  retiredAt?: string
  revision: number
}

export interface CreateApplicationInput {
  applicationKey: string
  displayName: string
  description?: string
  audience: string
}

export interface CreateApplicationClientInput {
  clientId: string
  clientType: ApplicationClientType
  redirectUris?: string[]
  postLogoutRedirectUris?: string[]
  scopes: string[]
}

// ── Users ─────────────────────────────────────────────────────────────────────
export const usersApi = {
  listPage: (page = 0, size = 100) => req<PageResponse<User>>('GET', `/users?page=${page}&size=${size}`),
  list: async () => {
    const page = await usersApi.listPage(0, 100)
    return page.content.map(withNormalizedSegments)
  },
  get: async (id: string) => withNormalizedSegments(await req<User>('GET', `/users/${id}`)),
  create: (data: CreateUserInput) =>
    req<User>('POST', '/users', data),
  update: (id: string, data: UpdateUserInput) =>
    req<User>('PUT', `/users/${id}`, data),
  delete: (id: string) => req<void>('DELETE', `/users/${id}`),
  assignRole: (userId: string, roleId: string) =>
    req<{ roles: string[] }>('POST', `/users/${userId}/roles`, { role_id: roleId }),
  removeRole: (userId: string, roleId: string) =>
    req<void>('DELETE', `/users/${userId}/roles/${roleId}`),
  getTeams: (userId: string) =>
    req<{ teams: Team[] }>('GET', `/users/${userId}/teams`),
}

// ── Teams ─────────────────────────────────────────────────────────────────────
export const teamsApi = {
  list: async () => (await req<Team[]>('GET', '/teams')).map(withNormalizedSegments),
  get: async (id: string) => {
    const [team, members] = await Promise.all([
      req<Team>('GET', `/teams/${id}`),
      req<User[]>('GET', `/teams/${id}/members`),
    ])
    return withNormalizedSegments({
      ...team,
      members: members.map(member => ({
        id: member.id,
        name: member.username,
        email: member.email,
        roles: member.roles,
      })),
    })
  },
  create: (data: Omit<Team, 'memberCount'>) =>
    req<Team>('POST', '/teams', {
      name: data.name,
      domainId: data.domainId || data.id || undefined,
      description: data.description,
      defaultRoles: data.defaultRoles,
      segments: data.segments,
      allowedDomains: data.allowedDomains,
    }),
  update: (id: string, data: Omit<Team, 'id' | 'memberCount'>) =>
    req<Team>('PUT', `/teams/${id}`, {
      name: data.name,
      domainId: data.domainId || undefined,
      description: data.description,
      defaultRoles: data.defaultRoles,
      segments: data.segments,
      allowedDomains: data.allowedDomains,
    }),
  delete: (id: string) => req<void>('DELETE', `/teams/${id}`),
  addMember: (teamId: string, userId: string) =>
    req<{ added: boolean }>('POST', `/teams/${teamId}/members`, { user_id: userId }),
  removeMember: (teamId: string, userId: string) =>
    req<void>('DELETE', `/teams/${teamId}/members/${userId}`),
  listMembers: async (teamId: string) => {
    const members = await req<User[]>('GET', `/teams/${teamId}/members`)
    return members.map(member => ({
      id: member.id,
      name: member.username,
      email: member.email,
      roles: member.roles,
    }))
  },
}

// ── Roles ─────────────────────────────────────────────────────────────────────
export const rolesApi = {
  list: () => req<Role[]>('GET', '/roles'),
  get: (id: string) => req<Role>('GET', `/roles/${id}`),
  create: (data: Role) => req<Role>('POST', '/roles', {
    name: data.name,
    description: data.description,
    permissions: data.permissions,
  }),
  update: (id: string, data: Omit<Role, 'id'>) =>
    req<Role>('PUT', `/roles/${id}`, {
      name: data.name,
      description: data.description,
      permissions: data.permissions,
    }),
  delete: (id: string) => req<void>('DELETE', `/roles/${id}`),
}

// ── Admin ─────────────────────────────────────────────────────────────────────
export const adminApi = {
  policyResources: () => req<{ resources: string[] }>('GET', '/admin/policy-resources'),
  segments: () => req<{ segments: string[] }>('GET', '/admin/segments'),
}

// ── Audit ─────────────────────────────────────────────────────────────────────
export const auditApi = {
  list: (page: number, size: number) =>
    req<PageResponse<AuditEntry>>('GET', `/admin/audit?page=${page}&size=${size}`),
  export: () =>
    req<AuditEntry[]>('GET', '/admin/audit/export'),
}

// ── Stats ─────────────────────────────────────────────────────────────────────
export const statsApi = {
  get: () => req<Stats>('GET', '/stats'),
}

// ── Tenant ─────────────────────────────────────────────────────────────────────
export const tenantApi = {
  getClassificationSchema: () =>
    req<ClassificationTier[]>('GET', '/tenants/current/classification-schema'),
}

// ── Applications ─────────────────────────────────────────────────────────────
export const applicationsApi = {
  list: (tenantId: string) =>
    req<Application[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/applications`),
  create: (tenantId: string, data: CreateApplicationInput) =>
    req<Application>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications`, data),
  clients: (tenantId: string, applicationId: string) =>
    req<ApplicationClient[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/clients`),
  createClient: (tenantId: string, applicationId: string, data: CreateApplicationClientInput) =>
    req<{ client: ApplicationClient; serviceSecret?: string }>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/clients`, data),
  disable: (tenantId: string, applicationId: string) =>
    req<void>('DELETE', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}`),
  disableClient: (tenantId: string, applicationId: string, clientId: string) =>
    req<void>('DELETE', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/clients/${clientId}`),
  rotateClientSecret: (tenantId: string, applicationId: string, clientId: string, expectedRevision: number) =>
    req<{ client: ApplicationClient; serviceSecret?: string }>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/clients/${clientId}/rotate-secret`, { expectedRevision }),
  revokeClientSecret: (tenantId: string, applicationId: string, clientId: string, expectedRevision: number) =>
    req<ApplicationClient>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/clients/${clientId}/revoke`, { expectedRevision }),
  accessRoles: (tenantId: string, applicationId: string) =>
    req<ApplicationRole[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/roles`),
  memberships: (tenantId: string, applicationId: string) =>
    req<ApplicationMembership[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships`),
  createRole: (tenantId: string, applicationId: string, data: { roleKey: string; displayName: string; description?: string; permissions: string[] }) =>
    req<ApplicationRole>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/roles`, data),
  createMembership: (tenantId: string, applicationId: string, data: { principalId: string; assignmentSource: string }) =>
    req<ApplicationMembership>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships`, data),
  assignRole: (tenantId: string, applicationId: string, membershipId: string, data: { roleId: string; assignmentSource: string }) =>
    req<ApplicationMembership>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships/${membershipId}/roles`, data),
  revokeRole: (tenantId: string, applicationId: string, membershipId: string, roleId: string) =>
    req<ApplicationMembership>('DELETE', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships/${membershipId}/roles/${roleId}`),
  updateAttributes: (tenantId: string, applicationId: string, membershipId: string, attributes: Record<string, unknown>) =>
    req<ApplicationMembership>('PATCH', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships/${membershipId}/attributes`, { attributes }),
  disableMembership: (tenantId: string, applicationId: string, membershipId: string) =>
    req<void>('DELETE', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships/${membershipId}`),
  enableMembership: (tenantId: string, applicationId: string, membershipId: string) =>
    req<ApplicationMembership>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/applications/${applicationId}/access/memberships/${membershipId}/enable`),
}

// ── Customer OIDC identity sources ───────────────────────────────────────────
export const identitySourcesApi = {
  list: (tenantId: string) =>
    req<IdentitySource[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources`),
  get: (tenantId: string, sourceId: string) =>
    req<IdentitySource>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}`),
  create: (tenantId: string, data: {
    displayName: string
    issuer: string
    discoveryUri: string
    clientId: string
    clientSecret: string
    requestedScopes: string[]
    allowedSigningAlgorithms: string[]
    requiredClaims: string[]
    requiredAcrValues: string[]
  }) => req<IdentitySource>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources`, data),
  validate: (tenantId: string, sourceId: string) =>
    req<IdentitySourceValidation>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/validate`),
  activate: (tenantId: string, sourceId: string) =>
    req<IdentitySource>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/activate`),
  disable: (tenantId: string, sourceId: string) =>
    req<void>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/disable`),
  rotateSecret: (tenantId: string, sourceId: string, clientSecret: string) =>
    req<void>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/rotate-secret`, { clientSecret }),
  links: (tenantId: string, sourceId: string) =>
    req<ExternalIdentityLink[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/links`),
  createLink: (tenantId: string, sourceId: string, data: { issuer: string; subject: string; principalId: string }) =>
    req<ExternalIdentityLink>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/links`, { sourceId, ...data }),
  disableLink: (tenantId: string, sourceId: string, linkId: string) =>
    req<void>('DELETE', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-sources/${sourceId}/links/${linkId}`),
}

// ── SCIM identity provisioning sources ───────────────────────────────────────
export const scimSourcesApi = {
  list: (tenantId: string) =>
    req<ScimSource[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/scim-sources`),
  create: (tenantId: string, data: { displayName: string; identitySourceId?: string }) =>
    req<ScimSource>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/scim-sources`, data),
  rotate: (tenantId: string, sourceId: string) =>
    req<ScimSource>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/scim-sources/${sourceId}/rotate`),
  revoke: (tenantId: string, sourceId: string) =>
    req<void>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/scim-sources/${sourceId}/revoke`),
  reconciliation: (tenantId: string, sourceId: string) =>
    req<ScimReconciliation>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/scim-sources/${sourceId}/reconciliation`),
}

// ── Signing-key lifecycle ────────────────────────────────────────────────────
export const signingKeysApi = {
  list: (tenantId: string) =>
    req<SigningKey[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/signing-keys`),
  createStaged: (tenantId: string) =>
    req<SigningKey>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/signing-keys`),
  activate: (tenantId: string, keyId: string) =>
    req<SigningKey>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/signing-keys/${keyId}/activate`),
  retire: (tenantId: string, keyId: string) =>
    req<void>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/signing-keys/${keyId}/retire`),
  emergencyRetire: (tenantId: string, keyId: string) =>
    req<void>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/signing-keys/${keyId}/emergency-retire`),
}

// ── Identity control requests ───────────────────────────────────────────────
export const identityControlsApi = {
  list: (tenantId: string, page: number, size: number, status?: IdentityControlStatus) => {
    const params = new URLSearchParams({ page: String(page), size: String(size) })
    if (status) params.set('status', status)
    return req<PageResponse<IdentityControlRequest>>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests?${params.toString()}`)
  },
  propose: (tenantId: string, data: {
    action: IdentityControlAction
    targetType: IdentityControlTargetType
    targetId: string
    payload?: Record<string, string>
    expectedTargetRevision?: number
  }) => req<IdentityControlRequest>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests`, data),
  apply: (tenantId: string, requestId: string, expectedRevision: number) =>
    req<IdentityControlApplyResponse>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests/${encodeURIComponent(requestId)}/apply`, { expectedRevision }),
  approve: (tenantId: string, requestId: string, expectedRevision: number) =>
    req<IdentityControlRequest>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests/${encodeURIComponent(requestId)}/approve`, { expectedRevision }),
  reject: (tenantId: string, requestId: string, expectedRevision: number) =>
    req<IdentityControlRequest>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests/${encodeURIComponent(requestId)}/reject`, { expectedRevision }),
  cancel: (tenantId: string, requestId: string, expectedRevision: number) =>
    req<IdentityControlRequest>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/identity-control-requests/${encodeURIComponent(requestId)}/cancel`, { expectedRevision }),
}

// ── Recovery operators ──────────────────────────────────────────────────────
export const recoveryOperatorsApi = {
  list: (tenantId: string) => req<RecoveryOperator[]>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/recovery-operators`),
  enroll: (tenantId: string, principalId: string) => req<RecoveryOperator>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/recovery-operators`, { principalId }),
  rotate: (tenantId: string, operatorId: string, expectedRevision: number) => req<RecoveryOperator>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/recovery-operators/${encodeURIComponent(operatorId)}/rotate`, { expectedRevision }),
  disable: (tenantId: string, operatorId: string, expectedRevision: number) => req<RecoveryOperator>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/recovery-operators/${encodeURIComponent(operatorId)}/disable`, { expectedRevision }),
}

export const myRecoveryOperatorsApi = {
  list: () => req<RecoveryOperator[]>('GET', '/api/me/recovery-operators'),
  activate: (operatorId: string, expectedRevision: number) => req<RecoveryOperator>('POST', `/api/me/recovery-operators/${encodeURIComponent(operatorId)}/activate`, { expectedRevision }),
  rotate: (operatorId: string, expectedRevision: number) => req<RecoveryOperator>('POST', `/api/me/recovery-operators/${encodeURIComponent(operatorId)}/rotate`, { expectedRevision }),
}

// ── Session inventory ────────────────────────────────────────────────────────
export const sessionsApi = {
  list: (tenantId: string, options: {
    page: number
    size: number
    principalId?: string
    clientId?: string
    status?: IamSessionStatus
  }) => {
    const params = new URLSearchParams({ page: String(options.page), size: String(options.size) })
    if (options.principalId) params.set('principalId', options.principalId)
    if (options.clientId) params.set('clientId', options.clientId)
    if (options.status) params.set('status', options.status)
    return req<PageResponse<IamSession>>('GET', `/admin/tenants/${encodeURIComponent(tenantId)}/sessions?${params.toString()}`)
  },
  revoke: (tenantId: string, sessionId: string, expectedRevision: number) =>
    req<IamSession>('POST', `/admin/tenants/${encodeURIComponent(tenantId)}/sessions/${encodeURIComponent(sessionId)}/revoke`, { expectedRevision }),
}

// ── Axiom Policy Studio ──────────────────────────────────────────────────────
export type JsonRecord = Record<string, unknown>

export interface ManifestVocabulary {
  resourceKind: string
  actions: string[]
  classifications: string[]
  attributes: string[]
  roles: string[]
  approvedImports: string[]
}

export interface BaseCeiling {
  resourceKind: string
  tuples: Array<{ action: string; role: string }>
  carriesTenantEqualityBackstop: boolean
  reservedIdentities: string[]
}

export interface StudioGroundingSnapshot {
  tenantId: string
  vocabulary: ManifestVocabulary
  baseCeiling: BaseCeiling
  matrix: { cells: FixtureCell[]; fixtureSetHash: string }
  current: BundleSnapshot
  manifestRefs: string[]
}

export interface DraftRequest {
  intent: string
  resourceKind?: string
  subscopesEnabled: boolean
  vocabulary?: ManifestVocabulary
  baseCeiling?: BaseCeiling
}

export interface ValidationResult {
  ok: boolean
  violations: string[]
  stage: string
}

export interface DraftResponse {
  draftId: string
  tenantId: string
  authorId: string
  accepted: boolean
  canonicalYaml: string | null
  validation: ValidationResult
}

export interface FixtureCell {
  principalRoles: string[]
  principalTenant: string
  principalAttrs: JsonRecord
  resourceTenant: string
  resourceAttrs: JsonRecord
  action: string
  label: string
}

export interface BundleSnapshot {
  bundleId: string
  policy: JsonRecord | null
  ceiling: BaseCeiling | null
  canonicalContent: string
}

export interface ReviewRequest {
  current: BundleSnapshot
  candidate: BundleSnapshot
  matrix: { cells: FixtureCell[]; fixtureSetHash: string }
  vocabulary: ManifestVocabulary
}

export interface ConsequenceDelta {
  cell: FixtureCell
  from: 'ALLOW' | 'DENY'
  to: 'ALLOW' | 'DENY'
  direction: 'WIDENED' | 'NARROWED'
  overPermission: boolean
  businessConsequence: string
}

export interface ConsequenceReview {
  tenantId: string
  resourceKind: string
  currentBundleId: string
  candidateBundleId: string
  fixtureSetHash: string
  deltas: ConsequenceDelta[]
  overPermissionAlarm: boolean
  principalsGainingAccess: number
  canonicalDelta: string
  consequenceReviewHash: string
  disclosure: { sampledNotFormal: boolean; sampledCellCount: number; statement: string }
  provenance: { sourceId: string; currentBatch: JsonRecord; candidateBatch: JsonRecord }
  generatedAt: string
  displayProse: string | null
}

export interface BundleFile { path: string; yaml: string }
export interface BundleTestMetadata {
  fixtureSetHash: string
  testCount: number
  oracle: string
  pdpSourceId: string
}
export interface PolicyBundle {
  bundleId: string
  tenantId: string
  files: BundleFile[]
  manifestRefs: string[]
  testMetadata: BundleTestMetadata
  canonicalContent: string
}

export interface BundleView {
  bundleId: string
  tenantId: string
  gitCommit: string
  fixtureSetHash: string
  testCount: number
  testOracle: string
  pdpSourceId: string
  createdAt: string
}

export interface PromotionReceipt {
  promotionId: string
  tenantId: string
  fromBundleId: string
  toBundleId: string
  directoryVersion: number
  kind: 'PROMOTION' | 'ROLLBACK'
  idempotentReplay: boolean
}

export interface ReviewHandoff {
  reviewId: string
  authorId: string
  review: ConsequenceReview
  candidate: PolicyBundle
  storedAt: string
}

export interface ExaminerChain {
  transactionId: string
  tenantId: string
  cerbosCallId: string
  activePolicyVersion: string
  decision: string
  resourceKind: string
  action: string
  bundleId: string
  gitCommit: string
  testMetadata: BundleTestMetadata
  approverId: string
  consequenceReviewHash: string
  approvalSignatureValid: boolean
  complete: boolean
}

export interface BreakGlassRequest {
  scope: string
  resourceKind: string
  action: string
  role: string
  ttlMinutes: number
  justification: string
}

export interface BreakGlassGrant {
  grantId: string
  tenantId: string
  requestedBy: string
  admissible: boolean
  issued: boolean
  expiresAt: string
  boundsViolations: string[]
  c2Violations: string[]
}

export const studioApi = {
  createDraft: (payload: DraftRequest) =>
    req<DraftResponse>('POST', '/admin/studio/drafts', payload),
  getVocabulary: (resourceKind: string) =>
    req<StudioGroundingSnapshot>('GET', `/admin/studio/vocabulary/${encodeURIComponent(resourceKind)}`),
  createReview: (payload: ReviewRequest) =>
    req<ConsequenceReview>('POST', '/admin/studio/reviews', payload),
  createAssembledReview: (resourceKind: string, canonicalYaml: string) =>
    req<ConsequenceReview>('POST', '/admin/studio/reviews/assembled', { resourceKind, canonicalYaml }),
  assembleCandidateBundle: (resourceKind: string, canonicalYaml: string, fixtureSetHash: string) =>
    req<PolicyBundle>('POST', '/admin/studio/bundles/candidates', { resourceKind, canonicalYaml, fixtureSetHash }),
  getReview: (reviewId: string) =>
    req<ConsequenceReview>('GET', `/admin/studio/reviews/${encodeURIComponent(reviewId)}`),
  listPendingReviews: () => req<ReviewHandoff[]>('GET', '/admin/studio/reviews/pending'),
  listBundles: () => req<BundleView[]>('GET', '/admin/studio/bundles'),
  getBundle: (bundleId: string) =>
    req<BundleView>('GET', `/admin/studio/bundles/${encodeURIComponent(bundleId)}`),
  getExaminerChain: (cerbosCallId: string) =>
    req<ExaminerChain>('GET', `/admin/studio/examiner/${encodeURIComponent(cerbosCallId)}`),
  promote: (reviewId: string, idempotencyKey: string) =>
    req<PromotionReceipt>('POST', '/admin/studio/promotions', { reviewId, idempotencyKey }),
  rollback: (reviewId: string, idempotencyKey: string) =>
    req<PromotionReceipt>('POST', '/admin/studio/rollbacks', { reviewId, idempotencyKey }),
  requestBreakGlass: (payload: BreakGlassRequest) =>
    req<BreakGlassGrant>('POST', '/admin/studio/break-glass', payload),
  approveBreakGlass: (grantId: string, correlationId?: string) =>
    req<BreakGlassGrant>('POST', `/admin/studio/break-glass/${encodeURIComponent(grantId)}/approve`, undefined,
      correlationId ? { 'X-Correlation-Id': correlationId } : undefined),
  listBreakGlass: () => req<BreakGlassGrant[]>('GET', '/admin/studio/break-glass'),
}
