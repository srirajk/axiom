{{- define "axiom.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "axiom.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := include "axiom.name" . -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{- define "axiom.labels" -}}
app.kubernetes.io/name: {{ include "axiom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end }}

{{- define "axiom.serverImage" -}}
{{- if .Values.server.image.digest -}}{{ printf "%s@%s" .Values.server.image.repository .Values.server.image.digest }}{{- else -}}{{ printf "%s:%s" .Values.server.image.repository (default .Chart.AppVersion .Values.server.image.tag) }}{{- end -}}
{{- end }}

{{- define "axiom.adminImage" -}}
{{- if .Values.admin.image.digest -}}{{ printf "%s@%s" .Values.admin.image.repository .Values.admin.image.digest }}{{- else -}}{{ printf "%s:%s" .Values.admin.image.repository (default .Chart.AppVersion .Values.admin.image.tag) }}{{- end -}}
{{- end }}

{{- define "axiom.selectorLabels" -}}
app.kubernetes.io/name: {{ include "axiom.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "axiom.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "axiom.fullname" .) .Values.serviceAccount.name }}{{ else }}{{ default "default" .Values.serviceAccount.name }}{{ end }}
{{- end }}

{{/*
Per-component ServiceAccount (admin, bootstrap, preflight, test). The server keeps axiom.serviceAccountName, so its
existing name and workload-identity annotations are unchanged; no other component shares it.
Usage: include "axiom.componentServiceAccountName" (dict "root" . "component" "admin")
*/}}
{{- define "axiom.componentServiceAccountName" -}}
{{- $sa := .root.Values.serviceAccount -}}
{{- $component := default (dict) (index $sa .component) -}}
{{- if $sa.create }}{{ default (printf "%s-%s" (include "axiom.fullname" .root) .component) $component.name }}{{ else }}{{ default "default" $component.name }}{{ end }}
{{- end }}

{{/*
Owner-only Secret files (0400). With the pod fsGroup the kubelet adds group read for that group only, so the
non-root process user can read them and no other user can.
*/}}
{{- define "axiom.secretFileMode" -}}
256
{{- end }}

{{/*
Runtime Secret keys a workload may read, as Secret volume items. Every component gets the database password and the
secrets master key; only the bootstrap path ("bootstrap" true: bootstrap job and preflight) gets the bootstrap
administrator password. Redis and S3 credentials are projected only when the chart is configured to use them.
Usage: include "axiom.runtimeSecretItems" (dict "root" . "bootstrap" false)
*/}}
{{- define "axiom.runtimeSecretItems" -}}
{{- $values := .root.Values -}}
{{- $keys := $values.runtimeSecret.keys -}}
{{- $selected := list $keys.databasePassword $keys.masterKey -}}
{{- if .bootstrap }}{{ $selected = append $selected $keys.adminPassword }}{{ end -}}
{{- if $values.redis.passwordEnabled }}{{ $selected = append $selected $keys.redisPassword }}{{ end -}}
{{- if and (eq $values.policyRuntime.backend "s3") $values.policyRuntime.s3.credentialsFromRuntimeSecret }}
{{- $selected = append $selected $keys.s3AccessKey }}{{ $selected = append $selected $keys.s3SecretKey }}
{{- end -}}
{{- range $selected }}
- key: {{ . | quote }}
  path: {{ . | quote }}
{{- end }}
{{- end }}

{{- define "axiom.validateValues" -}}
{{- if ne (int .Values.server.replicaCount) 1 }}{{ fail "server.replicaCount must remain 1 until session, Policy Studio, tenant-cache, and scheduler state are externalized" }}{{ end }}
{{- if not .Values.runtimeSecret.existingSecret }}{{ fail "runtimeSecret.existingSecret is required" }}{{ end }}
{{- if not .Values.signingKey.existingSecret }}{{ fail "signingKey.existingSecret is required" }}{{ end }}
{{- include "axiom.validateRuntimeSecretKeys" . }}
{{- if eq .Values.policyRuntime.backend "s3" }}
  {{- if not .Values.policyRuntime.s3.bucket }}{{ fail "policyRuntime.s3.bucket is required for the s3 backend" }}{{ end }}
{{- else if eq .Values.policyRuntime.backend "pvc" }}
  {{- if not .Values.policyRuntime.pvc.existingClaim }}{{ fail "policyRuntime.pvc.existingClaim is required for the pvc backend" }}{{ end }}
{{- else }}{{ fail "policyRuntime.backend must be s3 or pvc" }}{{ end }}
{{- end }}

{{- define "axiom.commonEnv" -}}
- name: SPRING_DATASOURCE_URL
  value: {{ printf "jdbc:postgresql://%s:%v/%s" .Values.postgresql.host .Values.postgresql.port .Values.postgresql.database | quote }}
- name: SPRING_DATASOURCE_USERNAME
  value: {{ .Values.postgresql.username | quote }}
- name: SPRING_CONFIG_IMPORT
  value: configtree:/var/run/secrets/axiom/
- name: SPRING_DATA_REDIS_HOST
  value: {{ .Values.redis.host | quote }}
- name: SPRING_DATA_REDIS_PORT
  value: {{ .Values.redis.port | quote }}
- name: SPRING_DATA_REDIS_DATABASE
  value: {{ .Values.redis.database | quote }}
- name: IAM_OAUTH2_AUTHORIZATION_STORE_REDIS_KEY_PREFIX
  value: {{ .Values.redis.authorizationKeyPrefix | quote }}
- name: AXIOM_REDIS_TENANT_NAMESPACE_PREFIX
  value: {{ .Values.redis.tenantNamespacePrefix | quote }}
- name: IAM_ISSUER_URL
  value: {{ .Values.config.issuerUrl | trimSuffix "/" | quote }}
- name: IAM_SIGNING_KEY_PATH
  value: /app/keys/signing-key.json
- name: IAM_SIGNING_KEY_ALLOW_GENERATION
  value: "false"
- name: IAM_AXIOM_ADMIN_REDIRECT_URI
  value: {{ printf "%s/callback" (.Values.config.adminPublicUrl | trimSuffix "/") | quote }}
- name: IAM_AXIOM_ADMIN_POST_LOGOUT_REDIRECT_URI
  value: {{ printf "%s/login" (.Values.config.adminPublicUrl | trimSuffix "/") | quote }}
- name: IAM_CORS_ALLOWED_ORIGINS
  value: {{ .Values.config.corsAllowedOrigins | quote }}
- name: IAM_FEDERATION_METADATA_ALLOWED_HOSTS
  value: {{ .Values.config.federationMetadataAllowedHosts | quote }}
- name: IAM_OAUTH2_APPROVED_BUSINESS_SCOPES
  value: {{ .Values.config.approvedBusinessScopes | quote }}
- name: IAM_CIAM_LOCAL_DEMO_CHALLENGE_DISCLOSURE
  value: {{ .Values.config.ciam.localDemoChallengeDisclosure | quote }}
- name: IAM_AUTH_LEGACY_PASSWORD_LOGIN_ENABLED
  value: {{ .Values.config.auth.legacyPasswordLogin | default false | quote }}
- name: IAM_AUTH_IMPERSONATION_ENABLED
  value: {{ .Values.config.auth.impersonation | default false | quote }}
- name: IAM_OAUTH2_INTERACTIVE_ACCESS_TOKEN_TTL
  value: {{ .Values.config.oauth2.interactiveAccessTokenTtl | default "PT1H" | quote }}
- name: IAM_OAUTH2_INTERACTIVE_ACCESS_TOKEN_MAX_TTL
  value: {{ .Values.config.oauth2.interactiveAccessTokenMaxTtl | default "PT1H" | quote }}
- name: IAM_OAUTH2_REFRESH_TOKEN_TTL
  value: {{ .Values.config.oauth2.refreshTokenTtl | default "PT8H" | quote }}
- name: IAM_OAUTH2_REFRESH_TOKEN_MAX_TTL
  value: {{ .Values.config.oauth2.refreshTokenMaxTtl | default "P30D" | quote }}
- name: CERBOS_HOST
  value: {{ .Values.cerbos.host | quote }}
- name: CERBOS_PORT
  value: {{ .Values.cerbos.grpcPort | quote }}
- name: CERBOS_IMAGE
  value: {{ .Values.cerbos.image | quote }}
- name: CERBOS_VERSION
  value: {{ .Values.cerbos.version | quote }}
- name: IAM_POLICY_STUDIO_BASE_BUNDLE_DIR
  value: /app/platform-policy/policies
- name: IAM_POLICY_STUDIO_PLATFORM_CONTRACT_PATH
  value: /app/platform-contract/axiom-platform-contract.json
- name: IAM_TENANCY_POLICY_STAGING_DIR
  value: {{ .Values.config.policyStagingDir | quote }}
{{- if eq .Values.policyRuntime.backend "s3" }}
- name: IAM_POLICY_STUDIO_RUNTIME_S3_BUCKET
  value: {{ .Values.policyRuntime.s3.bucket | quote }}
- name: IAM_POLICY_STUDIO_RUNTIME_S3_PREFIX
  value: {{ .Values.policyRuntime.s3.prefix | quote }}
- name: IAM_POLICY_STUDIO_RUNTIME_S3_ENDPOINT
  value: {{ .Values.policyRuntime.s3.endpoint | quote }}
- name: IAM_POLICY_STUDIO_RUNTIME_S3_REGION
  value: {{ .Values.policyRuntime.s3.region | quote }}
- name: IAM_POLICY_STUDIO_RUNTIME_S3_PATH_STYLE
  value: {{ .Values.policyRuntime.s3.pathStyle | quote }}
{{- else }}
- name: IAM_POLICY_STUDIO_RUNTIME_POLICIES_DIR
  value: /app/runtime-policies
{{- end }}
{{- end }}

{{/*
Each runtime-Secret role must name its own Secret key. Volumes project keys by name, so two roles sharing a key would
give a workload the other role's value: an adminPassword equal to any server-projected key (database, master, Redis
or S3) would mount the bootstrap administrator password into the long-running server. Checked for every role,
whether or not its feature is enabled, so enabling Redis or S3 later cannot create an alias. Names must also be
valid Secret keys and safe projected file names.
*/}}
{{- define "axiom.validateRuntimeSecretKeys" -}}
{{- $keys := .Values.runtimeSecret.keys -}}
{{- range $role := list "databasePassword" "masterKey" "adminPassword" "redisPassword" "s3AccessKey" "s3SecretKey" }}
{{- if not (index $keys $role) }}{{ fail (printf "runtimeSecret.keys.%s is required" $role) }}{{ end }}
{{- end }}
{{- $seen := dict -}}
{{- range $role, $raw := $keys }}
{{- $name := toString $raw -}}
{{- if or (not (regexMatch "^[-._a-zA-Z0-9]{1,253}$" $name)) (eq $name ".") (eq $name "..") }}
{{- fail (printf "runtimeSecret.keys.%s %q is not a valid Secret key name" $role $name) }}
{{- end }}
{{- if hasKey $seen $name }}
{{- fail (printf "runtimeSecret.keys.%s and runtimeSecret.keys.%s both name Secret key %q; each role needs its own key" (get $seen $name) $role $name) }}
{{- end }}
{{- $_ := set $seen $name $role }}
{{- end }}
{{- end }}

{{- define "axiom.serverVolumeMounts" -}}
- name: signing-key
  mountPath: /app/keys/signing-key.json
  subPath: {{ .Values.signingKey.privateJwkKey }}
  readOnly: true
- name: runtime-secret
  mountPath: /var/run/secrets/axiom
  readOnly: true
- name: tmp
  mountPath: /tmp
{{- if eq .Values.policyRuntime.backend "pvc" }}
- name: runtime-policies
  mountPath: /app/runtime-policies
{{- end }}
{{- end }}

{{/*
Usage: include "axiom.serverVolumes" (dict "root" . "bootstrap" false)
*/}}
{{- define "axiom.serverVolumes" -}}
{{- $root := .root -}}
- name: signing-key
  secret:
    secretName: {{ $root.Values.signingKey.existingSecret | quote }}
    defaultMode: {{ include "axiom.secretFileMode" . }}
    items:
      - key: {{ $root.Values.signingKey.privateJwkKey | quote }}
        path: signing-key.json
- name: runtime-secret
  secret:
    secretName: {{ $root.Values.runtimeSecret.existingSecret | quote }}
    defaultMode: {{ include "axiom.secretFileMode" . }}
    items:
      {{- include "axiom.runtimeSecretItems" (dict "root" $root "bootstrap" .bootstrap) | nindent 6 }}
- name: tmp
  emptyDir:
    sizeLimit: 256Mi
{{- if eq $root.Values.policyRuntime.backend "pvc" }}
- name: runtime-policies
  persistentVolumeClaim:
    claimName: {{ $root.Values.policyRuntime.pvc.existingClaim | quote }}
{{- end }}
{{- end }}
