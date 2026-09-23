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

{{- define "axiom.validateValues" -}}
{{- if ne (int .Values.server.replicaCount) 1 }}{{ fail "server.replicaCount must remain 1 until session, Policy Studio, tenant-cache, and scheduler state are externalized" }}{{ end }}
{{- if not .Values.runtimeSecret.existingSecret }}{{ fail "runtimeSecret.existingSecret is required" }}{{ end }}
{{- if not .Values.signingKey.existingSecret }}{{ fail "signingKey.existingSecret is required" }}{{ end }}
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

{{- define "axiom.serverVolumes" -}}
- name: signing-key
  secret:
    secretName: {{ .Values.signingKey.existingSecret | quote }}
    items:
      - key: {{ .Values.signingKey.privateJwkKey | quote }}
        path: signing-key.json
- name: runtime-secret
  secret:
    secretName: {{ .Values.runtimeSecret.existingSecret | quote }}
- name: tmp
  emptyDir:
    sizeLimit: 256Mi
{{- if eq .Values.policyRuntime.backend "pvc" }}
- name: runtime-policies
  persistentVolumeClaim:
    claimName: {{ .Values.policyRuntime.pvc.existingClaim | quote }}
{{- end }}
{{- end }}
