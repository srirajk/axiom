{{- define "axiomdeps.name" -}}
{{- .Values.namePrefix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "axiomdeps.image" -}}
{{- if .digest -}}{{ printf "%s@%s" .repository .digest }}{{- else -}}{{ printf "%s:%s" .repository .tag }}{{- end -}}
{{- end -}}
