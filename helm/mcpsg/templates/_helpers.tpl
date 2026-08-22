{{/* helpers.tpl */}}
{{- define "mcpsg.fullname" -}}
{{- printf "mcpsg-%s" .Release.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "mcpsg.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "mcpsg.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "mcpsg.selectorLabels" -}}
app.kubernetes.io/name: mcp-security-gateway
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "mcpsg.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mcpsg.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
