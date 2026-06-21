{{/* Common name helpers */}}
{{- define "aegisgraph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegisgraph.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "aegisgraph.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegisgraph.labels" -}}
app.kubernetes.io/name: {{ include "aegisgraph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Component service names */}}
{{- define "aegisgraph.postgresHost" -}}{{ include "aegisgraph.fullname" . }}-postgres{{- end -}}
{{- define "aegisgraph.natsHost" -}}{{ include "aegisgraph.fullname" . }}-nats{{- end -}}
{{- define "aegisgraph.backendHost" -}}{{ include "aegisgraph.fullname" . }}-backend{{- end -}}
