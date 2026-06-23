{{/* Common name helpers */}}
{{- define "perspectivegraph.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "perspectivegraph.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "perspectivegraph.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "perspectivegraph.labels" -}}
app.kubernetes.io/name: {{ include "perspectivegraph.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Component service names. postgresHost/postgresPort and natsUrl resolve to
     the bundled in-cluster service when enabled, or to the operator-supplied
     external endpoint when the bundled component is disabled. */}}
{{- define "perspectivegraph.postgresHost" -}}
{{- if .Values.postgres.enabled -}}
{{- include "perspectivegraph.fullname" . }}-postgres
{{- else -}}
{{- required "postgres.externalHost is required when postgres.enabled=false" .Values.postgres.externalHost -}}
{{- end -}}
{{- end -}}
{{- define "perspectivegraph.postgresPort" -}}
{{- if .Values.postgres.enabled -}}5432{{- else -}}{{ .Values.postgres.externalPort | default 5432 }}{{- end -}}
{{- end -}}
{{- define "perspectivegraph.natsHost" -}}{{ include "perspectivegraph.fullname" . }}-nats{{- end -}}
{{- define "perspectivegraph.natsUrl" -}}
{{- if .Values.nats.enabled -}}
nats://{{ include "perspectivegraph.natsHost" . }}:4222
{{- else -}}
{{- required "nats.externalUrl is required when nats.enabled=false" .Values.nats.externalUrl -}}
{{- end -}}
{{- end -}}
{{- define "perspectivegraph.backendHost" -}}{{ include "perspectivegraph.fullname" . }}-backend{{- end -}}

{{/* Name of the Secret the backend reads credentials from: an operator-supplied
     existing Secret (e.g. managed by External Secrets / Sealed Secrets / Vault)
     when secrets.existingSecret is set, otherwise the one this chart creates. */}}
{{- define "perspectivegraph.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "perspectivegraph.fullname" . }}-secrets
{{- end -}}
{{- end -}}
