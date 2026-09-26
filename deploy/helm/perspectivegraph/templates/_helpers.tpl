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

{{/* Whether this install carries a credential, for the guards that fire when it becomes
     reachable. Non-empty means "configured, or deliberately waived, or supplied through a
     Secret this chart cannot read". Kept in one place because it is asked from two
     surfaces - the ingress and the Service type - and two copies would drift. */}}
{{- define "perspectivegraph.credentialsConfigured" -}}
{{- if or .Values.secrets.existingSecret .Values.ingress.allowUnauthenticated -}}
yes
{{- else if and (or .Values.auth.apiTokens .Values.auth.oidc.jwksUrl) (or .Values.ingest.hmacSecret .Values.ingest.hmacSecrets) -}}
yes
{{- end -}}
{{- end -}}


{{/* Whether the backend authenticates to NATS. The bundled server always requires it
     unless nats.auth.enabled is false; an external NATS gets credentials only when some
     were given - it may well need none, and inventing a password would lock the backend
     out of it. */}}
{{- define "perspectivegraph.natsAuth" -}}
{{- if .Values.nats.enabled -}}
{{- if .Values.nats.auth.enabled -}}yes{{- end -}}
{{- else if and .Values.nats.auth.user (or .Values.nats.auth.password .Values.nats.auth.existingSecret) -}}
yes
{{- end -}}
{{- end -}}

{{/* The Secret holding NATS_PASSWORD: the operator's, or the one this chart creates. It is
     separate from the backend's credentials Secret on purpose, so an install that brings
     its own (secrets.existingSecret) gains NATS authentication without adding a key to it. */}}
{{- define "perspectivegraph.natsAuthSecret" -}}
{{- if .Values.nats.auth.existingSecret -}}
{{- .Values.nats.auth.existingSecret -}}
{{- else -}}
{{- include "perspectivegraph.fullname" . }}-nats-auth
{{- end -}}
{{- end -}}

{{/* A generated credential that survives upgrades: the value set in values.yaml if any,
     else the one already in the named Secret (read from the cluster), else a new random
     one. Rendering without a cluster - `helm template`, which is what Argo CD and Flux run
     - cannot read the Secret, so it draws a new one on every render: set the value (or an
     existing Secret) there. Arguments: (list $ secretName key explicitValue). */}}
{{- define "perspectivegraph.stableSecret" -}}
{{- $root := index . 0 -}}
{{- $name := index . 1 -}}
{{- $key := index . 2 -}}
{{- $explicit := index . 3 -}}
{{- if $explicit -}}
{{- $explicit -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" $root.Release.Namespace $name -}}
{{- if and $existing $existing.data (index $existing.data $key) -}}
{{- index $existing.data $key | b64dec -}}
{{- else -}}
{{- randAlphaNum 32 -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* The Postgres password written into the chart's Secret. The bundled Postgres gets a
     generated one when none is set - it used to default to "perspective", the same on
     every install. An existing install keeps the password it has: Postgres only reads
     POSTGRES_PASSWORD when it initialises its data directory, so changing it here would
     lock the backend out of its own database. An external Postgres gets nothing invented:
     it needs the password it actually has. */}}
{{- define "perspectivegraph.postgresPassword" -}}
{{- $name := printf "%s-secrets" (include "perspectivegraph.fullname" .) -}}
{{- if .Values.postgres.enabled -}}
{{- include "perspectivegraph.stableSecret" (list . $name "POSTGRES_PASSWORD" .Values.postgres.auth.password) -}}
{{- else if or .Values.postgres.auth.password .Values.postgres.dsn -}}
{{- .Values.postgres.auth.password -}}
{{- else -}}
{{- $existing := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- if and $existing $existing.data (index $existing.data "POSTGRES_PASSWORD") -}}
{{- index $existing.data "POSTGRES_PASSWORD" | b64dec -}}
{{- else -}}
{{- fail "postgres.auth.password is required for an external Postgres (postgres.enabled=false): set it, or postgres.dsn, or bring the credentials in secrets.existingSecret" -}}
{{- end -}}
{{- end -}}
{{- end -}}
