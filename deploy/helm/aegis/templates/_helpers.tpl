{{- define "aegis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegis.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "aegis.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aegis.labels" -}}
app.kubernetes.io/name: {{ include "aegis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
