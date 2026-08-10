{{- define "shadowshield.name" -}}
shadowshield
{{- end -}}

{{- define "shadowshield.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "shadowshield.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "shadowshield.labels" -}}
app.kubernetes.io/name: {{ include "shadowshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "shadowshield.selectorLabels" -}}
app.kubernetes.io/name: {{ include "shadowshield.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "shadowshield.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "shadowshield.fullname" . -}}
{{- end -}}
{{- end -}}
