{{/*
Determine if knative should be enabled based on runtimeEngineMode
*/}}
{{- define "core.knative.enabled" -}}
{{- if eq .Values.runtimeEngineMode "serverless" -}}
true
{{- else -}}
false
{{- end -}}
{{- end }}