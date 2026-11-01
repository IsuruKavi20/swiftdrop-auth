{{- define "auth.name" -}}{{ .Release.Name }}{{- end -}}

{{- define "auth.labels" -}}
app.kubernetes.io/part-of: swiftdrop
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* selector labels for one component: include "auth.selector" (list . "app") */}}
{{- define "auth.selector" -}}
app.kubernetes.io/name: {{ index . 1 }}
app.kubernetes.io/instance: {{ (index . 0).Release.Name }}
{{- end -}}

{{/* in-cluster DNS name of a component's Service */}}
{{- define "auth.host" -}}
{{ (index . 0).Release.Name }}-{{ index . 1 }}.{{ (index . 0).Release.Namespace }}.svc.cluster.local
{{- end -}}

{{- define "auth.publicUrl" -}}
https://{{ required "publicHost is required" .Values.publicHost }}{{ if .Values.publicPort }}:{{ .Values.publicPort }}{{ end }}
{{- end -}}

{{/* DNS names for an internal TLS certificate */}}
{{- define "auth.dnsNames" -}}
- {{ (index . 0).Release.Name }}-{{ index . 1 }}
- {{ (index . 0).Release.Name }}-{{ index . 1 }}.{{ (index . 0).Release.Namespace }}
- {{ (index . 0).Release.Name }}-{{ index . 1 }}.{{ (index . 0).Release.Namespace }}.svc
- {{ include "auth.host" . }}
{{- end -}}
