{{- /* Shared labels, names, and security contexts. */ -}}
{{- define "cipherpost.labels" -}}
app.kubernetes.io/name: cipherpost
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "cipherpost.selectorLabels" -}}
app.kubernetes.io/name: cipherpost
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "cipherpost.podSecurity" -}}
runAsUser: {{ .Values.podSecurity.runAsUser }}
runAsNonRoot: {{ .Values.podSecurity.runAsNonRoot }}
{{- end }}

{{- define "cipherpost.containerSecurity" -}}
allowPrivilegeEscalation: {{ .Values.podSecurity.allowPrivilegeEscalation }}
runAsUser: {{ .Values.podSecurity.runAsUser }}
{{- end }}

{{- define "cipherpost.env" -}}
- name: CIPHERPOST_ENV
  value: {{ .Values.config.env | quote }}
- name: CIPHERPOST_LOG_LEVEL
  value: {{ .Values.config.logLevel | quote }}
- name: CIPHERPOST_SINGLE_TENANT
  value: {{ .Values.config.singleTenant | quote }}
- name: CIPHERPOST_CORS_ORIGINS
  value: {{ .Values.config.corsOrigins | quote }}
- name: CIPHERPOST_DNS_RESOLVER
  value: {{ .Values.config.dnsResolver | quote }}
- name: CIPHERPOST_LIVE_IFACE
  value: {{ .Values.config.liveIface | quote }}
{{- end }}
