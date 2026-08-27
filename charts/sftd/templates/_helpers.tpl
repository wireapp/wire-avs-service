{{/*
Expand the name of the chart.
*/}}
{{- define "sftd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "sftd.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "sftd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "sftd.labels" -}}
helm.sh/chart: {{ include "sftd.chart" . }}
{{ include "sftd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
{{- define "sftd.join-call.labels" -}}
helm.sh/chart: {{ include "sftd.chart" . }}
{{ include "sftd.join-call.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "sftd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sftd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "sftd.join-call.selectorLabels" -}}
app.kubernetes.io/name: join-call
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Allow KubeVersion to be overridden. */}}
{{- define "kubeVersion" -}}
  {{- default .Capabilities.KubeVersion.Version .Values.kubeVersionOverride -}}
{{- end -}}

{{/* Get Ingress API Version */}}
{{- define "ingress.apiVersion" -}}
  {{- if and (.Capabilities.APIVersions.Has "networking.k8s.io/v1") (semverCompare ">= 1.19-0" (include "kubeVersion" .)) -}}
      {{- print "networking.k8s.io/v1" -}}
  {{- else if .Capabilities.APIVersions.Has "networking.k8s.io/v1beta1" -}}
    {{- print "networking.k8s.io/v1beta1" -}}
  {{- else -}}
    {{- print "extensions/v1beta1" -}}
  {{- end -}}
{{- end -}}

{{/* Check Ingress stability */}}
{{- define "ingress.isStable" -}}
  {{- eq (include "ingress.apiVersion" .) "networking.k8s.io/v1" -}}
{{- end -}}

{{/* Check Ingress supports pathType */}}
{{/* pathType was added to networking.k8s.io/v1beta1 in Kubernetes 1.18 */}}
{{- define "ingress.supportsPathType" -}}
  {{- or (eq (include "ingress.isStable" .) "true") (and (eq (include "ingress.apiVersion" .) "networking.k8s.io/v1beta1") (semverCompare ">= 1.18-0" (include "kubeVersion" .))) -}}
{{- end -}}

{{- define "ingress.FieldNotAnnotation" -}}
  {{- (semverCompare ">= 1.27-0" (include "kubeVersion" .)) -}}
{{- end -}}

{{/*
Name of the Gateway resource. Uses gateway.name if set, otherwise derives one from the release name.
*/}}
{{- define "sftd.gatewayName" -}}
{{- if .Values.gateway.name -}}
{{ .Values.gateway.name }}
{{- else -}}
{{ include "sftd.fullname" . }}-gateway
{{- end -}}
{{- end -}}

{{/*
The address sftd advertises to clients for media, i.e. the argument to -A.
Unset defaults to __SFT_EXT_IP__, which keeps the get-external-ip helper on and
preserves the behaviour of charts that never set mediaIP. Used by both the
rendered command and the placeholder detection below, so the two cannot drift.
*/}}
{{- define "sftd.mediaIp" -}}
{{- default "__SFT_EXT_IP__" .Values.mediaIP -}}
{{- end -}}

{{/*
Whether the rendered command depends on the node's discovered external IP. This
drives whether the get-external-ip init container and its node-read RBAC are
included. True when mediaIP falls back to __SFT_EXT_IP__ because it is unset, or
when it is set to a value embedding the placeholder. Uses contains rather than
eq so an embedded form still counts. Returns "true" or "".
*/}}
{{- define "sftd.usesExternalIp" -}}
{{- if contains "__SFT_EXT_IP__" (include "sftd.mediaIp" .) -}}true{{- end -}}
{{- end -}}

{{/*
The effective mediaIP with each placeholder replaced by the shell variable that
holds it, for use inside the container command. The substitution happens here at
render time rather than with sed in the container, so a discovered address is
only ever expanded inside a quoted shell variable and can never be parsed as
part of a sed expression.
*/}}
{{- define "sftd.mediaIpShell" -}}
{{- $ip := include "sftd.mediaIp" . -}}
{{- $ip = replace "__SFT_EXT_IP__" "${EXTERNAL_IP}" $ip -}}
{{- $ip = replace "__SFT_HOST_IP__" "${HOST_IP}" $ip -}}
{{- $ip = replace "__SFT_POD_IP__" "${POD_IP}" $ip -}}
{{- $ip -}}
{{- end -}}

{{/*
Whether mediaIP resolves to the pod's own address. Under hostNetwork the pod and
host addresses are the same, so both placeholders are equivalent for sftd.
advertiseInternalIp already advertises that address via -B, so combining the two
would advertise one address twice.
*/}}
{{- define "sftd.mediaIpIsPodAddress" -}}
{{- $ip := include "sftd.mediaIp" . -}}
{{- if or (contains "__SFT_POD_IP__" $ip) (contains "__SFT_HOST_IP__" $ip) -}}true{{- end -}}
{{- end -}}
