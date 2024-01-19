{{/*
Expand the name of the chart.
*/}}
{{- define "kuryr.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kuryr.fullname" -}}
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
{{- define "kuryr.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kuryr.labels" -}}
helm.sh/chart: {{ include "kuryr.chart" . }}
{{ include "kuryr.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kuryr.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kuryr.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/*
Create the name of the controller service account to use
*/}}
{{- define "kuryr.controller.serviceAccountName" -}}
{{- if .Values.controller.serviceAccount.create }}
{{- default (printf "%s-controller" (include "kuryr.fullname" .)) .Values.controller.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.controller.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the cni service account to use
*/}}
{{- define "kuryr.cni.serviceAccountName" -}}
{{- if .Values.cni.serviceAccount.create }}
{{- default (printf "%s-cni" (include "kuryr.fullname" .)) .Values.cni.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.cni.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMapName" -}}
{{- default ( printf "%s" (include "kuryr.fullname" .) ) .Values.existingConfigMap | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{/*
Create the k8s_api_root of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.k8sApiRoot" -}}
{{- default "127.0.0.1:6443" .Values.config.kubernetes.k8sApiRoot }}
{{- end -}}

{{/*
Create the project_domain_name of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.projectDomainName" -}}
{{- default "default" .Values.config.neutron.projectDomainName }}
{{- end -}}

{{/*
Create the user_domain_name of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.userDomainName" -}}
{{- default "default" .Values.config.neutron.userDomainName }}
{{- end -}}

{{/*
Create the user_name of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.userName" -}}
{{- default "neutron" .Values.config.neutron.userName }}
{{- end -}}

{{/*
Create the password of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.password" -}}
{{- default "Inspur1!" .Values.config.neutron.password }}
{{- end -}}

{{/*
Create the authType of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.authType" -}}
{{- default "password" .Values.config.neutron.authType }}
{{- end -}}

{{/*
Create the debug of the settings ConfigMap to use.
*/}}
{{- define "kuryr.configMap.debug" -}}
{{- default "true" .Values.config.debug }}
{{- end -}}

