{{/*
Create the registry credentials for cp-platform
*/}}
{{- define "platform.dockerconfigjson" -}}
{
  "auths": {
    "{{ .Values.platform.dockerconfig.registry }}": {
      "username": "{{ .Values.platform.dockerconfig.username }}",
      "password": "{{ .Values.platform.dockerconfig.password }}",
      "auth": "{{ printf "%s:%s" .Values.platform.dockerconfig.username .Values.platform.dockerconfig.password | b64enc }}"
    }
  }
}
{{- end -}}
