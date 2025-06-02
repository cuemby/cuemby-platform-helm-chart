{{/*
Create the registry credentials for cp-configurator
*/}}
{{- define "configurator.dockerconfigjson" -}}
{
  "auths": {
    "{{ .Values.configurator.dockerconfig.registry }}": {
      "username": "{{ .Values.configurator.dockerconfig.username }}",
      "password": "{{ .Values.configurator.dockerconfig.password }}",
      "auth": "{{ printf "%s:%s" .Values.configurator.dockerconfig.username .Values.configurator.dockerconfig.password | b64enc }}"
    }
  }
}
{{- end -}}
