# cuemby-platform

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

Meta chart que instala todos los componentes obligatorios de cuemby-platform-core

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| file://../cuemby-platform-core/configurator | configurator | 1.0.0 |
| file://../cuemby-platform-core/core | core | 0.1.3 |
| file://../cuemby-platform-core/dashboard | dashboard | 1.0.0 |
| file://../cuemby-platform-core/platform | platform | 1.0.0 |
| file://../cuemby-platform-core/walrus | walrus | 1.0.0 |
| https://helm.goharbor.io | registry(harbor) | 1.14.0 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| configurator.configurator.dockerconfig.password | string | `""` |  |
| configurator.configurator.dockerconfig.registry | string | `""` |  |
| configurator.configurator.dockerconfig.username | string | `""` |  |
| configurator.configurator.enabled | bool | `true` |  |
| configurator.configurator.environment.GITHUB_CLIENT_ID | string | `""` |  |
| configurator.configurator.environment.GITHUB_CLIENT_SECRET | string | `""` |  |
| configurator.configurator.environment.PGPASSWORD | string | `""` |  |
| configurator.configurator.environment.PGUSERNAME | string | `""` |  |
| configurator.secret.db.database | string | `""` |  |
| configurator.secret.db.password | string | `""` |  |
| configurator.secret.db.username | string | `""` |  |
| configurator.secret.github.clientId | string | `""` |  |
| configurator.secret.github.clientSecret | string | `""` |  |
| core.analytics.affinity | object | `{}` |  |
| core.analytics.autoscaling.enabled | bool | `true` |  |
| core.analytics.autoscaling.maxReplicas | int | `100` |  |
| core.analytics.autoscaling.minReplicas | int | `1` |  |
| core.analytics.autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| core.analytics.enabled | bool | `true` |  |
| core.auth.environment.API_EXTERNAL_URL | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_CLIENT_ID | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_ENABLED | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_REDIRECT_URI | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_SECRET | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_CLIENT_ID | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_ENABLED | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_REDIRECT_URI | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_SECRET | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_ENABLED | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_SECRET | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_CLIENT_ID | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_ENABLED | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_REDIRECT_URI | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_SECRET | string | `""` |  |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_TENANT | string | `""` |  |
| core.auth.environment.GOTRUE_LOG_FILE | string | `""` |  |
| core.auth.environment.GOTRUE_SITE_URL | string | `""` |  |
| core.auth.environment.GOTRUE_SMTP_ADMIN_EMAIL | string | `""` |  |
| core.auth.environment.GOTRUE_SMTP_HOST | string | `""` |  |
| core.auth.environment.GOTRUE_SMTP_PORT | string | `""` |  |
| core.auth.environment.GOTRUE_SMTP_SENDER_NAME | string | `""` |  |
| core.auth.environment.LOG_LEVEL | string | `""` |  |
| core.auth.environment.MAILER_OTP_EXP | string | `""` |  |
| core.auth.environment.MAILER_SUBJECTS_CONFIRMATION | string | `""` |  |
| core.auth.environment.MAILER_SUBJECTS_EMAIL_CHANGE | string | `""` |  |
| core.auth.environment.MAILER_SUBJECTS_INVITE | string | `""` |  |
| core.auth.environment.MAILER_SUBJECTS_MAGIC_LINK | string | `""` |  |
| core.auth.environment.MAILER_SUBJECTS_RECOVERY | string | `""` |  |
| core.auth.environment.MAILER_TEMPLATES_CONFIRMATION | string | `""` |  |
| core.auth.environment.MAILER_TEMPLATES_EMAIL_CHANGE | string | `""` |  |
| core.auth.environment.MAILER_TEMPLATES_MAGIC_LINK | string | `""` |  |
| core.auth.environment.MAILER_TEMPLATES_RECOVERY | string | `""` |  |
| core.functions.dockerconfig.password | string | `""` |  |
| core.functions.dockerconfig.registry | string | `""` |  |
| core.functions.dockerconfig.username | string | `""` |  |
| core.functions.environment.CCP_DOMAIN_APP | string | `""` |  |
| core.functions.environment.CP_CORE_REGISTRY_DEFAULT_PRODIVER | string | `""` |  |
| core.functions.environment.HARBOR_BASE_URL | string | `""` |  |
| core.functions.environment.HARBOR_PASSWORD | string | `""` |  |
| core.functions.environment.HARBOR_REGISTRY | string | `""` |  |
| core.functions.environment.HARBOR_USERNAME | string | `""` |  |
| core.functions.environment.INGRESS_ANNOTATIONS | string | `""` |  |
| core.functions.environment.INGRESS_CLASSNAME | string | `""` |  |
| core.functions.environment.INGRESS_ENABLED | string | `""` |  |
| core.functions.environment.INGRESS_TLS_ENABLED | string | `""` |  |
| core.functions.environment.LIMIT_STORAGE_HARBOR | string | `""` |  |
| core.functions.environment.REDIS_HOSTNAME | string | `""` |  |
| core.functions.environment.REDIS_PASSWORD | string | `""` |  |
| core.functions.environment.REDIS_PORT | string | `""` |  |
| core.functions.environment.REDIS_USERNAME | string | `""` |  |
| core.functions.environment.SENTRY_DSN | string | `""` |  |
| core.functions.environment.SUPA_URL | string | `""` |  |
| core.imgproxy.environment.IMGPROXY_AUTO_WEBP | string | `"true"` |  |
| core.imgproxy.environment.IMGPROXY_BIND | string | `":5001"` |  |
| core.imgproxy.environment.IMGPROXY_KEY | string | `""` |  |
| core.imgproxy.environment.IMGPROXY_LOCAL_FILESYSTEM_ROOT | string | `"/"` |  |
| core.imgproxy.environment.IMGPROXY_SALT | string | `""` |  |
| core.imgproxy.environment.IMGPROXY_USE_ETAG | string | `"true"` |  |
| core.kong.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` |  |
| core.kong.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` |  |
| core.kong.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` |  |
| core.kong.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` |  |
| core.kong.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` |  |
| core.kong.ingress.className | string | `""` |  |
| core.kong.ingress.hosts[0].host | string | `""` |  |
| core.kong.ingress.hosts[0].paths[0].path | string | `"/"` |  |
| core.kong.ingress.hosts[0].paths[0].pathType | string | `"Prefix"` |  |
| core.kong.ingress.tls[0].hosts[0] | string | `""` |  |
| core.kong.ingress.tls[0].secretName | string | `""` |  |
| core.minio.host | string | `""` |  |
| core.minio.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` |  |
| core.minio.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` |  |
| core.minio.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` |  |
| core.minio.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` |  |
| core.minio.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` |  |
| core.minio.ingress.className | string | `""` |  |
| core.minio.ingress.enabled | bool | `true` |  |
| core.minio.tls[0].hosts[0] | string | `""` |  |
| core.minio.tls[0].secretName | string | `""` |  |
| core.realtime.enabled | bool | `true` |  |
| core.realtime.environment.SECRET_KEY_BASE | string | `""` |  |
| core.secret.analytics.apiKey | string | `""` |  |
| core.secret.dashboard.password | string | `""` |  |
| core.secret.dashboard.username | string | `""` |  |
| core.secret.db.database | string | `""` |  |
| core.secret.db.password | string | `""` |  |
| core.secret.db.username | string | `""` |  |
| core.secret.git.repoUrl | string | `""` |  |
| core.secret.git.secretName | string | `""` |  |
| core.secret.git.token | string | `""` |  |
| core.secret.jwt.anonKey | string | `""` |  |
| core.secret.jwt.secret | string | `""` |  |
| core.secret.jwt.serviceKey | string | `""` |  |
| core.secret.s3.accessKey | string | `""` |  |
| core.secret.s3.bucket | string | `""` |  |
| core.secret.s3.cdnUrl | string | `""` |  |
| core.secret.s3.endpoint | string | `""` |  |
| core.secret.s3.keyId | string | `""` |  |
| core.secret.s3.region | string | `""` |  |
| core.secret.s3.secretKey | string | `""` |  |
| core.secret.smtp.password | string | `""` |  |
| core.secret.smtp.username | string | `""` |  |
| core.studio.environment.NEXT_ANALYTICS_BACKEND_PROVIDER | string | `""` |  |
| core.studio.environment.NEXT_PUBLIC_ENABLE_LOGS | string | `""` |  |
| core.studio.environment.STUDIO_DEFAULT_ORGANIZATION | string | `""` |  |
| core.studio.environment.STUDIO_DEFAULT_PROJECT | string | `""` |  |
| core.studio.environment.SUPABASE_PUBLIC_URL | string | `""` |  |
| core.studio.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` |  |
| core.studio.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` |  |
| core.studio.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` |  |
| core.studio.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` |  |
| core.studio.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` |  |
| core.studio.ingress.className | string | `""` |  |
| core.studio.ingress.host | string | `""` |  |
| platform.enabled | bool | `true` |  |
| platform.global | object | `{}` |  |
| platform.platform.dockerconfig.password | string | `""` |  |
| platform.platform.dockerconfig.registry | string | `""` |  |
| platform.platform.dockerconfig.username | string | `""` |  |
| platform.platform.enabled | bool | `true` |  |
| platform.platform.environment.API_KEY | string | `""` |  |
| platform.platform.environment.DB_PASSWORD | string | `""` |  |
| platform.platform.environment.DB_USERNAME | string | `""` |  |
| platform.platform.environment.HARBOR_BASE_URL | string | `""` |  |
| platform.platform.environment.HARBOR_PASSWORD | string | `""` |  |
| platform.platform.environment.HARBOR_USERNAME | string | `""` |  |
| platform.rabbitmq.auth.enableLoopbackUser | bool | `false` |  |
| platform.rabbitmq.auth.erlangCookie | string | `""` |  |
| platform.rabbitmq.auth.existingErlangSecret | string | `""` |  |
| platform.rabbitmq.auth.existingPasswordSecret | string | `""` |  |
| platform.rabbitmq.auth.password | string | `""` |  |
| platform.rabbitmq.auth.securePassword | bool | `true` |  |
| platform.rabbitmq.auth.username | string | `""` |  |
| platform.redis.architecture | string | `"standalone"` |  |
| platform.redis.auth.enabled | bool | `true` |  |
| platform.redis.auth.password | string | `""` |  |
| platform.redis.auth.username | string | `""` |  |
| platform.redis.commonConfiguration | string | `"databases 100"` |  |
| platform.secret.db.database | string | `""` |  |
| platform.secret.db.password | string | `""` |  |
| platform.secret.db.username | string | `""` |  |
| platform.secret.github.clientId | string | `""` |  |
| platform.secret.github.clientSecret | string | `""` |  |
| registry.database.external.coreDatabase | string | `""` |  |
| registry.database.external.existingSecret | string | `""` |  |
| registry.database.external.host | string | `""` |  |
| registry.database.external.password | string | `""` |  |
| registry.database.external.port | int | `5432` |  |
| registry.database.external.sslmode | string | `"disable"` |  |
| registry.database.external.username | string | `""` |  |
| registry.database.type | string | `"external"` |  |
| registry.enabled | bool | `true` |  |
| registry.expose.clusterIP.annotations | object | `{}` |  |
| registry.expose.clusterIP.labels | object | `{}` |  |
| registry.expose.clusterIP.name | string | `"harbor"` |  |
| registry.expose.clusterIP.ports.httpPort | int | `80` |  |
| registry.expose.clusterIP.ports.httpsPort | int | `443` |  |
| registry.expose.clusterIP.staticClusterIP | string | `""` |  |
| registry.expose.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` |  |
| registry.expose.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` |  |
| registry.expose.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` |  |
| registry.expose.ingress.annotations."ingress.kubernetes.io/proxy-body-size" | string | `""` |  |
| registry.expose.ingress.annotations."ingress.kubernetes.io/ssl-redirect" | string | `""` |  |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` |  |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` |  |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/proxy-body-size" | string | `""` |  |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/ssl-redirect" | string | `""` |  |
| registry.expose.ingress.className | string | `""` |  |
| registry.expose.ingress.controller | string | `"default"` |  |
| registry.expose.ingress.hosts.core | string | `""` |  |
| registry.expose.type | string | `"ingress"` |  |
| registry.externalURL | string | `""` |  |
| registry.harborAdminPassword | string | `""` |  |
| registry.redis.external.addr | string | `""` |  |
| registry.redis.external.password | string | `""` |  |
| registry.redis.external.username | string | `""` |  |
| registry.redis.type | string | `"external"` |  |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
