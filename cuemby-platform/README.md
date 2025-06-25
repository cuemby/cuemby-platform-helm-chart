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
| configurator.configurator.dockerconfig.password | string | `""` | "This is the password for accessing the Docker registry." |
| configurator.configurator.dockerconfig.registry | string | `""` | This is the URL of the Docker registry where the configurator image is stored. |
| configurator.configurator.dockerconfig.username | string | `""` | This is the username for accessing the Docker registry. |
| configurator.configurator.enabled | bool | `true` | Enable or disable the configurator deployment |
| configurator.configurator.environment.GITHUB_CLIENT_ID | string | `""` | GitHub OAuth client ID |
| configurator.configurator.environment.GITHUB_CLIENT_SECRET | string | `""` | GitHub OAuth client secret |
| configurator.configurator.environment.PGPASSWORD | string | `""` | Database password |
| configurator.configurator.environment.PGUSERNAME | string | `""` | Database username |
| configurator.secret.db.database | string | `""` |  |
| configurator.secret.db.password | string | `""` |  |
| configurator.secret.db.username | string | `""` |  |
| configurator.secret.github.clientId | string | `""` |  |
| configurator.secret.github.clientSecret | string | `""` |  |
| core.analytics.affinity | object | `{}` | Affinity rules for scheduling analytics pods |
| core.analytics.autoscaling.enabled | bool | `true` | Enable or disable autoscaling for analytics |
| core.analytics.autoscaling.maxReplicas | int | `100` | Maximum number of replicas for autoscaling |
| core.analytics.autoscaling.minReplicas | int | `1` | Minimum number of replicas for autoscaling |
| core.analytics.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage for autoscaling |
| core.analytics.enabled | bool | `true` |  |
| core.auth.environment.API_EXTERNAL_URL | string | `""` | Public API endpoint for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_CLIENT_ID | string | `""` | GitHub OAuth client ID for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_ENABLED | string | `""` | Enable GitHub OAuth authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_REDIRECT_URI | string | `""` | Redirect URI for GitHub OAuth |
| core.auth.environment.GOTRUE_EXTERNAL_GITHUB_SECRET | string | `""` | GitHub OAuth client secret for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_CLIENT_ID | string | `""` | GitLab OAuth client ID for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_ENABLED | string | `""` | Enable GitLab OAuth authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_REDIRECT_URI | string | `""` | Redirect URI for GitLab OAuth |
| core.auth.environment.GOTRUE_EXTERNAL_GITLAB_SECRET | string | `""` | GitLab OAuth client secret for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_CLIENT_ID | string | `""` | Google OAuth client ID for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_ENABLED | string | `""` | Enable Google OAuth authentication |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_REDIRECT_URI | string | `""` | Redirect URI for Google OAuth |
| core.auth.environment.GOTRUE_EXTERNAL_GOOGLE_SECRET | string | `""` | Google OAuth client secret for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_CLIENT_ID | string | `""` | Microsoft OAuth client ID for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_ENABLED | string | `""` | Enable Microsoft OAuth authentication |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_REDIRECT_URI | string | `""` | Redirect URI for Microsoft OAuth |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_SECRET | string | `""` | Microsoft OAuth client secret for authentication |
| core.auth.environment.GOTRUE_EXTERNAL_MICROSOFT_TENANT | string | `""` | Microsoft OAuth tenant ID |
| core.auth.environment.GOTRUE_LOG_FILE | string | `"/var/log/go/auth.log"` | Log file path for authentication logs |
| core.auth.environment.GOTRUE_SITE_URL | string | `""` | Site URL for authentication redirects |
| core.auth.environment.GOTRUE_SMTP_ADMIN_EMAIL | string | `""` | SMTP admin email for authentication |
| core.auth.environment.GOTRUE_SMTP_HOST | string | `""` | SMTP server hostname |
| core.auth.environment.GOTRUE_SMTP_PORT | string | `""` | SMTP server port |
| core.auth.environment.GOTRUE_SMTP_SENDER_NAME | string | `""` | SMTP sender name |
| core.auth.environment.LOG_LEVEL | string | `"debug"` | Log level (available without GOTRUE prefix) |
| core.auth.environment.MAILER_OTP_EXP | string | `"259200"` | Expiration time for OTPs in seconds |
| core.auth.environment.MAILER_SUBJECTS_CONFIRMATION | string | `""` | Email subject for confirmation |
| core.auth.environment.MAILER_SUBJECTS_EMAIL_CHANGE | string | `""` | Email subject for email change confirmation |
| core.auth.environment.MAILER_SUBJECTS_INVITE | string | `""` | Email subject for invitation |
| core.auth.environment.MAILER_SUBJECTS_MAGIC_LINK | string | `""` | Email subject for magic link |
| core.auth.environment.MAILER_SUBJECTS_RECOVERY | string | `""` | Email subject for password recovery |
| core.auth.environment.MAILER_TEMPLATES_CONFIRMATION | string | `""` | Email template for confirmation |
| core.auth.environment.MAILER_TEMPLATES_EMAIL_CHANGE | string | `""` | Email template for email change confirmation |
| core.auth.environment.MAILER_TEMPLATES_MAGIC_LINK | string | `""` | Email template for magic link |
| core.auth.environment.MAILER_TEMPLATES_RECOVERY | string | `""` | Email template for password recovery |
| core.functions.dockerconfig.password | string | `""` | Docker registry password for functions |
| core.functions.dockerconfig.registry | string | `""` | Docker registry for functions |
| core.functions.dockerconfig.username | string | `""` | Docker registry username for functions |
| core.functions.environment.CCP_DOMAIN_APP | string | `""` | Domain for application access |
| core.functions.environment.CP_CORE_REGISTRY_DEFAULT_PRODIVER | string | `""` | Default registry provider for core |
| core.functions.environment.HARBOR_BASE_URL | string | `""` | Base URL of the Harbor registry |
| core.functions.environment.HARBOR_PASSWORD | string | `""` | Harbor registry password |
| core.functions.environment.HARBOR_REGISTRY | string | `""` | Harbor registry name |
| core.functions.environment.HARBOR_USERNAME | string | `""` | Harbor registry username |
| core.functions.environment.INGRESS_ANNOTATIONS | string | `""` | Ingress annotations for functions |
| core.functions.environment.INGRESS_CLASSNAME | string | `""` | Ingress class name for functions |
| core.functions.environment.INGRESS_ENABLED | string | `""` | Enable or disable ingress for functions |
| core.functions.environment.INGRESS_TLS_ENABLED | string | `""` | Enable or disable TLS for functions ingress |
| core.functions.environment.LIMIT_STORAGE_HARBOR | string | `""` | Harbor storage limit for functions |
| core.functions.environment.REDIS_HOSTNAME | string | `""` | Redis hostname for functions |
| core.functions.environment.REDIS_PASSWORD | string | `""` | Redis password for functions |
| core.functions.environment.REDIS_PORT | string | `""` | Redis port for functions |
| core.functions.environment.REDIS_USERNAME | string | `""` | Redis username for functions |
| core.functions.environment.SENTRY_DSN | string | `""` | Sentry DSN for error monitoring |
| core.functions.environment.SUPA_URL | string | `""` | Supabase URL for backend integration |
| core.imgproxy.environment.IMGPROXY_AUTO_WEBP | string | `"true"` | Automatically enable WebP image format for optimized images |
| core.imgproxy.environment.IMGPROXY_BIND | string | `":5001"` | Address and port to bind the imgproxy service |
| core.imgproxy.environment.IMGPROXY_KEY | string | `""` | Secret key used to sign image URLs for security |
| core.imgproxy.environment.IMGPROXY_LOCAL_FILESYSTEM_ROOT | string | `"/"` | Root path of the local file system accessible by imgproxy |
| core.imgproxy.environment.IMGPROXY_SALT | string | `""` | Salt used for secure image URL generation |
| core.imgproxy.environment.IMGPROXY_USE_ETAG | string | `"true"` | Enable or disable ETag support for caching |
| core.kong.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` | Cluster issuer used by cert-manager for TLS certificates |
| core.kong.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` | Enable or disable Cloudflare proxy for external-dns |
| core.kong.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` | Hostname used by external-dns |
| core.kong.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` | Backend protocol used by ingress (e.g., HTTP, HTTPS) |
| core.kong.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` | Forces SSL redirect in nginx ingress |
| core.kong.ingress.className | string | `""` | Ingress class name for Kong |
| core.kong.ingress.hosts[0].host | string | `""` | Host for Kong ingress |
| core.kong.ingress.hosts[0].paths[0].path | string | `"/"` | Path for Kong ingress |
| core.kong.ingress.hosts[0].paths[0].pathType | string | `"Prefix"` | Path type for Kong ingress |
| core.kong.ingress.tls[0].hosts[0] | string | `""` | Host for Kong TLS ingress |
| core.kong.ingress.tls[0].secretName | string | `""` | TLS secret for Kong ingress |
| core.minio.host | string | `""` | MinIO host address |
| core.minio.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` | Cluster issuer used by cert-manager for TLS certificates |
| core.minio.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` | Enable or disable Cloudflare proxy for external-dns |
| core.minio.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` | Hostname used by external-dns |
| core.minio.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` | Backend protocol used by ingress (e.g., HTTP, HTTPS) |
| core.minio.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` | Forces SSL redirect in nginx ingress |
| core.minio.ingress.className | string | `""` | Ingress class name for MinIO |
| core.minio.ingress.enabled | bool | `true` | Enable or disable MinIO ingress |
| core.minio.tls[0].hosts[0] | string | `""` | Host for MinIO TLS ingress |
| core.minio.tls[0].secretName | string | `""` | TLS secret name for MinIO |
| core.realtime.enabled | bool | `true` | Enable or disable the realtime service |
| core.realtime.environment.SECRET_KEY_BASE | string | `""` | Secret used to encrypt communication in realtime service |
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
| core.studio.environment.NEXT_ANALYTICS_BACKEND_PROVIDER | string | `""` | Analytics backend provider for Studio |
| core.studio.environment.NEXT_PUBLIC_ENABLE_LOGS | string | `""` | Enable or disable frontend logging in Studio |
| core.studio.environment.STUDIO_DEFAULT_ORGANIZATION | string | `""` | Default studio organization and project |
| core.studio.environment.STUDIO_DEFAULT_PROJECT | string | `""` | Default project for Studio |
| core.studio.environment.SUPABASE_PUBLIC_URL | string | `""` | Supabase public URL for Studio |
| core.studio.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` | Ingress annotations for Studio |
| core.studio.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` | Enable or disable Cloudflare proxy for Studio |
| core.studio.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` | Hostname for Studio ingress |
| core.studio.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` | Sets backend protocol for Studio ingress |
| core.studio.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` | Forces SSL redirect in nginx ingress for Studio |
| core.studio.ingress.className | string | `""` | Ingress class name for Studio |
| core.studio.ingress.host | string | `""` | Hostname for Studio ingress |
| platform.enabled | bool | `true` | Enable or disable the platform module |
| platform.platform.dockerconfig.password | string | `""` | This is the password for accessing the Docker registry. |
| platform.platform.dockerconfig.registry | string | `""` | This is the URL of the Docker registry where the configurator image is stored. |
| platform.platform.dockerconfig.username | string | `""` | This is the username for accessing the Docker registry. |
| platform.platform.enabled | bool | `true` | Enable or disable the platform module |
| platform.platform.environment.API_KEY | string | `""` | This is the API key for the service (this is for the authentication layer) |
| platform.platform.environment.DB_PASSWORD | string | `""` | Database password |
| platform.platform.environment.DB_USERNAME | string | `""` | Database username |
| platform.platform.environment.HARBOR_BASE_URL | string | `""` | This is the URL of your Docker registry, either Harbor or Docker Hub, that you have configured. |
| platform.platform.environment.HARBOR_PASSWORD | string | `""` | This is the password for accessing your Docker registry. |
| platform.platform.environment.HARBOR_USERNAME | string | `""` | This is the username for accessing your Docker registry. |
| platform.rabbitmq.auth.enableLoopbackUser | bool | `false` | Enable or disable loopback user for RabbitMQ |
| platform.rabbitmq.auth.erlangCookie | string | `""` | This is the erlang cookie for RabbitMQ |
| platform.rabbitmq.auth.password | string | `""` | This is the password for the RabbitMQ user. |
| platform.rabbitmq.auth.securePassword | bool | `true` | Enable or disable RabbitMQ authentication |
| platform.rabbitmq.auth.username | string | `""` | This is the username for the RabbitMQ user. |
| platform.redis.architecture | string | `"standalone"` | Redis deployment architecture (e.g., standalone or cluster) |
| platform.redis.auth.enabled | bool | `true` | Enable or disable authentication in Redis |
| platform.redis.auth.password | string | `""` | This is the password for the RabbitMQ user. |
| platform.redis.auth.username | string | `""` | This is the username for the RabbitMQ user. |
| platform.redis.commonConfiguration | string | `"databases 100"` | Additional Redis configuration, like number of databases |
| platform.secret.db.database | string | `""` |  |
| platform.secret.db.password | string | `""` |  |
| platform.secret.db.username | string | `""` |  |
| platform.secret.github.clientId | string | `""` |  |
| platform.secret.github.clientSecret | string | `""` |  |
| registry.database.external.coreDatabase | string | `""` | Name of the core database schema used by Harbor |
| registry.database.external.existingSecret | string | `""` | Name of an existing Kubernetes secret containing DB credentials |
| registry.database.external.host | string | `""` | Hostname or IP of the external PostgreSQL database |
| registry.database.external.password | string | `""` | Password for the database user |
| registry.database.external.port | int | `5432` | Port number for connecting to the database |
| registry.database.external.sslmode | string | `"disable"` | SSL mode used when connecting to the database (e.g., disable, require) |
| registry.database.external.username | string | `""` | Username for authenticating to the database |
| registry.database.type | string | `"external"` | Type of database used by Harbor (e.g., external) |
| registry.enabled | bool | `true` | Enable or disable the Harbor registry |
| registry.expose.clusterIP.name | string | `"harbor"` | Name of the clusterIP service |
| registry.expose.clusterIP.ports.httpPort | int | `80` | HTTP port exposed by the clusterIP service |
| registry.expose.clusterIP.ports.httpsPort | int | `443` | HTTPS port exposed by the clusterIP service |
| registry.expose.clusterIP.staticClusterIP | string | `""` | Static cluster IP address, if manually assigned |
| registry.expose.ingress.annotations."cert-manager.io/cluster-issuer" | string | `""` | Cluster issuer used by cert-manager for TLS certificates |
| registry.expose.ingress.annotations."external-dns.alpha.kubernetes.io/cloudflare-proxied" | string | `""` | Enable or disable Cloudflare proxy for external-dns |
| registry.expose.ingress.annotations."external-dns.alpha.kubernetes.io/hostname" | string | `""` | Hostname used by external-dns |
| registry.expose.ingress.annotations."ingress.kubernetes.io/proxy-body-size" | string | `""` | Sets max size of body accepted by the ingress controller |
| registry.expose.ingress.annotations."ingress.kubernetes.io/ssl-redirect" | string | `""` | Enables or disables SSL redirect |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/backend-protocol" | string | `""` | Backend protocol used by ingress (e.g., HTTP, HTTPS) |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/force-ssl-redirect" | string | `""` | Forces SSL redirect in nginx ingress |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/proxy-body-size" | string | `""` | Sets max body size in nginx ingress |
| registry.expose.ingress.annotations."nginx.ingress.kubernetes.io/ssl-redirect" | string | `""` | Enables or disables SSL redirect in nginx ingress |
| registry.expose.ingress.className | string | `""` | Class name of the ingress controller |
| registry.expose.ingress.controller | string | `"default"` | Controller identifier for the ingress |
| registry.expose.ingress.hosts.core | string | `""` | Hostname used to expose the Harbor core service |
| registry.expose.type | string | `"ingress"` | Exposure type for Harbor (e.g., ingress, clusterIP) |
| registry.externalURL | string | `""` | External URL used to access Harbor |
| registry.harborAdminPassword | string | `""` | Password for the Harbor admin user |
| registry.redis.external.addr | string | `""` | Redis server address |
| registry.redis.external.password | string | `""` | Redis password |
| registry.redis.external.username | string | `""` | Redis username (if required) |
| registry.redis.type | string | `"external"` | Type of Redis service (e.g., external) |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.14.2](https://github.com/norwoodj/helm-docs/releases/v1.14.2)
