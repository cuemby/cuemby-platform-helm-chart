#!/bin/bash
set -euo pipefail

# ========================
# COLORS
# ========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ========================
# NAMESPACES & TIMEOUT
# ========================
NAMESPACE_ISTIO="istio-system"
NAMESPACE_KNATIVE_OPERATOR="knative-operator"
NAMESPACE_KNATIVE_SERVING="knative-serving"
NAMESPACE_MONITORING="cuemby-system"
TIMEOUT="600s"

# ===== Public IP ========
PUBLIC_IP=$(curl -s ifconfig.me)

# ===== Vars Cuemby Platform =====
DOCKERCONFIG_PASSWORD=""
DOCKERCONFIG_REGISTRY=""
DOCKERCONFIG_USERNAME=""
SIGNUP_EMAIL=""
SIGNUP_PASSWORD=""
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
PG_USERNAME=""
PG_PASSWORD=""
JWT_ANON_KEY=""
JWT_SERVICE_KEY=""
JWT_SECRET=""
API_BASE_URL=""
API_KEY=""
HARBOR_BASE_URL=""
HARBOR_PASSWORD=""
HARBOR_USERNAME=""
RABBITMQ_PASSWORD=""
RABBITMQ_USERNAME=""
REDIS_PASSWORD=""
REDIS_USERNAME=""
SMTP_USERNAME=""
SMTP_PASSWORD=""
DASHBOARD_PASSWORD=""
DASHBOARD_USERNAME=""
MINIO_USERNAME=""
MINIO_PASSWORD=""
S3_KEYID=""
S3_ACCESSKEY=""
S3_SECRETKEY=""

GOTRUE_SMTP_HOST=""
GOTRUE_SMTP_PORT=""
GOTRUE_SMTP_ADMIN_EMAIL=""
CCP_DOMAIN_APP=""

# ===== URLS Domains =====
GATEWAY_DOMAIN=""
DASHBOARD_DOMAIN=""
API_DOMAIN=""
REGISTRY_DOMAIN=""
STORAGE_DOMAIN=""
WALRUS_DOMAIN=""

# ===== Vars Nginx Controller =====
CF_API_TOKEN=""
ORIGIN_CA_KEY=""
EXT_DNS_NS="external-dns"
ORIGIN_CA_NS="origin-ca"
CLUSTER_ISSUER_NAME="origin-ca-issuer"
INGRESS_NS="ingress-nginx"

# ===== Vars Notify Email =====
NOTIFY_EMAIL="${NOTIFY_EMAIL:-}"
RESEND_API_KEY="${RESEND_API_KEY:-}"
RESEND_FROM="${RESEND_FROM:-}"


# ========================
# Check command exists
# ========================
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 no está instalado. Instálalo primero."
    fi
}

# ========================
# Wait for deployment
# ========================
wait_for_deployment() {
    local namespace=$1
    local deployment=$2
    print_status "Esperando a que el deployment $deployment esté listo en el namespace $namespace..."
    microk8s kubectl wait --for=condition=available --timeout=$TIMEOUT deployment/$deployment -n $namespace
}

# ========================
# Create namespace if not exist
# ========================
create_namespace() {
    local ns=$1
    if ! microk8s kubectl get ns "$ns" &> /dev/null; then
        print_status "Creando namespace $ns..."
        microk8s kubectl create namespace "$ns"
    else
        print_status "El namespace $ns ya existe, omitiendo creación."
    fi
}

# ========================
# Install MicroK8s & Public IP Setup
# ========================
install_microk8s() {
    print_status "Instalando MicroK8s..."
    snap install microk8s --classic --channel=1.30/stable

    # Si no es root, agregar usuario al grupo
    if [ "$(id -u)" -ne 0 ]; then
        print_status "Agregando usuario actual al grupo microk8s..."
        sudo usermod -a -G microk8s "$USER"
    fi

    print_status "Esperando a que MicroK8s esté completamente operativo..."
    microk8s status --wait-ready

    print_status "Habilitando complementos básicos (dns, storage, helm3)..."
    microk8s enable dns storage helm3

    # ========================
    # Enable MetalLB with automatic network detection
    # ========================
    print_status "Verificando MetalLB..."
    if ! microk8s status | grep -q "metallb: enabled"; then
        print_status "IP pública detectada: $PUBLIC_IP"
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        SUBNET=$(echo "$LOCAL_IP" | awk -F. '{print $1"."$2"."$3}')
        START_IP="${SUBNET}.240"
        END_IP="${SUBNET}.250"
        METALLB_RANGE="${START_IP}-${END_IP}"
        microk8s enable metallb:$METALLB_RANGE
    fi

    print_success "MicroK8s instalado."
}

# ========================
# Configurar kubeconfig con IP pública
# ========================
configure_kubeconfig_public_ip() {
    print_status "Detectando IP pública de la instancia..."
    print_status "IP pública detectada: $PUBLIC_IP"

    CSR_FILE="/var/snap/microk8s/current/certs/csr.conf.template"
    if ! grep -q "$PUBLIC_IP" "$CSR_FILE"; then
        print_status "Agregando IP pública ${PUBLIC_IP} al csr.conf.template..."
        # Calcula el siguiente índice disponible de IP
        INDEX=$(grep -c '^IP\.' "$CSR_FILE")
        INDEX=$((INDEX + 1))
        
        if grep -q "#MOREIPS" "$CSR_FILE"; then
            sudo sed -i "/#MOREIPS/i IP.${INDEX} = ${PUBLIC_IP}" "$CSR_FILE"
        else
            echo "IP.${INDEX} = ${PUBLIC_IP}" | sudo tee -a "$CSR_FILE" > /dev/null
        fi
    else
        print_status "La IP pública ya estaba agregada al csr.conf.template"
    fi

    print_status "Creando respaldo de certificados..."
    sudo cp -a /var/snap/microk8s/current/certs /var/snap/microk8s/current/certs.bak.$(date +%s)

    print_status "Regenerando certificados del API Server..."
    sudo microk8s refresh-certs --cert server.crt

    print_status "Reiniciando MicroK8s..."
    microk8s stop
    sleep 5
    microk8s start

    print_status "Esperando a que MicroK8s esté listo..."
    RETRIES=0
    until microk8s status --wait-ready || [ $RETRIES -ge 12 ]; do
        print_warning "MicroK8s aún no está listo, reintentando... ($RETRIES/12)"
        sleep 10
        ((RETRIES++))
    done

    if ! microk8s status --wait-ready; then
        print_error "MicroK8s no pudo iniciar correctamente después de regenerar certificados."
    fi

    print_status "Generando kubeconfig con la IP pública..."
    mkdir -p $HOME/.kube
    microk8s config > $HOME/.kube/config
    sed -i "s|https://.*:16443|https://${PUBLIC_IP}:16443|g" $HOME/.kube/config

    print_success "Kubeconfig actualizado y accesible con IP pública: https://${PUBLIC_IP}:16443"
}

install_istio() {
    print_status "Installing Istio with Helm..."
    create_namespace $NAMESPACE_ISTIO

    if ! microk8s helm3 repo list | grep -q "istio"; then
        microk8s helm3 repo add istio https://istio-release.storage.googleapis.com/charts
    else
        print_status "Istio repo already exists, skipping add."
    fi
    microk8s helm3 repo update

    ISTIO_VALUES="https://raw.githubusercontent.com/cuemby/cuemby-platform-helm-chart/refs/heads/main/dependencies/istio/istio.yaml"
    ISTIO_GATEWAY_VALUES="https://raw.githubusercontent.com/cuemby/cuemby-platform-helm-chart/refs/heads/main/dependencies/istio/istio-gateway.yaml"
    print_status "Installing Istio with custom values from ./dependencies/istio/..."
    print_status "Using Istio values: $ISTIO_VALUES"
    microk8s helm3 upgrade --install istiod istio/istiod \
        -n $NAMESPACE_ISTIO \
        -f "$ISTIO_VALUES" \
        --wait --timeout=$TIMEOUT

    microk8s helm3 upgrade --install istio-ingressgateway istio/gateway \
        -n $NAMESPACE_ISTIO \
        -f "$ISTIO_GATEWAY_VALUES" \
        --wait --timeout=$TIMEOUT

    wait_for_deployment $NAMESPACE_ISTIO "istiod"

    print_success "Istio successfully installed with Helm."
}

install_knative() {
    print_status "Installing Knative Operator..."
    create_namespace $NAMESPACE_KNATIVE_OPERATOR
    create_namespace $NAMESPACE_KNATIVE_SERVING

    print_status "Installing Knative Operator using kubectl..."
    microk8s kubectl apply -f https://github.com/knative/operator/releases/download/knative-v1.15.0/operator.yaml

    print_status "Waiting for the operator to be ready..."
    microk8s kubectl wait --for=condition=available --timeout=$TIMEOUT deployment/knative-operator -n $NAMESPACE_KNATIVE_OPERATOR

    print_status "Installing KnativeServing..."
    cat <<EOF | microk8s kubectl apply -f -
apiVersion: operator.knative.dev/v1beta1
kind: KnativeServing
metadata:
  name: knative-serving
  namespace: $NAMESPACE_KNATIVE_SERVING
spec:
  config:
    network:
      ingress-class: "istio.ingress.networking.knative.dev"
  ingress:
    istio:
      enabled: true
EOF

    print_status "Waiting for KnativeServing to be ready..."
    local max_attempts=5
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        print_status "Attempt $attempt/$max_attempts - Checking KnativeServing status..."

        if microk8s kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING &> /dev/null; then
            local ready_status=$(microk8s kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
            print_status "KnativeServing status: $ready_status"

            if [ "$ready_status" = "True" ]; then
                print_success "KnativeServing is ready!"
                break
            elif [ "$ready_status" = "False" ]; then
                print_warning "KnativeServing is not ready. Checking details..."
                microk8s kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING -o yaml | grep -A 10 "conditions:"
            fi
        else
            print_warning "KnativeServing not found, waiting..."
        fi

        print_status "Pods status in $NAMESPACE_KNATIVE_SERVING:"
        microk8s kubectl get pods -n $NAMESPACE_KNATIVE_SERVING 2>/dev/null || echo "No pods yet"

        if [ $attempt -eq $max_attempts ]; then
            print_warning "Timeout reached, continuing. Please verify manually with:"
            echo "kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING"
            echo "kubectl get pods -n $NAMESPACE_KNATIVE_SERVING"
            break
        fi

        sleep 10
        ((attempt++))
    done

    print_success "Knative Operator and Serving successfully installed."
}

install_prometheus() {
    print_status "Installing Prometheus Stack with Helm..."
    create_namespace $NAMESPACE_MONITORING

    # check_command microk8s helm3

    if ! microk8s helm3 repo list | grep -q "prometheus-community"; then
        microk8s helm3 repo add prometheus-community https://prometheus-community.github.io/helm-charts
    else
        print_status "prometheus-community repo already exists, skipping add."
    fi
    microk8s helm3 repo update

    PROMETHEUS_VALUES="https://raw.githubusercontent.com/cuemby/cuemby-platform-helm-chart/refs/heads/main/dependencies/prometheus.yaml"
    print_status "Installing Prometheus with custom values from ./dependencies/prometheus.yaml..."
    microk8s helm3 upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
        -n $NAMESPACE_MONITORING \
        --create-namespace \
        -f "$PROMETHEUS_VALUES" \
        --wait --timeout=$TIMEOUT

    print_success "Prometheus Stack successfully installed"
}

install_openebs() {
    helm repo add openebs-localpv https://openebs.github.io/dynamic-localpv-provisioner
    helm repo update

    helm install openebs-localpv openebs-localpv/localpv-provisioner --namespace openebs --create-namespace

    # Esperar a que se cree el storageclass
    print_status "Esperando a que se cree el StorageClass 'openebs-hostpath'..."
    until microk8s kubectl get storageclass openebs-hostpath &> /dev/null; do
        sleep 2
    done

    # Establecer como clase por defecto
    print_status "Marcando 'openebs-hostpath' como StorageClass por defecto..."
    microk8s kubectl patch storageclass openebs-hostpath \
    -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'

    print_success "'openebs-hostpath' ahora es la StorageClass por defecto."
    
}

install_nginx_ingress() {
    # Install cert-manager

    microk8s kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.17.2/cert-manager.crds.yaml

    helm repo add jetstack https://charts.jetstack.io --force-update
    microk8s kubectl create namespace cert-manager
    helm install cert-manager --version v1.17.2 jetstack/cert-manager \
    -n cert-manager

    # Install origin CA
    microk8s kubectl apply -f https://raw.githubusercontent.com/cloudflare/origin-ca-issuer/refs/heads/trunk/deploy/crds/cert-manager.k8s.cloudflare.com_clusteroriginissuers.yaml
    microk8s kubectl apply -f https://raw.githubusercontent.com/cloudflare/origin-ca-issuer/refs/heads/trunk/deploy/crds/cert-manager.k8s.cloudflare.com_originissuers.yaml

    print_status "Namespace $ORIGIN_CA_NS…"
    microk8s kubectl get ns "$ORIGIN_CA_NS" >/dev/null 2>&1 || microk8s kubectl create ns "$ORIGIN_CA_NS"

    helm install origin-ca oci://ghcr.io/cloudflare/origin-ca-issuer-charts/origin-ca-issuer --version 0.5.10 --namespace "$ORIGIN_CA_NS"

    print_status "Secret de Origin CA Key…"
    microk8s kubectl -n "$ORIGIN_CA_NS" delete secret origin-ca-issuer-secret >/dev/null 2>&1 || true
    microk8s kubectl -n "$ORIGIN_CA_NS" create secret generic origin-ca-issuer-secret \
        --from-literal=key="$ORIGIN_CA_KEY"

    print_status "ClusterOriginIssuer '$CLUSTER_ISSUER_NAME'…"
    cat <<EOF | microk8s kubectl apply -f -
apiVersion: cert-manager.k8s.cloudflare.com/v1
kind: ClusterOriginIssuer
metadata:
  name: ${CLUSTER_ISSUER_NAME}
  namespace: "$ORIGIN_CA_NS"
spec:
  requestType: OriginECC
  auth:
    serviceKeyRef:
      name: origin-ca-issuer-secret
      key: key
EOF

    # Install External-DNS    
    print_status "Namespace $EXT_DNS_NS…"
    microk8s kubectl get ns "$EXT_DNS_NS" >/dev/null 2>&1 || microk8s kubectl create ns "$EXT_DNS_NS"

    microk8s kubectl -n "$EXT_DNS_NS" create secret generic cloudflare-api-token \
        --from-literal=cloudflare_api_token="$CF_API_TOKEN"
    
    microk8s kubectl -n "$EXT_DNS_NS" get secret cloudflare-api-token \
        -o jsonpath='{.data.cloudflare_api_token}' | base64 -d; echo

    print_status "ExternalDNS (Bitnami) con provider Cloudflare…"
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo update
    helm upgrade --install external-dns bitnami/external-dns \
        -n "$EXT_DNS_NS" \
        --set provider=cloudflare \
        --set txtOwnerId="cuemby-lab" \
        --set cloudflare.secretName=cloudflare-api-token \
        --set policy=sync \
        --set env=null \
        # --set domainFilters=*.cuemby-lab.com

    # Install NGINX
    print_status "Instalando NGINX Ingress Controller…"
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
    helm repo update
    microk8s kubectl get ns "$INGRESS_NS" >/dev/null 2>&1 || microk8s kubectl create ns "$INGRESS_NS"
    helm install ingress-nginx ingress-nginx/ingress-nginx --version 4.12.2 -n $INGRESS_NS

    # Instal database Metrics Admin
    helm repo add metrics-server https://kubernetes-sigs.github.io/metrics-server/
    helm repo update
    helm upgrade --install my-metrics-server metrics-server/metrics-server \
        --version 3.12.2 \
        -n kube-system \
        --set "args[0]=--kubelet-insecure-tls"

    # Upgrade NGINX Ingress Controller
    print_status "Upgrading NGINX Ingress Controller rules…"
    helm repo update
    helm upgrade --install ingress-nginx ingress-nginx/ingress-nginx \
        --version 4.12.2 \
        -n $INGRESS_NS \
        --set controller.allowSnippetAnnotations=true \
        --set controller.config.annotations-risk-level=Critical \
        --set-string controller.config.server-snippet="location ~ /\\.git { deny all; return 404; } location ~ /Dockerfile { deny all; return 404; }" \
        --set controller.config.proxy-body-size="1500m" \
        --set controller.admissionWebhooks.enabled=true \
        --set controller.admissionWebhooks.patch.enabled=true \
        --set controller.admissionWebhooks.failurePolicy=Ignore \
        --set controller.admissionWebhooks.certManager.enabled=false
    
    print_success "NGINX Ingress Controller successfully installed"
}

install_helm() {
    if ! command -v helm &> /dev/null; then
        print_status "Instalando Helm..."
        curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
        chmod 700 get_helm.sh
        ./get_helm.sh
        rm get_helm.sh
        print_success "Helm instalado correctamente."
    else
        print_status "Helm ya está instalado."
    fi
}

generate_jwt() {
    
    # ---------------------------
    # Configuración
    # ---------------------------
    SECRET="$2"

    # Verificar que se pase el payload como parámetro
    if [[ $# -eq 0 ]]; then
        echo "Error: Debes proporcionar el payload JSON como parámetro"
        echo "Uso: $0 '{\"role\":\"anon\",\"iss\":\"supabase\",\"iat\":1747198800,\"exp\":1904965200}'"
        exit 1
    fi

    # Obtener el payload del primer parámetro
    PAYLOAD_JSON="$1"

    ALG="HS256"
    HEADER_JSON='{
    "alg": "'"$ALG"'",
    "typ": "JWT"
    }'

    # ---------------------------
    # Funciones
    # ---------------------------
    base64url_encode() {
        local input="${1:-}"
        if [[ -z "$input" ]]; then
            # Si no hay input como parámetro, leer desde stdin
            input=$(cat)
        fi
        # Codifica en base64 URL-safe (sin padding)
        echo -n "$input" | openssl base64 -e -A | tr '+/' '-_' | tr -d '='
    }

    sign_hs256() {
        local data="$1"
        echo -n "$data" | openssl dgst -sha256 -hmac "$SECRET" -binary | base64url_encode
    }

    # ---------------------------
    # Generación del JWT
    # ---------------------------
    HEADER_B64=$(echo -n "$HEADER_JSON" | jq -c . | base64url_encode)
    PAYLOAD_B64=$(echo -n "$PAYLOAD_JSON" | jq -c . | base64url_encode)
    SIGNATURE=$(sign_hs256 "$HEADER_B64.$PAYLOAD_B64")

    JWT="$HEADER_B64.$PAYLOAD_B64.$SIGNATURE"

    # Opcional: Verificar el JWT
    # echo ""
    # echo "Verificación del JWT:"
    # echo "Header: $(echo "$HEADER_B64" | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "Error decodificando header")"
    # echo "Payload: $(echo "$PAYLOAD_B64" | base64 -d 2>/dev/null | jq . 2>/dev/null || echo "Error decodificando payload")"
    # ---------------------------
    # Resultado
    # ---------------------------
    # echo "JWT generado:"
    echo "$JWT"
}

generate_secret() {
  openssl rand -base64 32
}

parse_cuemby_platform_args() {
    # ===== Parse CLI args =====
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dockerconfig-password) DOCKERCONFIG_PASSWORD="$2"; shift 2 ;;
            --dockerconfig-registry) DOCKERCONFIG_REGISTRY="$2"; shift 2 ;;
            --dockerconfig-username) DOCKERCONFIG_USERNAME="$2"; shift 2 ;;
            --signup-email)          SIGNUP_EMAIL="$2"; shift 2 ;;
            --signup-password)       SIGNUP_PASSWORD="$2"; shift 2 ;;
            --github-client-id)      GITHUB_CLIENT_ID="$2"; shift 2 ;;
            --github-client-secret)  GITHUB_CLIENT_SECRET="$2"; shift 2 ;;
            --pg-username)           PG_USERNAME="$2"; shift 2 ;;
            --pg-password)           PG_PASSWORD="$2"; shift 2 ;;
            # --jwt-anon-key)          JWT_ANON_KEY="$2"; shift 2 ;;
            # --jwt-service-key)       JWT_SERVICE_KEY="$2"; shift 2 ;;
            # --jwt-secret)            JWT_SECRET="$2"; shift 2 ;;
            --api-base-url)          API_BASE_URL="$2"; shift 2 ;;
            --api-key)               API_KEY="$2"; shift 2 ;;
            --harbor-base-url)       HARBOR_BASE_URL="$2"; shift 2 ;;
            --harbor-password)       HARBOR_PASSWORD="$2"; shift 2 ;;
            --harbor-username)       HARBOR_USERNAME="$2"; shift 2 ;;
            --rabbitmq-password)     RABBITMQ_PASSWORD="$2"; shift 2 ;;
            --rabbitmq-username)     RABBITMQ_USERNAME="$2"; shift 2 ;;
            --redis-password)        REDIS_PASSWORD="$2"; shift 2 ;;
            --redis-username)        REDIS_USERNAME="$2"; shift 2 ;;
            --smtp-username)         SMTP_USERNAME="$2"; shift 2 ;;
            --smtp-password)         SMTP_PASSWORD="$2"; shift 2 ;;
            --dashboard-password)    DASHBOARD_PASSWORD="$2"; shift 2 ;;
            --dashboard-username)    DASHBOARD_USERNAME="$2"; shift 2 ;;
            # --minio-username)        MINIO_USERNAME="$2"; shift 2 ;;
            # --minio-password)        MINIO_PASSWORD="$2"; shift 2 ;;
            # --s3-keyid)              S3_KEYID="$2"; shift 2 ;;
            # --s3-accesskey)          S3_ACCESSKEY="$2"; shift 2 ;;
            # --s3-secretkey)          S3_SECRETKEY="$2"; shift 2 ;;
            --cloudflare-api-token)  CF_API_TOKEN="$2"; shift 2 ;;
            --origin-ca-key)         ORIGIN_CA_KEY="$2"; shift 2 ;;
            --dashboard-domain)      DASHBOARD_DOMAIN="$2"; shift 2 ;;
            --api-domain)            API_DOMAIN="$2"; shift 2 ;;
            --registry-domain)       REGISTRY_DOMAIN="$2"; shift 2 ;;
            --storage-domain)        STORAGE_DOMAIN="$2"; shift 2 ;;
            --walrus-domain)         WALRUS_DOMAIN="$2"; shift 2 ;;
            --gateway-domain)        GATEWAY_DOMAIN="$2"; shift 2 ;;
            --gotrue-smtp-host)      GOTRUE_SMTP_HOST="$2"; shift 2 ;;
            --gotrue-smtp-port)      GOTRUE_SMTP_PORT="$2"; shift 2 ;;
            --gotrue-smtp-admin-email) GOTRUE_SMTP_ADMIN_EMAIL="$2"; shift 2 ;;
            --ccp-domain-app)        CCP_DOMAIN_APP="$2"; shift 2 ;;
            --notify-email)          NOTIFY_EMAIL="$2"; shift 2 ;;
            --resend-api-key)        RESEND_API_KEY="$2"; shift 2 ;;
            --resend-from)           RESEND_FROM="$2"; shift 2 ;;
            --) shift; break ;;
            *)
            echo "Opción desconocida: $1" exit 1 ;;
        esac
    done
}

prompt_missing_cuemby_platform_args() {
    # Helpers para pedir datos
    _prompt_plain()  { local v; read -rp "$1: " v; echo "$v"; }
    _prompt_secret() { local v; read -rsp "$1: " v; echo; echo "$v"; }

    # ===== Fallback interactivo (pide lo que falte) =====
    [[ -z "$DOCKERCONFIG_PASSWORD" ]] && DOCKERCONFIG_PASSWORD="$(_prompt_secret 'Ingrese DOCKERCONFIG_PASSWORD')"
    [[ -z "$DOCKERCONFIG_REGISTRY" ]] && DOCKERCONFIG_REGISTRY="$(_prompt_plain  'Ingrese DOCKERCONFIG_REGISTRY (p.ej. harbor-prod.cuemby.io)')"
    [[ -z "$DOCKERCONFIG_USERNAME" ]] && DOCKERCONFIG_USERNAME="$(_prompt_plain  'Ingrese DOCKERCONFIG_USERNAME')"

    [[ -z "$SIGNUP_EMAIL"    ]] && SIGNUP_EMAIL="$(_prompt_plain 'Ingrese SIGNUP_EMAIL')"
    [[ -z "$SIGNUP_PASSWORD" ]] && SIGNUP_PASSWORD="$(_prompt_secret 'Ingrese SIGNUP_PASSWORD')"

    [[ -z "$GITHUB_CLIENT_ID"     ]] && GITHUB_CLIENT_ID="$(_prompt_plain  'Ingrese GITHUB_CLIENT_ID')"
    [[ -z "$GITHUB_CLIENT_SECRET" ]] && GITHUB_CLIENT_SECRET="$(_prompt_secret 'Ingrese GITHUB_CLIENT_SECRET')"

    [[ -z "$PG_USERNAME" ]] && PG_USERNAME="$(_prompt_plain  'Ingrese PG_USERNAME')"
    [[ -z "$PG_PASSWORD" ]] && PG_PASSWORD="$(_prompt_secret 'Ingrese PG_PASSWORD')"

    # [[ -z "$JWT_ANON_KEY"    ]] && JWT_ANON_KEY="$(_prompt_secret 'Ingrese JWT_ANON_KEY')"
    # [[ -z "$JWT_SERVICE_KEY" ]] && JWT_SERVICE_KEY="$(_prompt_secret 'Ingrese JWT_SERVICE_KEY')"
    # [[ -z "$JWT_SECRET"      ]] && JWT_SECRET="$(_prompt_secret 'Ingrese JWT_SECRET (HS256)')"

    [[ -z "$API_BASE_URL" ]] && API_BASE_URL="$(_prompt_plain 'Ingrese API_BASE_URL (p.ej. http://cuemby-platform-core-kong:8000)')"
    [[ -z "$API_KEY"      ]] && API_KEY="$(_prompt_secret 'Ingrese API_KEY')"

    [[ -z "$HARBOR_BASE_URL" ]] && HARBOR_BASE_URL="$(_prompt_plain  'Ingrese HARBOR_BASE_URL (p.ej. https://harbor.../api/v2.0)')"
    [[ -z "$HARBOR_USERNAME" ]] && HARBOR_USERNAME="$(_prompt_plain  'Ingrese HARBOR_USERNAME')"
    [[ -z "$HARBOR_PASSWORD" ]] && HARBOR_PASSWORD="$(_prompt_secret 'Ingrese HARBOR_PASSWORD')"

    [[ -z "$RABBITMQ_USERNAME" ]] && RABBITMQ_USERNAME="$(_prompt_plain  'Ingrese RABBITMQ_USERNAME')"
    [[ -z "$RABBITMQ_PASSWORD" ]] && RABBITMQ_PASSWORD="$(_prompt_secret 'Ingrese RABBITMQ_PASSWORD')"

    [[ -z "$REDIS_USERNAME" ]] && REDIS_USERNAME="$(_prompt_plain  'Ingrese REDIS_USERNAME')"
    [[ -z "$REDIS_PASSWORD" ]] && REDIS_PASSWORD="$(_prompt_secret 'Ingrese REDIS_PASSWORD')"

    [[ -z "$SMTP_USERNAME" ]] && SMTP_USERNAME="$(_prompt_plain  'Ingrese SMTP_USERNAME')"
    [[ -z "$SMTP_PASSWORD" ]] && SMTP_PASSWORD="$(_prompt_secret 'Ingrese SMTP_PASSWORD')"

    [[ -z "$DASHBOARD_USERNAME" ]] && DASHBOARD_USERNAME="$(_prompt_plain  'Ingrese DASHBOARD_USERNAME')"
    [[ -z "$DASHBOARD_PASSWORD" ]] && DASHBOARD_PASSWORD="$(_prompt_secret 'Ingrese DASHBOARD_PASSWORD')"

    # [[ -z "$MINIO_USERNAME" ]] && MINIO_USERNAME="$(_prompt_plain  'Ingrese MINIO_USERNAME')"
    # [[ -z "$MINIO_PASSWORD" ]] && MINIO_PASSWORD="$(_prompt_secret 'Ingrese MINIO_PASSWORD')"

    # [[ -z "$S3_KEYID"     ]] && S3_KEYID="$(_prompt_plain  'Ingrese S3_KEYID')"
    # [[ -z "$S3_ACCESSKEY" ]] && S3_ACCESSKEY="$(_prompt_secret 'Ingrese S3_ACCESSKEY')"
    # [[ -z "$S3_SECRETKEY" ]] && S3_SECRETKEY="$(_prompt_secret 'Ingrese S3_SECRETKEY')"

    [[ -z "$CF_API_TOKEN" ]] && CF_API_TOKEN="$(_prompt_secret 'Ingrese CF_API_TOKEN')"
    [[ -z "$ORIGIN_CA_KEY" ]] && ORIGIN_CA_KEY="$(_prompt_secret 'Ingrese ORIGIN_CA_KEY')"

    [[ -z "$DASHBOARD_DOMAIN" ]] && DASHBOARD_DOMAIN="$(_prompt_plain 'Ingrese DASHBOARD_DOMAIN (p.ej. dashboard.net)')"
    [[ -z "$API_DOMAIN" ]] && API_DOMAIN="$(_prompt_plain 'Ingrese API_DOMAIN (p.ej. api.net)')"
    [[ -z "$REGISTRY_DOMAIN" ]] && REGISTRY_DOMAIN="$(_prompt_plain 'Ingrese REGISTRY_DOMAIN (p.ej. registry.net)')"
    [[ -z "$STORAGE_DOMAIN" ]] && STORAGE_DOMAIN="$(_prompt_plain 'Ingrese STORAGE_DOMAIN (p.ej. storage.net)')"
    [[ -z "$WALRUS_DOMAIN" ]] && WALRUS_DOMAIN="$(_prompt_plain 'Ingrese WALRUS_DOMAIN (p.ej. walrus.net)')"
    [[ -z "$GATEWAY_DOMAIN" ]] && GATEWAY_DOMAIN="$(_prompt_plain 'Ingrese GATEWAY_DOMAIN (p.ej. gateway.net)')"

    [[ -z "$GOTRUE_SMTP_HOST" ]] && GOTRUE_SMTP_HOST="$(_prompt_plain 'Ingrese GOTRUE_SMTP_HOST (p.ej. smtp.resend.com)')"
    [[ -z "$GOTRUE_SMTP_PORT" ]] && GOTRUE_SMTP_PORT="$(_prompt_plain 'Ingrese GOTRUE_SMTP_PORT (p.ej. 587)')"
    [[ -z "$GOTRUE_SMTP_ADMIN_EMAIL" ]] && GOTRUE_SMTP_ADMIN_EMAIL="$(_prompt_plain 'Ingrese GOTRUE_SMTP_ADMIN_EMAIL (p.ej. admin@cuemby.com)')"

    [[ -z "$CCP_DOMAIN_APP" ]] && CCP_DOMAIN_APP="$(_prompt_plain 'Ingrese DOMAIN_APP (p.ej. app-market.cuemby.net)')"

    [[ -z "$NOTIFY_EMAIL" ]] && NOTIFY_EMAIL="$(_prompt_plain 'Ingrese NOTIFY_EMAIL (p.ej. admin@cuemby.com)')"
    [[ -z "$RESEND_API_KEY" ]] && RESEND_API_KEY="$(_prompt_secret 'Ingrese RESEND_API_KEY')"
    [[ -z "$RESEND_FROM" ]] && RESEND_FROM="$(_prompt_plain 'Ingrese RESEND_FROM (p.ej. admin@cuemby.com)')"

    print_status "All params successfully setted"
}

# ========================
# INSTALL CUEMBY PLATFORM
# ========================

install_cuemby_platform() {
    
    local now
    now=$(date +%s)
    local exp
    exp=$(date -d "2030-12-31 23:59:59" +%s)
    local payloadAnon
    payloadAnon=$(jq -n \
        --arg iss "supabase" \
        --arg role "anon" \
        --argjson iat "$now" \
        --argjson exp "$exp" \
        '{
            iss: $iss,
            role: $role,
            iat: $iat,
            exp: $exp
        }'
    )
    local payloadRole
    payloadRole=$(jq -n \
        --arg iss "supabase" \
        --arg ref "default" \
        --arg role "service_role" \
        --argjson iat "$now" \
        --argjson exp "$exp" \
        '{
            iss: $iss,
            ref: $ref,
            role: $role,
            iat: $iat,
            exp: $exp
        }'
    )
    local JWT_ANON_KEY
    local JWT_SERVICE_KEY
    JWT_SECRET=$(generate_secret)
    S3_KEYID=$(generate_secret)
    S3_ACCESSKEY=$(generate_secret)
    S3_SECRETKEY=$(generate_secret)
    MINIO_USERNAME=$S3_KEYID
    MINIO_PASSWORD=$S3_ACCESSKEY
    JWT_ANON_KEY=$(generate_jwt "$payloadAnon" "$JWT_SECRET")
    JWT_SERVICE_KEY=$(generate_jwt "$payloadRole" "$JWT_SECRET")

    print_status "Generating JWTs..."
    print_status "JWT_ANON_KEY: $JWT_ANON_KEY"
    print_status "JWT_SERVICE_KEY: $JWT_SERVICE_KEY"
    print_status "JWT_SECRET: $JWT_SECRET"
    print_status "S3_KEYID: $S3_KEYID"
    print_status "S3_ACCESSKEY: $S3_ACCESSKEY"
    print_status "S3_SECRETKEY: $S3_SECRETKEY"
    print_status "MINIO_USERNAME: $MINIO_USERNAME"
    print_status "MINIO_PASSWORD: $MINIO_PASSWORD"

    helm repo add cuemby-platform https://cuemby.github.io/cuemby-platform-helm-chart
    helm repo update

    helm upgrade --install cuemby-platform cuemby-platform/cuemby-platform \
        --version 2.0.2 \
        --namespace cuemby-system --create-namespace \
        --set configurator.configurator.dockerconfig.password="$DOCKERCONFIG_PASSWORD" \
        --set configurator.configurator.dockerconfig.registry="$DOCKERCONFIG_REGISTRY" \
        --set configurator.configurator.dockerconfig.username="$DOCKERCONFIG_USERNAME" \
        --set configurator.configurator.environment.SIGNUP_EMAIL="${SIGNUP_EMAIL}" \
        --set configurator.configurator.environment.SIGNUP_PASSWORD="${SIGNUP_PASSWORD}" \
        --set configurator.configurator.environment.GITHUB_CLIENT_ID="${GITHUB_CLIENT_ID}" \
        --set configurator.configurator.environment.GITHUB_CLIENT_SECRET="${GITHUB_CLIENT_SECRET}" \
        --set configurator.configurator.environment.PGUSERNAME="${PG_USERNAME}" \
        --set configurator.configurator.environment.PGPASSWORD="${PG_PASSWORD}" \
        --set configurator.configurator.environment.API_BASE_URL="http://cuemby-platform-core-kong:8000" \
        --set configurator.configurator.environment.ANON_KEY="$JWT_ANON_KEY" \
        --set configurator.configurator.image.repository="netsaj/cp-configurator" \
        --set configurator.configurator.image.tag="v2.0.61" \
        --set platform.platform.dockerconfig.password="$DOCKERCONFIG_PASSWORD" \
        --set platform.platform.dockerconfig.registry="$DOCKERCONFIG_REGISTRY" \
        --set platform.platform.dockerconfig.username="$DOCKERCONFIG_USERNAME" \
        --set platform.platform.environment.HARBOR_USERNAME="${HARBOR_USERNAME}" \
        --set platform.platform.environment.HARBOR_PASSWORD="${HARBOR_PASSWORD}" \
        --set platform.platform.environment.HARBOR_BASE_URL="${HARBOR_BASE_URL}" \
        --set platform.platform.environment.DB_PASSWORD="${PG_PASSWORD}" \
        --set platform.platform.environment.DB_USERNAME="${PG_USERNAME}" \
        --set platform.platform.environment.API_KEY="${API_KEY}" \
        --set platform.platform.image.repository="netsaj/cp-platform" \
        --set platform.platform.image.tag="v1.0.34-dev.1" \
        --set platform.rabbitmq.auth.password="${RABBITMQ_PASSWORD}" \
        --set platform.rabbitmq.auth.username="${RABBITMQ_USERNAME}" \
        --set platform.redis.auth.password="${REDIS_PASSWORD}" \
        --set platform.redis.auth.username="${REDIS_USERNAME}" \
        --set registry.database.external.host="cuemby-platform-core-db" \
        --set registry.database.external.password="${PG_PASSWORD}" \
        --set registry.database.external.username="${PG_USERNAME}" \
        --set registry.database.external.coreDatabase="registry" \
        --set registry.redis.external.addr="cuemby-platform-redis-headless:6379" \
        --set registry.redis.external.password="${REDIS_PASSWORD}" \
        --set registry.redis.external.username="${REDIS_USERNAME}" \
        --set-string registry.expose.ingress.hosts.core="$REGISTRY_DOMAIN" \
        --set-string registry.expose.ingress.className="nginx" \
        --set-string registry.expose.ingress.controller="default" \
        --set-string registry.expose.externalUrl="https://$REGISTRY_DOMAIN" \
        --set-string registry.expose.harborAdminPassword="${HARBOR_PASSWORD}" \
        --set-json registry.expose.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$REGISTRY_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set core.imgproxy.environment.IMGPROXY_KEY="c86ee9da270bd06f3f3f39ed33264d8124ada22a957f26452e385ee0c79f5f4d" \
        --set core.imgproxy.environment.IMGPROXY_KEY="bc4682582207c756d325115d8caeb71a" \
        --set core.auth.environment.API_EXTERNAL_URL="$API_DOMAIN" \
        --set core.auth.environment.GOTRUE_SMTP_HOST="$GOTRUE_SMTP_HOST" \
        --set core.auth.environment.GOTRUE_SMTP_PORT="$GOTRUE_SMTP_PORT" \
        --set core.auth.environment.GOTRUE_SMTP_ADMIN_EMAIL="$GOTRUE_SMTP_ADMIN_EMAIL" \
        --set core.functions.dockerconfig.password="$DOCKERCONFIG_PASSWORD" \
        --set core.functions.dockerconfig.registry="$DOCKERCONFIG_REGISTRY" \
        --set core.functions.dockerconfig.username="$DOCKERCONFIG_USERNAME" \
        --set core.functions.environment.CCP_DOMAIN_APP="$CCP_DOMAIN_APP" \
        --set core.functions.environment.CP_CORE_REGISTRY_DEFAULT_PRODIVER="harbor" \
        --set core.functions.environment.HARBOR_USERNAME="${HARBOR_USERNAME}" \
        --set core.functions.environment.HARBOR_PASSWORD="${HARBOR_PASSWORD}" \
        --set core.functions.environment.HARBOR_BASE_URL="http://cuemby-platform-harbor-core:80/api/v2.0" \
        --set core.functions.environment.HARBOR_REGISTRY="$REGISTRY_DOMAIN" \
        --set core.functions.environment.REDIS_HOSTNAME="cuemby-platform-redis-headless" \
        --set core.functions.environment.REDIS_PASSWORD="${REDIS_PASSWORD}" \
        --set core.functions.environment.REDIS_USERNAME="${REDIS_USERNAME}" \
        --set core.functions.environment.REDIS_PORT="6379" \
        --set core.functions.environment.SUPA_URL="http://cuemby-platform-core-kong:8000" \
        --set core.functions.environment.CP_PLATFORM_V2_URL="http://cuemby-platform-core-kong:8000" \
        --set core.functions.environment.CP_PLATFORM_API_KEY="http://cuemby-platform-core-kong:8000" \
        --set core.functions.initContainers.image.repository="netsaj/cp-functions" \
        --set core.functions.initContainers.image.tag="v2.0.61" \
        --set-string core.minio.ingress.hosts.core="$STORAGE_DOMAIN" \
        --set-string core.minio.ingress.className="nginx" \
        --set-string core.minio.ingress.secretName="minio-market-cuemby-net-tls" \
        --set-json core.minio.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$STORAGE_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set-string core.kong.ingress.hosts[0].host=$API_DOMAIN \
        --set-string core.kong.ingress.hosts[0].paths[0].path="/" \
        --set-string core.kong.ingress.hosts[0].paths[0].pathType=Prefix \
        --set-string core.kong.ingress.tls[0].hosts[0]=$API_DOMAIN \
        --set-string core.kong.ingress.tls[0].secretName=api-market-cuemby.net-tls \
        --set-string core.kong.ingress.className="nginx" \
        --set-string core.kong.ingress.secretName="api-market-cuemby-net-tls" \
        --set-json core.kong.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$API_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set core.secret.jwt.anonKey="${JWT_ANON_KEY}" \
        --set core.secret.jwt.serviceKey="${JWT_SERVICE_KEY}" \
        --set core.secret.jwt.secret="${JWT_SECRET}" \
        --set core.secret.smtp.username="$SMTP_USERNAME" \
        --set core.secret.smtp.password="$SMTP_PASSWORD" \
        --set core.secret.dashboard.username="$DASHBOARD_USERNAME" \
        --set core.secret.dashboard.password="$DASHBOARD_PASSWORD" \
        --set core.secret.db.username="$PG_USERNAME" \
        --set core.secret.db.password="$PG_PASSWORD" \
        --set core.secret.db.database="postgress" \
        --set core.secret.s3.keyId="$S3_KEYID" \
        --set core.secret.s3.accessKey="$S3_ACCESSKEY" \
        --set core.secret.minio.secretKey="$S3_SECRETKEY" \
        --set core.secret.s3.bucket="admin" \
        --set-string core.studio.ingress.host="studio.market.cuemby.net" \
        --set-string core.studio.ingress.className="nginx" \
        --set-json core.studio.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"studio.market.cuemby.net",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set dashboard.dashboard.image.repository="netsaj/cp-dashboard" \
        --set dashboard.dashboard.image.tag="latest" \
        --set-string dashboard.dashboard.ingress.host="$DASHBOARD_DOMAIN" \
        --set-string dashboard.dashboard.ingress.className="nginx" \
        --set-string dashboard.dashboard.ingress.tls[0].hosts[0]=$DASHBOARD_DOMAIN \
        --set-string dashboard.dashboard.ingress.tls[0].secretName=dashboard-market-cuemby.net-tls \
        --set-string dashboard.dashboard.ingress.secretName="dashboard-market-cuemby-net-tls" \
        --set-json dashboard.dashboard.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$DASHBOARD_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set walrus.secret.db.password="$PG_PASSWORD" \
        --set walrus.secret.minio.rootUser="$MINIO_USERNAME" \
        --set walrus.secret.minio.rootPassword="$MINIO_PASSWORD" \
        --set walrus.walrus.environment.DATABASE_SERVICE_HOST="cuemby-platform-core-db.cuemby-system.svc.cluster.local" \
        --set walrus.walrus.ingress.hosts.core="$WALRUS_DOMAIN" \
        --set walrus.walrus.ingress.className="nginx" \
        --set walrus.walrus.ingress.secretName="walrus-market-cuemby-net-tls" \
        --set-json walrus.walrus.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$WALRUS_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set apiGateway.apiGateway.environment.BACKEND_HOST="http://cuemby-platform-core-kong:8000" \
        --set-string apiGateway.apiGateway.ingress.hosts.core="$GATEWAY_DOMAIN" \
        --set-string apiGateway.apiGateway.ingress.className="nginx" \
        --set-string apiGateway.apiGateway.ingress.secretName="api-gateway-market-cuemby-net-tls" \
        --set-json apiGateway.apiGateway.ingress.annotations='{
            "cert-manager.io/issuer":"origin-ca-issuer",
            "cert-manager.io/issuer-kind":"ClusterOriginIssuer",
            "cert-manager.io/issuer-group":"cert-manager.k8s.cloudflare.com",
            "external-dns.alpha.kubernetes.io/hostname":"'$GATEWAY_DOMAIN'",
            "nginx.ingress.kubernetes.io/backend-protocol":"HTTP",
            "nginx.ingress.kubernetes.io/force-ssl-redirect":"true",
            "external-dns.alpha.kubernetes.io/cloudflare-proxied":"true"
            "external-dns.alpha.kubernetes.io/target": "'$PUBLIC_IP'"
        }' \
        --set apiGateway.apiGateway.image.repository="netsaj/cp-apigw" \
        --set apiGateway.apiGateway.image.tag="v0.0.1-dev.8" \
        --wait --timeout=900s
}

# ===========================
# Notity By Email
# ===========================
notify_email() {
  local to="$NOTIFY_EMAIL" subject="$1" body="$2"
  # 1) Resend API (recomendado)
  if [[ -n "${RESEND_API_KEY:-}" && -n "${RESEND_FROM:-}" ]]; then
    # Necesita 'jq' (instálalo si no lo tienes: apt-get install -y jq)
    if ! command -v jq >/dev/null 2>&1; then
      echo "[WARNING] 'jq' no está instalado; no puedo usar la API de Resend."
    else
      curl -sS https://api.resend.com/emails \
        -H "Authorization: Bearer ${RESEND_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$(jq -n \
              --arg from "$RESEND_FROM" \
              --arg to   "$to" \
              --arg subject "$subject" \
              --arg text "$body" \
              '{from:$from,to:[$to],subject:$subject,text:$text}')" \
        >/dev/null || echo "[WARNING] Falló el envío por Resend."
      return
    fi
  fi

  # 2) mailx (si está disponible y configurado)
  if command -v mailx >/dev/null 2>&1; then
    printf "%s\n" "$body" | mailx -s "$subject" "$to" || \
      echo "[WARNING] Falló el envío con mailx."
    return
  fi

  # 3) sendmail (si existe)
  if command -v sendmail >/dev/null 2>&1; then
    /usr/sbin/sendmail -t <<EOF
From: ${RESEND_FROM:-noreply@local}
To: ${to}
Subject: ${subject}

${body}
EOF
    return
  fi

  echo "[WARNING] No hay método disponible para enviar correo (Resend/mailx/sendmail)."
}

build_install_summary() {
  cat <<EOF
Instalación completada ✔

Ingresses:
$(microk8s kubectl get ing -A 2>/dev/null || echo "sin ingresses")

¡Listo!
EOF
}

# ========================
# MAIN
# ========================
main() {
    print_status "Validating platform arguments.."
    parse_cuemby_platform_args "$@"
    prompt_missing_cuemby_platform_args
    install_microk8s
    configure_kubeconfig_public_ip
    install_helm
    install_istio
    install_knative
    install_prometheus
    install_openebs
    install_nginx_ingress
    print_success "Cluster and dependencies installed successfully."
    print_success "kubeconfig file generate successfully"
    print_status "Installing Cuemby Platform..."
    install_cuemby_platform
    print_success "CP installed successfully."
    notify_email "✅ Instalación completada en $(hostname)" \
        "$(build_install_summary)"
}

main "$@"