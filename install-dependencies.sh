#!/bin/bash

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE_ISTIO="istio-system"
NAMESPACE_KNATIVE_OPERATOR="knative-operator"
NAMESPACE_KNATIVE_SERVING="knative-serving"
NAMESPACE_MONITORING="cuemby-system"
TIMEOUT="600s"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
check_command() {
    if ! command -v $1 &> /dev/null; then
        print_error "$1 is not installed. Please install it first."
        exit 1
    fi
}

# Function to wait for deployment to be ready
wait_for_deployment() {
    local namespace=$1
    local deployment=$2
    print_status "Waiting for deployment $deployment to be ready in namespace $namespace..."
    kubectl wait --for=condition=available --timeout=$TIMEOUT deployment/$deployment -n $namespace
}

# Function to create a namespace if it doesn't exist
create_namespace() {
    local ns=$1
    if ! kubectl get ns "$ns" &> /dev/null; then
        print_status "Creating namespace $ns..."
        kubectl create ns "$ns"
    else
        print_status "Namespace $ns already exists, skipping creation."
    fi
}

install_istio() {
    print_status "Installing Istio with Helm..."
    create_namespace $NAMESPACE_ISTIO

    if ! helm repo list | grep -q "istio"; then
        helm repo add istio https://istio-release.storage.googleapis.com/charts
    else
        print_status "Istio repo already exists, skipping add."
    fi
    helm repo update

    if [ ! -d "./dependencies/istio" ]; then
        print_warning "./dependencies/istio directory not found. Installing with default config."
        helm upgrade --install istiod istio/istiod \
            -n $NAMESPACE_ISTIO \
            --wait --timeout=$TIMEOUT

        helm upgrade --install istio-ingressgateway istio/gateway \
            -n $NAMESPACE_ISTIO \
            --wait --timeout=$TIMEOUT
    else
        helm upgrade --install istiod istio/istiod \
            -n $NAMESPACE_ISTIO \
            -f ./dependencies/istio/istio.yaml \
            --wait --timeout=$TIMEOUT

        helm upgrade --install istio-ingressgateway istio/gateway \
            -n $NAMESPACE_ISTIO \
            -f ./dependencies/istio/istio-gateway.yaml \
            --wait --timeout=$TIMEOUT
    fi

    wait_for_deployment $NAMESPACE_ISTIO "istiod"

    print_success "Istio successfully installed with Helm."
}

install_knative() {
    print_status "Installing Knative Operator..."
    create_namespace $NAMESPACE_KNATIVE_OPERATOR
    create_namespace $NAMESPACE_KNATIVE_SERVING

    print_status "Installing Knative Operator using kubectl..."
    kubectl apply -f https://github.com/knative/operator/releases/download/knative-v1.15.0/operator.yaml

    print_status "Waiting for the operator to be ready..."
    kubectl wait --for=condition=available --timeout=$TIMEOUT deployment/knative-operator -n $NAMESPACE_KNATIVE_OPERATOR

    print_status "Installing KnativeServing..."
    cat <<EOF | kubectl apply -f -
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
    local max_attempts=10
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        print_status "Attempt $attempt/$max_attempts - Checking KnativeServing status..."

        if kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING &> /dev/null; then
            local ready_status=$(kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
            print_status "KnativeServing status: $ready_status"

            if [ "$ready_status" = "True" ]; then
                print_success "KnativeServing is ready!"
                break
            elif [ "$ready_status" = "False" ]; then
                print_warning "KnativeServing is not ready. Checking details..."
                kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING -o yaml | grep -A 10 "conditions:"
            fi
        else
            print_warning "KnativeServing not found, waiting..."
        fi

        print_status "Pods status in $NAMESPACE_KNATIVE_SERVING:"
        kubectl get pods -n $NAMESPACE_KNATIVE_SERVING 2>/dev/null || echo "No pods yet"

        if [ $attempt -eq $max_attempts ]; then
            print_warning "Timeout reached, continuing. Please verify manually with:"
            echo "kubectl get knativeserving knative-serving -n $NAMESPACE_KNATIVE_SERVING"
            echo "kubectl get pods -n $NAMESPACE_KNATIVE_SERVING"
            break
        fi

        sleep 30
        ((attempt++))
    done

    print_success "Knative Operator and Serving successfully installed."
}

install_prometheus() {
    print_status "Installing Prometheus Stack with Helm..."
    create_namespace $NAMESPACE_MONITORING

    check_command helm

    if ! helm repo list | grep -q "prometheus-community"; then
        helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    else
        print_status "prometheus-community repo already exists, skipping add."
    fi
    helm repo update

    if [ ! -f "./dependencies/prometheus.yaml" ]; then
        print_warning "./dependencies/prometheus.yaml file not found. Installing with default config."
        helm upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
            -n $NAMESPACE_MONITORING \
            --create-namespace \
            --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false \
            --set prometheus.prometheusSpec.podMonitorSelectorNilUsesHelmValues=false \
            --set prometheus.prometheusSpec.ruleSelectorNilUsesHelmValues=false \
            --set grafana.enabled=false \
            --wait --timeout=$TIMEOUT
    else
        helm upgrade --install prometheus-stack prometheus-community/kube-prometheus-stack \
            -n $NAMESPACE_MONITORING \
            --create-namespace \
            -f ./dependencies/prometheus.yaml \
            --wait --timeout=$TIMEOUT
    fi

    print_success "Prometheus Stack successfully installed"
}

main() {
    check_command kubectl
    check_command helm

    install_istio
    install_knative
    install_prometheus

    print_success "All dependencies successfully installed."
}

main "$@"
