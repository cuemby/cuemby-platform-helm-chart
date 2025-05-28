#!/bin/bash

set -euo pipefail

CHART_NAME="cuemby-platform"
CHART_VERSION="1.0.0"

echo "==> Updating dependencies..."
helm dependency update .

echo "==> Packaging chart..."
mkdir -p build
helm package . -d build
helm repo index ./

echo "✅ Chart packaged: build/${CHART_NAME}-${CHART_VERSION}.tgz"
