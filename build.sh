#!/bin/bash

set -euo pipefail
CHARTS_DIR="charts"
REPO_URL="${REPO_URL:-}"

echo "🚀 Preparing Helm..."

# Clean helm cache to avoid repository conflicts
echo "🧹 Cleaning helm cache..."
rm -rf ~/.cache/helm/repository/helm-manager-* || true

# Delete previous packages
echo "🧹 Deleting old .tgz files..."
mkdir -p "$CHARTS_DIR"
rm -f "$CHARTS_DIR"/*.tgz

# Function to package charts that contain Chart.yaml
package_chart() {
  local chart_dir="$1"
  if [ -f "$chart_dir/Chart.yaml" ]; then
    echo "📦 Packaging: $chart_dir"
    helm dependency update "$chart_dir" || echo "ℹ️ There are no dependencies to update in $chart_dir"
    helm package "$chart_dir" -d "$CHARTS_DIR"
  fi
}

# Packaging individual charts (core)
for dir in cuemby-platform-core/* ; do
  package_chart "$dir"
done

# Packaging the main metachart
if [ -f cuemby-platform/Chart.yaml ]; then
  package_chart cuemby-platform
fi

# Generate or update the index.yaml file
if [ -n "$REPO_URL" ]; then
  echo "🧭 Generate index.yaml with URL: $REPO_URL"
  helm repo index "$CHARTS_DIR" --url "$REPO_URL"
else
  echo "🧭 Generate index.yaml locally (sin URL remota)"
  helm repo index "$CHARTS_DIR"
fi

echo "✅ All charts were packaged and ready for publication."
