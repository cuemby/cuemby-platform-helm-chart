#!/bin/bash

set -euo pipefail
CHARTS_DIR="charts"

echo "🚀 Preparing Helm..."

# Delete previous packages
echo "🧹 Deleting old .tgz files..."
mkdir -p "$CHARTS_DIR"
rm -f "$CHARTS_DIR"/*.tgz

# Funtion to package charts that contain Chart.yaml
package_chart() {
  local chart_dir="$1"
  if [ -f "$chart_dir/Chart.yaml" ]; then
    echo "📦 Packaging: $chart_dir"
    helm dependency update "$chart_dir" || echo "ℹ️ There are no dependencies to update in $chart_dir"
    helm package "$chart_dir" -d "$CHARTS_DIR"
  fi
}

# Packaging individual charts (core and registry)
for dir in cuemby-platform-core/* cuemby-platform-registry/*; do
  package_chart "$dir"
done

# Packaging the main metachart
if [ -f cuemby-platform/Chart.yaml ]; then
  package_chart cuemby-platform
fi

# Generate or update the index.yaml file
echo "🧭 Updating index.yaml..."
helm repo index "$CHARTS_DIR"

echo "✅ All charts were packaged and ready for publication."
