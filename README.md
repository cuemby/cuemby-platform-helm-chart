# cuemby-platform

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

A Helm chart that installs cuemby-platform and its dependencies.

## Basic Installation

The platform installation is done in two steps:

### 1. Install dependencies with the script

This step installs Istio, Knative, and Prometheus with their custom configurations.
```bash
./install-dependencies.sh
```

The script:
  - Creates the required namespaces.
  - Installs Istio (control plane and gateway) using Helm.
  - Installs the Knative Operator using Helm.
  - Installs Prometheus Stack using Helm and a custom configuration.

**Important:**
In the Knative configuration included in dependencies/knative.yaml, a default domain is specified (app-shlab.cuemby.io).
Each user must customize this before running the script by modifying the following fields:

```yaml
commonName: "*.app-shlab.cuemby.io"
dnsNames:
  - "*.app-shlab.cuemby.io"
...
domain:
  app-shlab.cuemby.io: ""
```

Replace it with the domain that corresponds to your environment.

### 2. Install the platform with Helm

Once the dependencies are installed, you can install the platform:

```sh
helm install cuemby-platform -f values.yaml . -n cuemby-system --create-namespace
```
