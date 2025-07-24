# cuemby-platform

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

A Helm chart that installs cuemby-platform and its dependencies.

## Basic Installation

The platform installation is done in two steps:

### 1. Add repo to helm

```bash
> helm repo add cuemby https://cuemby.github.io/cuemby-platform-helm-chart/
> helm repo update
```

Then you will see the repo in your list.

```bash
> helm repo list

NAME                	URL
cuemby              	https://cuemby.github.io/cuemby-platform-helm-chart/
```

### 2. Install dependencies with the script

This step installs Istio, Knative, and Prometheus with their custom configurations.
```bash
> ./install-dependencies.sh
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

### 3. Install the platform with Helm

Once the dependencies are installed, you can install the platform:

```sh
> helm install cuemby-platform cuemby/cuemby-platform --version <chart_version> --values values.yaml
> helm install cuemby-platform cuemby/cuemby-platform --version 2.0.1 --values values.yaml
```
