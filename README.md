**observer-cli** is a command-line-tool that allows you to create Software Bill of Materials (SBOMs) and interact with [SBOM Observer](https://sbom.observer) from the command line (and CI/CD pipelines etc).

> [!IMPORTANT]
> This is a preview software and is subject to change.

```
Usage:
observer-cli [command]

Available Commands:
completion  Generate the autocompletion script for the specified shell
help        Help about any command
image       Create an SBOM for a container image (TODO)
k8s         Create an environment snapshot, and optionally SBOMs, of a k8s cluster.
repo        Create an SBOM from a source repository (or monorepo) (TODO)
upload      Upload one or more attestations (SBOMs) to https://sbom.observer (TODO)

Flags:
    --debug     Enable debug logging (implies silent mode)
-h, --help      help for observer-cli
    --silent    Silent mode (no progress bars)
-v, --version   version for observer-cli

Use "observer-cli [command] --help" for more information about a command.
```

## Authentication

The CLI expects an `OBSERVER_TOKEN` environment variable to be set with a valid API token.


## SBOM generation

The tool is primarily a *meta* scanner, meaning that in most cases it delegates the actual generation to other tools like [Syft](https://github.com/anchore/syft) or [Trivy](https://github.com/aquasecurity/trivy).

Supporting multiple scanners allows us to create multiple SBOMs from a monorepo, and select the most accurate one depending on the ecosystem.

The tool is designed to be extensible, so we may add support for other scanners as well.


## Preview: Kubernetes BOM generation

This is an experimental feature and may be radically changed or removed in future releases.

The `k8s` command allows you to create an BOM (snapshot) of all the running resources, both control-plane and workloads, in a k8s cluster. It can optionally create SBOMs for all identified running images.

Uploading these BOMs to [SBOM Observer](https://sbom.observer) allows you to identify vulnerabilities both in workloads and control-plane components (including advisories published to the [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/).

For creating the snapshot it uses [kubectl](https://kubernetes.io/docs/reference/kubectl/overview/).

Example: `observer-cli k8s --sbom --upload` will create a snapshot of the k8s cluster, and upload the SBOMs to [SBOM Observer](https://sbom.observer).

