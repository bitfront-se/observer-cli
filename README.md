**observer** is a command-line-tool that allows you to create Software Bill of Materials (SBOMs) and interact with [SBOM Observer](https://sbom.observer) from the command line (and CI/CD pipelines etc).

> [!IMPORTANT]
> This is a preview software and is subject to change.

```
Usage:
observer [command]

Available Commands:
completion  Generate the autocompletion script for the specified shell
help        Help about any command
repo        Create an SBOM from a source repository (or monorepo)
image       Create an SBOM for a container image
k8s         Create an environment snapshot, and optionally SBOMs, of a k8s cluster.
upload      Upload one or more attestations (SBOMs) to https://sbom.observer

Flags:
    --debug     Enable debug logging (implies silent mode)
-h, --help      help for observer-cli
    --silent    Silent mode (no progress bars)
-v, --version   version for observer-cli

Use "observer [command] --help" for more information about a command.
```

## SBOM generation

This tool is primarily a *meta* scanner, meaning that in most cases it delegates the actual generation to other tools like [Syft](https://github.com/anchore/syft) or [Trivy](https://github.com/aquasecurity/trivy).
Supporting multiple scanners allows us to select the most accurate one depending on the specific ecosystem. The tool is designed to be extensible, so we may add support for other scanners as well.

For monorepos, the `repo` command will scan each component in the repository and create a separate SBOM for each component (subdirectory).
When there is multiple components in the same folder (e.g. go.mod + package-lock.json), the scanner will merge the SBOMs into a single file.

## SBOM Metadata files

You can configure the SBOM metadata fields (root component, supplier, manufacture, etc) by adding a `observer.yaml` file in the root of the repository (or the root of each component in a monorepo).

Example:
```yaml
component:
    type: application
    name: my-application
    group: my-group
    version: 1.0.0
    description: Description of component
    license: MIT
supplier:
    name: Supplier Name
    url: https://example.com
    contacts:
        - name: John Doe
          email: john.doe@example.com
          phone: "123"
```

## Authentication with SBOM Observer

To upload SBOMs to [SBOM Observer](https://sbom.observer) the CLI expects an `OBSERVER_TOKEN` environment variable to be set with a valid API token.


## Preview: Support for C/C++ projects

Using a combination of [build-observer](https://github.com/sbom-observer/build-observer) and the `repo` command, you can create SBOMs for C/C++ projects.

`build-observer` will watch (using eBPF or ptrace) the build process and create a log (`build-observations.out`) of all files that are read, written or executed during the build.
This log will be parsed by the observer `repo` command to create an SBOM using dependency information from OS package manager.

This also works for projects that include multiple languages, like a Go projects that uses CGO to include C code, or a _npm_ project that uses `node-gyp` to include C++ code.
For mixed-language projects, the `repo` command will create multiple SBOMs during scanning and then merge them into a single SBOM.

Example
```bash
~/src/nginx-1.26.0 $ sudo build-observer -u cicd -- /usr/bin/make
...
~/src/nginx-1.26.0 $ observer --debug repo -o ./sboms .
...
INFO buildops: parsing build observations file build-observations.out
...
INFO wrote CycloneDX BOM to ./sboms/nginx-1.26.0.bom.xml
~/src/nginx-1.26.0 $
```

Example of a mixed project:
```bash
~/src/webapp $ sudo build-observer -u cicd -- /usr/bin/npm install --build-from-source
...
~/src/webapp $ observer --debug repo -o ./sboms .
...
INFO buildops: parsing build observations file build-observations.out
...
INFO wrote CycloneDX BOM to ./sboms/webapp-0.0.0.bom.xml
~/src/webapp $
```

> [!IMPORTANT]
> Currently the scanner can only resolve observed dependencies when they are installed on the build machine using the package manager of the OS.
> **Initially only Debian-based systems are supported**, but we plan to add support for RPM based systems as well.

> [!IMPORTANT]
> See the [build-observer](https://github.com/sbom-observer/build-observer) repository for detailed requirements and instructions.

## Preview: Kubernetes BOM generation

This is an experimental feature and may be radically changed or removed in future releases.

The `k8s` command allows you to create an BOM (snapshot) of all the running resources, both control-plane and workloads, in a k8s cluster. It can optionally create SBOMs for all identified running images.

Uploading these BOMs to [SBOM Observer](https://sbom.observer) allows you to identify vulnerabilities both in workloads and control-plane components (including advisories published to the [Kubernetes Official CVE Feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/).

For creating the snapshot it uses [kubectl](https://kubernetes.io/docs/reference/kubectl/overview/).

Example: `observer-cli k8s --sbom --upload` will create a snapshot of the k8s cluster, and upload the SBOMs to [SBOM Observer](https://sbom.observer).

