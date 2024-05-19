package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"io"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/buildops"
	"sbom.observer/cli/pkg/ids"
	"sbom.observer/cli/pkg/log"
	"time"
)

// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
const JsonSchemaDateTimeFormat = "2006-01-02T15:04:05+00:00"

type buildopsScanner struct{}

func (s *buildopsScanner) Id() string {
	return "buildops"
}

func (s *buildopsScanner) Priority() int {
	return 100
}

func (s *buildopsScanner) Scan(target scanTarget, output string) error {
	log := log.Logger.WithPrefix("buildops")

	for filename, ecosystem := range target.files {
		if filename == "build-observations.out" || filename == "build-observations.out.txt" {
			log.Debug("found build observations file config file", "filename", filename, "ecosystem", ecosystem)

			log.Infof("parsing build observations file %s", filename)
			opens, executions, err := buildops.ParseFile(filepath.Join(target.path, filename))
			if err != nil {
				return fmt.Errorf("failed to parse build observations file: %w", err)
			}

			// TODO: figure out which distro we are running in

			log.Debugf("filtering dependencies from %d observed build operations", len(opens)+len(executions))
			depOpens, depExecutions := buildops.DependencyObservations(opens, executions)

			dependencies, err := buildops.ResolveDependencies(depOpens, depExecutions)
			if err != nil {
				return fmt.Errorf("failed to parse build observations file: %w", err)
			}

			log.Infof("resolved %d unique dependencies", len(dependencies.Code))

			err = s.generateCycloneDX(dependencies, target.config, output)
			if err != nil {
				return fmt.Errorf("failed to generate CycloneDX BOM: %w", err)
			}
		}
	}

	return nil
}

func (s *buildopsScanner) generateCycloneDX(deps *buildops.BuildDependencies, config ScanConfig, output string) error {
	createdAt := time.Now()

	bom := cdx.NewBOM()

	bom.Version = 1
	bom.SerialNumber = fmt.Sprintf("urn:uuid:%s", ids.NextUUID())

	bom.Metadata = &cdx.Metadata{
		Timestamp: createdAt.Format(JsonSchemaDateTimeFormat),
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "sbom.observer (cli)",
					Version: "1.0", // TODO: should be git version
					ExternalReferences: &[]cdx.ExternalReference{
						{
							Type: cdx.ERTypeWebsite,
							URL:  "https://github.com/sbom-observer/observer-cli",
							//Comment: "",
						},
					},
				},
				{
					Type:    cdx.ComponentTypeApplication,
					Name:    "build-observer",
					Version: "0.1", // TODO: should fetch from build-observer file
					ExternalReferences: &[]cdx.ExternalReference{
						{
							Type: cdx.ERTypeWebsite,
							URL:  "https://github.com/sbom-observer/build-observer",
							//Comment: "",
						},
					},
				},
			},
		},
		// https://cyclonedx.org/docs/1.5/json/#metadata_lifecycles
		Lifecycles: &[]cdx.Lifecycle{
			{
				Phase: cdx.LifecyclePhaseBuild,
			},
		},
	}

	// metadata component
	bom.Metadata.Component = &cdx.Component{
		BOMRef:  ids.NextUUID(),
		Type:    cdx.ComponentTypeApplication,
		Name:    config.Component.Name,
		Group:   config.Component.Group,
		Version: config.Component.Version,
	}

	if config.Supplier.Name != "" {
		bom.Metadata.Supplier = &cdx.OrganizationalEntity{
			Name: config.Supplier.Name,
			URL:  &[]string{config.Supplier.URL},
		}
	}

	// TODO: metadata component license
	// TODO: metadata authors

	// components
	var components []cdx.Component
	var rootDependencies []string
	dependencies := map[string][]string{}

	index := map[string]int{}

	for _, dep := range deps.Code {
		// TODO: add distro
		purl := fmt.Sprintf("pkg:deb/debian/%s@%s?arch=%s", dep.Name, dep.Version, dep.Arch)

		if dep.IsSourcePackage {
			purl = fmt.Sprintf("pkg:generic/%s@%s", dep.Name, dep.Version)
		}

		component := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: purl,
		}

		components = append(components, component)
		index[dep.Id] = len(components) - 1

		if !dep.IsSourcePackage {
			rootDependencies = append(rootDependencies, component.BOMRef)
		}
	}

	// source packages
	for _, dep := range deps.Code {
		component := components[index[dep.Id]]
		if len(dep.Dependencies) > 0 {
			for _, sourceDep := range dep.Dependencies {
				i, found := index[sourceDep]
				if !found {
					log.Error("build observation source package dependency not found", "sourceDep", sourceDep)
					continue
				}
				sourceComponent := components[i]
				dependencies[component.BOMRef] = append(dependencies[component.BOMRef], sourceComponent.BOMRef)
			}
		}
	}

	for _, dep := range deps.Tools {
		// TODO: add distro
		purl := fmt.Sprintf("pkg:deb/debian/%s@%s?arch=%s", dep.Name, dep.Version, dep.Arch)

		component := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeApplication,
			Name:       dep.Name,
			Version:    dep.Version,
			PackageURL: purl,
			// TODO: revisit
			//Properties: &[]cdx.Property{
			//	{
			//		Name:  "observer:build:role",
			//		Value: "tool",
			//	},
			//},
		}

		var subComponents []cdx.Component
		for _, file := range dep.Files {
			fileHash, err := HashFileSha256(file)
			if err != nil {
				log.Error("failed to hash file", "file", file, "error", err)
				continue
			}
			subComponents = append(subComponents, cdx.Component{
				Type: cdx.ComponentTypeFile,
				Name: file,
				Hashes: &[]cdx.Hash{
					{
						Algorithm: "SHA-256",
						Value:     fileHash,
					},
				},
			})
		}

		if len(subComponents) > 0 {
			component.Components = &subComponents
		}

		components = append(components, component)
		index[dep.Id] = len(components) - 1

		if !dep.IsSourcePackage {
			rootDependencies = append(rootDependencies, component.BOMRef)
		}
	}

	dependencies[bom.Metadata.Component.BOMRef] = rootDependencies

	ds := []cdx.Dependency{}
	for bomRef, refs := range dependencies {
		rc := refs
		ds = append(ds, cdx.Dependency{
			Ref:          bomRef,
			Dependencies: &rc,
		})
	}

	bom.Components = &components
	bom.Dependencies = &ds
	
	// marshal bom as json and write to file output
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	log.Logger.WithPrefix("buildops").Debug("writing CycloneDX BOM to file", "output", output)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(bom)
	if err != nil {
		return err
	}

	return nil
}

// HashFileSha256 calculates the SHA-256 hash of a file
func HashFileSha256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
