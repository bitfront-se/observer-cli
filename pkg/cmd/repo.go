package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/ids"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/types"
	"text/template"
	"time"
)

// repoCmd represents the repo command
var repoCmd = &cobra.Command{
	Aliases: []string{"repository"},
	Use:     "repo",
	Short:   "Create an SBOM from a source repository",
	Long:    `Create an SBOM from a local source repository (or monorepo)`,
	Run:     RunRepoCommand,
	Args:    cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(repoCmd)

	// toggles
	repoCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")

	repoCmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories (short for --depth=1)")
	repoCmd.Flags().Uint("depth", 1, "Recursively scan subdirectories down to max tree depth (e.g. monorepos)")

	// output
	repoCmd.Flags().StringP("output", "o", "", "Output file for the results (default: stdout)")
}

func RunRepoCommand(cmd *cobra.Command, args []string) {
	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug
	flagDepth, _ := cmd.Flags().GetUint("depth")

	flagOutput, _ := cmd.Flags().GetString("output")

	if len(args) != 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	targets, err := findScanTargets(args[0], flagDepth)
	if err != nil {
		log.Fatal("failed to find scan targets", "err", err)
	}

	// pre-scan work
	//if len(targets) > 0 {
	//	// update Trivy Java DB
	//	err = TrivyUpdateJavaDb()
	//	if err != nil {
	//		log.Debug("failed to update Trivy Java DB ", "err", err)
	//	}
	//}

	// TODO: merge output flag

	// TODO: load config from args[0]

	// scan targets
	for _, target := range targets {
		log.Infof("Generating SBOM for '%s'", target.path)
		log.Debug("Generating SBOM", "path", target.path, "target", target.files)

		for _, scanner := range scannersForTarget(*target) {
			output := filepath.Join(os.TempDir(), fmt.Sprintf("sbom-%s-%s.cdx.json", ids.NextUUID(), time.Now().Format("20060102-150405")))
			log.Debug("running scanner", "id", scanner.Id(), "output", output)
			err = scanner.Scan(target, output)
			if err != nil {
				log.Fatal("failed to create SBOM for repository", "path", target.path, "err", err)
			}
		}

		// post-process output
		mergedFilenameTemplate := "sbom-{{.Name}}-{{.Module}}-{{.Timestamp}}.cdx.json"
		if target.config.OutputTemplate != "" {
			mergedFilenameTemplate = target.config.OutputTemplate
		}

		mergedOutput, err := generateFilename(mergedFilenameTemplate, "", target.config.Component)
		if err != nil {
			log.Fatal("failed to generate output filename", "err", err)
		}

		mergedOutputFullPath := filepath.Join(os.TempDir(), mergedOutput)
		err = mergeSBOMs(target.results, mergedOutputFullPath, target.config)
		if err != nil {
			log.Fatal("failed to merge SBOMs for target", "target", target.path, "err", err)
		}

		log.Debugf("merged %d BOMs for target %s -> %s", len(target.results), target.path, mergedOutputFullPath)
		target.results = []string{mergedOutputFullPath}

	}

	// output to stdout
	if flagOutput == "" {
		for _, target := range targets {
			for _, result := range target.results {
				f, err := os.Open(result)
				if err != nil {
					log.Fatal("error opening file", "file", result, "err", err)
				}
				_, _ = io.Copy(os.Stdout, f)
				_ = f.Close()
				//_ = os.Remove(result)
			}
		}
	}

	// upload
	if flagUpload {
		var filesToUpload []string

		for _, target := range targets {
			for _, result := range target.results {
				filesToUpload = append(filesToUpload, result)
			}
		}

		c := client.NewObserverClient()

		progress := log.NewProgressBar(int64(len(filesToUpload)), "Uploading BOMs", flagSilent)

		for _, file := range filesToUpload {
			err = c.UploadFile(file)
			if err != nil {
				log.Error("error uploading", "file", file, "err", err)
				os.Exit(1)
			}

			_ = progress.Add(1)
		}

		_ = progress.Finish()
		_ = progress.Clear()

		log.Printf("Uploaded %d BOM(s)", len(filesToUpload))
	}

	// move results to the final output
	if flagOutput != "" && isDirectory(flagOutput) {
		for _, target := range targets {
			for _, result := range target.results {
				destination := filepath.Join(flagOutput, filepath.Base(result))
				err = os.Rename(result, destination)
				if err != nil {
					log.Fatal("failed to move result to output destination", "err", err)
				}
				log.Infof("wrote CycloneDX BOM to %s", destination)
			}
		}
	}
}

func generateFilename(templateString string, module string, component ScanConfigComponent) (string, error) {
	t, err := template.New("filename").Parse(templateString)
	if err != nil {
		return "", fmt.Errorf("failed to parse filename template: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")

	var buf bytes.Buffer
	err = t.Execute(&buf, struct {
		Module    string
		Timestamp string
		Name      string
		Version   string
		Group     string
	}{
		Module:    module,
		Timestamp: timestamp,
		Name:      component.Name,
		Version:   component.Version,
		Group:     component.Group,
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute filename template: %w", err)
	}

	filename := buf.String()
	filename = regexp.MustCompile("-+").ReplaceAllString(filename, "-")

	return filename, nil
}

func isDirectory(filename string) bool {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		// If there's an error (e.g., file does not exist), return false
		return false
	}
	// Check if the FileMode is a directory
	return fileInfo.IsDir()
}

func mergeSBOMs(files []string, destination string, config ScanConfig) error {
	var boms []*cdx.BOM
	for _, filename := range files {
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		var bom cdx.BOM
		err = json.NewDecoder(f).Decode(&bom)
		f.Close()
		if err != nil {
			return err
		}
		boms = append(boms, &bom)
	}

	merged, err := mergeCycloneDX(boms)
	if err != nil {
		return err
	}

	// set metadata
	if config.Component.Type != "" {
		merged.Metadata.Component.Type = cdx.ComponentType(config.Component.Type)
	}
	if config.Component.Name != "" {
		merged.Metadata.Component.Name = config.Component.Name
	}
	if config.Component.Group != "" {
		merged.Metadata.Component.Group = config.Component.Group
	}
	if config.Component.Version != "" {
		merged.Metadata.Component.Version = config.Component.Version
	}
	if config.Component.Description != "" {
		merged.Metadata.Component.Description = config.Component.Description
	}
	if config.Component.License != "" {
		merged.Metadata.Component.Licenses = &cdx.Licenses{
			{
				License: &cdx.License{
					ID: config.Component.License,
				},
			},
		}
	}

	if config.Supplier.Name != "" {
		merged.Metadata.Supplier = &cdx.OrganizationalEntity{
			Name: config.Supplier.Name,
			URL:  &[]string{config.Supplier.URL},
		}
		if len(config.Supplier.Contacts) > 0 {
			merged.Metadata.Supplier.Contact = &[]cdx.OrganizationalContact{}
			for _, contact := range config.Supplier.Contacts {
				*merged.Metadata.Supplier.Contact = append(*merged.Metadata.Supplier.Contact, cdx.OrganizationalContact{
					Name:  contact.Name,
					Email: contact.Email,
					Phone: contact.Phone,
				})
			}
		}
	}

	if config.Manufacturer.Name != "" {
		merged.Metadata.Supplier = &cdx.OrganizationalEntity{
			Name: config.Manufacturer.Name,
			URL:  &[]string{config.Manufacturer.URL},
		}
		if len(config.Manufacturer.Contacts) > 0 {
			merged.Metadata.Supplier.Contact = &[]cdx.OrganizationalContact{}
			for _, contact := range config.Manufacturer.Contacts {
				*merged.Metadata.Supplier.Contact = append(*merged.Metadata.Supplier.Contact, cdx.OrganizationalContact{
					Name:  contact.Name,
					Email: contact.Email,
					Phone: contact.Phone,
				})
			}
		}
	}

	// TODO: metadata manufacture
	// TODO: metadata authors

	// add observer-cli tool if missing
	toolFound := false
	if merged.Metadata.Tools != nil && merged.Metadata.Tools.Components != nil {
		for _, tool := range *merged.Metadata.Tools.Components {
			if tool.Name == "observer" {
				toolFound = true
			}
		}
	}

	if !toolFound {
		if merged.Metadata.Tools == nil {
			merged.Metadata.Tools = &cdx.ToolsChoice{}
		}
		if merged.Metadata.Tools.Components == nil {
			merged.Metadata.Tools.Components = &[]cdx.Component{}
		}
		*merged.Metadata.Tools.Components = append(*merged.Metadata.Tools.Components, cdx.Component{
			Type:    cdx.ComponentTypeApplication,
			Name:    "sbom.observer (cli)",
			Version: types.Version,
			ExternalReferences: &[]cdx.ExternalReference{
				{
					Type: cdx.ERTypeWebsite,
					URL:  "https://github.com/sbom-observer/observer-cli",
				},
			},
		})
	}

	out, err := os.Create(destination)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(merged)
	out.Close()
	if err != nil {
		return err
	}

	log.Debugf("mergeSBOMs: wrote merged SBOM to %s", destination)

	return nil
}

func mergeCycloneDX(boms []*cdx.BOM) (*cdx.BOM, error) {
	// short-circuit if there's only one BOM
	if len(boms) == 1 {
		return boms[0], nil
	}

	merged := boms[0]

	// TODO: we might want to move the root component for each BOM and create a new uber root
	// move root component to components
	//if merged.Components == nil {
	//	merged.Components = &[]cdx.Component{}
	//}
	//*merged.Components = append(*merged.Components, *merged.Metadata.Component)

	// bomRef -> merged bomRef map
	components := map[string]string{}
	dependencies := map[string]*cdx.Dependency{}

	for _, component := range *merged.Components {
		components[component.BOMRef] = component.BOMRef
	}

	for _, dependency := range *merged.Dependencies {
		dependencies[dependency.Ref] = &dependency
	}

	for _, bom := range boms[1:] {
		components[bom.Metadata.Component.BOMRef] = merged.Metadata.Component.BOMRef
		for _, component := range *bom.Components {
			_, found := components[component.BOMRef]

			if !found {
				components[component.BOMRef] = component.BOMRef
				*merged.Components = append(*merged.Components, component)
			}
		}

		for _, dependency := range *bom.Dependencies {
			bomRef := components[dependency.Ref]
			if bomRef == "" {
				log.Error("failed to find component for dependency ref", "dependency", dependency.Ref)
				continue
			}

			mergedDependency, found := dependencies[bomRef]
			if !found {
				dependency.Ref = bomRef
				*merged.Dependencies = append(*merged.Dependencies, dependency)
			} else {
				mergedDependencies := types.SliceSet[string](*mergedDependency.Dependencies)
				*mergedDependency.Dependencies = mergedDependencies.AddAll(*dependency.Dependencies)
			}
		}

		// merge metadata tools
		if merged.Metadata.Tools == nil {
			merged.Metadata.Tools = &cdx.ToolsChoice{}
		}

		if merged.Metadata.Tools.Components == nil {
			merged.Metadata.Tools.Components = &[]cdx.Component{}
		}

		if bom.Metadata.Tools != nil && bom.Metadata.Tools.Components != nil {
			for _, tool := range *bom.Metadata.Tools.Components {
				found := false
				for _, existingTool := range *merged.Metadata.Tools.Components {
					if tool.Name == existingTool.Name && tool.Version == existingTool.Version {
						found = true
						break
					}
				}
				if !found {
					*merged.Metadata.Tools.Components = append(*merged.Metadata.Tools.Components, tool)
				}
			}
		}
	}

	return merged, nil
}
