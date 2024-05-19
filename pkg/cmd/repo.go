package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/log"
	"time"
)

// repoCmd represents the repo command
var repoCmd = &cobra.Command{
	Use:   "repo",
	Short: "Create an SBOM from a source repository (or monorepo) (TODO)",
	Long:  `Create an SBOM from a local source repository (or monorepo) (TODO)`,
	Run:   RunRepoCommand,
	Args:  cobra.MinimumNArgs(1),
}

func init() {
	rootCmd.AddCommand(repoCmd)

	// toggles
	repoCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")
	repoCmd.Flags().String("scanner", "trivy", "SBOM scanner to use [trivy,syft] (default: trivy)")

	repoCmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories (short for --depth=1)")
	repoCmd.Flags().Uint("depth", 1, "Recursively scan subdirectories down to max tree depth (e.g. monorepos)")

	// output
	repoCmd.Flags().StringP("output", "o", "", "Output file for the results (default: stdout)")
}

func RunRepoCommand(cmd *cobra.Command, args []string) {
	//flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug
	flagDepth, _ := cmd.Flags().GetUint("depth")

	scannerEngine, _ := cmd.Flags().GetString("scanner")
	flagOutput, _ := cmd.Flags().GetString("output")

	if len(args) != 1 {
		log.Fatal("the path to a source repository is required as an argument")
	}

	targets, err := findScanTargets(args[0], flagDepth)
	if err != nil {
		log.Fatal("failed to find scan targets", "err", err)
	}

	// pre-scan work
	if len(targets) > 0 {
		// update Trivy Java DB
		err = TrivyUpdateJavaDb()
		if err != nil {
			log.Debug("failed to update Trivy Java DB ", "err", err)
		}
	}

	// results
	var results []string

	// scan targets
	for _, target := range targets {
		log.Debug("scanning target", "target", target)

		log.Printf("Generating SBOM for '%s'", target.path)

		// TODO: check that output matches arguments
		// create output filename
		output := flagOutput
		if output == "" {
			directoryName := filepath.Base(target.path)
			output = filepath.Join(os.TempDir(), fmt.Sprintf("sbom-%s-%s.cdx.json", directoryName, time.Now().Format("20060102-150405")))
			log.Debug("scan", "directoryName", directoryName, "filename", output, "engine", scannerEngine)
		}

		for _, scanner := range scannersForTarget(target) {
			err = scanner.Scan(target, output)
			if err != nil {
				log.Fatal("failed to create SBOM for repository", "path", target.path, "err", err)
			}
		}

		results = append(results, output)
	}

	// post-process output
	// TODO: add metadata

	// upload
	//if flagUpload {
	//	filesToUpload := []string{output}
	//
	//	c := client.NewObserverClient()
	//
	//	progress := log.NewProgressBar(int64(len(filesToUpload)), "Uploading BOMs", flagSilent)
	//
	//	for _, file := range filesToUpload {
	//		err = c.UploadFile(file)
	//		if err != nil {
	//			log.Error("error uploading", "file", file, "err", err)
	//			os.Exit(1)
	//		}
	//
	//		_ = progress.Add(1)
	//	}
	//
	//	_ = progress.Finish()
	//	_ = progress.Clear()
	//
	//	log.Printf("Uploaded %d BOM(s)", len(filesToUpload))
	//}

	//if !flagUpload {
	//	if flagOutput == "" {
	//		f, err := os.Open(output)
	//		if err != nil {
	//			log.Fatal("error opening file", "file", output, "err", err)
	//		}
	//
	//		defer f.Close()
	//
	//		_, _ = io.Copy(os.Stdout, f)
	//	} else {
	//		log.Printf("Wrote SBOM to %s", output)
	//	}
}
