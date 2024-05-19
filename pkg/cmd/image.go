package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"io"
	"os"
	"path"
	"sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/log"
	"time"
)

// imageCmd represents the image command
var imageCmd = &cobra.Command{
	Use:   "image <image>",
	Short: "Create an SBOM for a container image",
	Long:  `Create an SBOM for a container image`,
	Run:   ImageCommand,
}

func init() {
	rootCmd.AddCommand(imageCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// k8sCmd.PersistentFlags().String("foo", "", "A help for foo")

	// toggles
	imageCmd.Flags().BoolP("upload", "u", false, "Upload the results to https://sbom.observer")
	imageCmd.Flags().String("scanner", "trivy", "SBOM scanner to use [trivy,syft] (default: trivy)")

	// output
	imageCmd.Flags().StringP("output", "o", "", "Output file for the results (default: stdout)")
}

func ImageCommand(cmd *cobra.Command, args []string) {
	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug

	scannerEngine, _ := cmd.Flags().GetString("scanner")
	flagOutput, _ := cmd.Flags().GetString("output")

	if len(args) != 1 {
		log.Fatal("an container image reference is required as an argument")
	}

	// TODO: validate output (parse, sanity check)

	// create output filename
	output := path.Join(os.TempDir(), fmt.Sprintf("sbom-%s.cdx.json", time.Now().Format("20060102-150405")))
	if flagOutput != "" {
		output = flagOutput
	}

	// update Trivy Java DB
	err := TrivyUpdateJavaDb()
	if err != nil {
		log.Debug("failed to update Trivy Java DB ", "err", err)
	}

	log.Printf("Creating SBOM for '%s'", args[0])

	err = CreateImageSbom(scannerEngine, args[0], output)
	if err != nil {
		os.Exit(1)
	}

	// upload
	if flagUpload {
		filesToUpload := []string{output}

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

	if !flagUpload && flagOutput == "" {
		f, err := os.Open(output)
		if err != nil {
			log.Fatal("error opening file", "file", output, "err", err)
		}

		defer f.Close()

		_, _ = io.Copy(os.Stdout, f)
	}
}
