package k8s

import (
	"errors"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"os"
	"path"
	"sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/execx"
	"sbom.observer/cli/pkg/log"
	"strings"
	"time"
)

func NewProgressBar(total int64, description string, silent bool) *progressbar.ProgressBar {
	// disable when debugging
	if silent {
		return progressbar.DefaultSilent(total, description)
	}

	//return progressbar.Default(total, description)

	return progressbar.NewOptions(int(total),
		progressbar.OptionSetWriter(os.Stderr), //you should install "github.com/k0kubun/go-ansi"
		progressbar.OptionSetDescription(description),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionSetWidth(25),
		//progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
}

func KubernetesCommand(cmd *cobra.Command, args []string) {
	flagSbom, _ := cmd.Flags().GetBool("sbom")
	flagUpload, _ := cmd.Flags().GetBool("upload")
	flagDebug, _ := cmd.Flags().GetBool("debug")
	flagSilent, _ := cmd.Flags().GetBool("silent")
	flagSilent = flagSilent || flagDebug

	scannerEngine, _ := cmd.Flags().GetString("scanner")

	log.Print("Creating k8s snapshot using 'kubectl'")

	// kubectl get svc,nodes,pods,namespaces --all-namespaces -o json
	kubectlArgs := []string{"get", "svc,nodes,pods,namespaces", "-o", "json"}

	if value, _ := cmd.Flags().GetString("namespace"); value != "" {
		kubectlArgs = append(kubectlArgs, "-n", value)
	} else {
		kubectlArgs = append(kubectlArgs, "--all-namespaces")
	}

	if value, _ := cmd.Flags().GetString("kubeconfig"); value != "" {
		kubectlArgs = append(args, "--kubeconfig", value)
	}

	output, extErr := Kubectl(kubectlArgs...)
	if extErr != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(extErr, &extCmdErr) {
			log.Error("failed to create snapshot for cluster with 'kubectl'", "err", extErr)
			log.Debug("error details", "message", extCmdErr.Message, "exitcode", extCmdErr.ExitCode, "stderr", extCmdErr.StdErr)
			os.Exit(1)
		}

		log.Error("failed to get k8s snapshot with 'kubectl'", "err", extErr)
		os.Exit(1)
	}

	// TODO: validate output (parse, sanity check)

	// create output filename
	outputDirectory, err := cmd.Flags().GetString("output")

	if outputDirectory == "" {
		tempDir, err := os.MkdirTemp("", "observer-cli")
		if err != nil {
			log.Error("failed to create temporary directory", "err", err)
			os.Exit(1)
		}

		outputDirectory = tempDir

		//defer func() {
		//	err := os.RemoveAll(tempDir)
		//	if err != nil {
		//		log.Error("failed to remove temporary directory", "err", err)
		//		os.Exit(1)
		//	}
		//	log.Debug("removed temporary directory", "dir", tempDir)
		//}()
	}

	snapshotFile := path.Join(outputDirectory, fmt.Sprintf("k8s-snapshot-%s.json", time.Now().Format("20060102-1504")))

	// write output to file
	err = os.WriteFile(snapshotFile, []byte(output), 0644)
	if err != nil {
		log.Error("Error writing k8s snapshot to file", "filename", snapshotFile, "err", err)
		os.Exit(1)
	}

	log.Debug(fmt.Sprintf("wrote k8s snapshot to file %s", snapshotFile))

	// upload candidates
	var filesToUpload []string
	filesToUpload = append(filesToUpload, snapshotFile)

	// create sboms
	if flagSbom {
		// parse snapshot
		snapshot, err := ParseKubetclSnapshot([]byte(output))
		if err != nil {
			log.Error("error parsing k8s snapshot", "err", err)
			os.Exit(1)
		}

		// extract images
		images := map[string]Image{}
		for _, resource := range snapshot.Resources {
			for _, image := range resource.Images {
				images[image.Name] = image
			}
		}

		log.Printf("Creating SBOMs for %d images found in snapshot", len(images))

		// create sboms
		sboms, err := createImageSboms(scannerEngine, images, outputDirectory, flagSilent)
		if err != nil {
			log.Error("error creating image sboms", "err", err)
			os.Exit(1)
		}

		filesToUpload = append(filesToUpload, sboms...)

		log.Printf("Created %d BOM(s)", len(sboms))
	}

	// upload
	if flagUpload {
		c := client.NewObserverClient()

		progress := NewProgressBar(int64(len(filesToUpload)), "Uploading BOMs", flagSilent)

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

	if !flagUpload {
		log.Printf("Wrote %d BOM(s) to %s", len(filesToUpload), outputDirectory)
	}
}

func createImageSboms(engine string, images map[string]Image, tempDir string, flagSilent bool) ([]string, error) {
	var sboms []string

	// update Trivy Java DB
	err := TrivyUpdateJavaDb()
	if err != nil {
		return nil, err
	}

	// create sboms
	progress := NewProgressBar(int64(len(images)), "Scanning images", flagSilent)

NextImage:
	for _, image := range images {
		output := path.Join(tempDir, fmt.Sprintf("%s.sbom.cdx.json", sanitizeFilename(image.Name)))

		// TODO: caching (~/Librache/Caches/[app] or ~/.caches/[app]

		// TODO: this probably needs to be more robust
		pullable := image.RepositoryURL
		if image.Digest != "" {
			pullable = fmt.Sprintf("%s@%s", image.RepositoryURL, image.Digest)
		} else if image.Tag != "" {
			pullable = fmt.Sprintf("%s:%s", image.RepositoryURL, image.Tag)
		}

		err := CreateImageSbom(engine, pullable, output)
		if err != nil {
			// user is already notified, so we just skip this image
			_ = progress.Add(1)
			continue NextImage
		}

		sboms = append(sboms, output)
		_ = progress.Add(1)
	}

	_ = progress.Finish()
	_ = progress.Clear()

	return sboms, nil
}

func Kubectl(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("kubectl 'trivy %s'", strings.Join(args, " ")))

	output, err := execx.Exec("kubectl", args...)
	if err != nil {
		if errors.Is(err, execx.ErrNotFound) {
			log.Error("kubectl not found in $PATH")
			log.Print("Download and install kubectl from https://kubernetes.io/docs/tasks/tools/")
			// TODO: add curl download instructions
			os.Exit(1)
		}
	}

	return output, err
}

func Trivy(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("running 'trivy %s'", strings.Join(args, " ")))

	output, err := execx.Exec("trivy", args...)
	if err != nil {
		if errors.Is(err, execx.ErrNotFound) {
			log.Error("Trivy not found in $PATH")
			log.Print("Download and install Trivy from https://github.com/aquasecurity/trivy/releases")
			// TODO: add curl download instructions (use Github releases API?)
			os.Exit(1)
		}
	}

	return output, err
}

func TrivyUpdateDb() error {
	log.Debug("updating Trivy vulnerability database")

	_, extErr := Trivy("image", "--download-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy vulnerability database: %w", extErr)
	}

	return nil
}

func TrivyUpdateJavaDb() error {
	log.Debug("updating Trivy java database")

	_, extErr := Trivy("image", "--download-java-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy java vulnerability database: %w", extErr)
	}

	return nil
}

func Syft(args ...string) (string, error) {
	log.Debug(fmt.Sprintf("running 'syft %s'", strings.Join(args, " ")))

	output, err := execx.Exec("syft", args...)
	if err != nil {
		if errors.Is(err, execx.ErrNotFound) {
			log.Error("Syft not found in $PATH")
			log.Print("Download and install Syft from https://github.com/anchore/syft")
			// TODO: add curl download instructions (use Github releases API?)
			os.Exit(1)
		}
	}

	return output, err
}

func CreateImageSbom(engine string, image string, output string) error {
	switch engine {
	case "trivy":
		return CreateImageSbomTrivy(image, output)
	case "syft":
		return CreateImageSbomSyft(image, output)
	}
	return nil
}

func CreateImageSbomTrivy(image string, output string) error {
	output, err := Trivy("image", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", output, image)
	if err != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(err, &extCmdErr) {
			log.Error("failed to create SBOM for image with 'trivy' generator", "image", image, "exitcode", extCmdErr.ExitCode)
			_, _ = fmt.Fprint(os.Stderr, "-- Trivy output --\n")
			_, _ = fmt.Fprint(os.Stderr, extCmdErr.StdErr)
			_, _ = fmt.Fprint(os.Stderr, "\n------------------\n")
			return err
		}

		log.Error("failed to create sbom for image using Trivy", "err", err)
		return err
	}

	return nil
}

func CreateImageSbomSyft(image string, output string) error {
	//syft -o cyclonedx-json=/tmp/syft.cdx.json  postgres:latest
	output, err := Syft("-o", "cyclonedx-json="+output, image)
	if err != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(err, &extCmdErr) {
			log.Error("failed to create SBOM for image with 'syft' generator", "image", image, "exitcode", extCmdErr.ExitCode)
			_, _ = fmt.Fprint(os.Stderr, "-- Trivy output --\n")
			_, _ = fmt.Fprint(os.Stderr, extCmdErr.StdErr)
			_, _ = fmt.Fprint(os.Stderr, "\n------------------\n")
			return err
		}

		log.Error("failed to create sbom for image using Syft", "err", err)
		return err
	}

	return nil
}

func sanitizeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, "/", ".")
	filename = strings.ReplaceAll(filename, "@", "_")
	return filename
}
