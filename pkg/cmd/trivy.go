package cmd

import (
	"errors"
	"fmt"
	"os"
	"sbom.observer/cli/pkg/execx"
	"sbom.observer/cli/pkg/log"
	"strings"
)

func TrivyUpdateJavaDb() error {
	log.Debug("updating Trivy java database")

	_, extErr := Trivy("image", "--download-java-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy java vulnerability database: %w", extErr)
	}

	return nil
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
