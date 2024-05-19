package cmd

import (
	"errors"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/exp/maps"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"
	"sbom.observer/cli/pkg/execx"
	"sbom.observer/cli/pkg/log"
	"slices"
	"strings"
)

type Ecosystem string

const EcosystemGo Ecosystem = "go"
const EcosystemNpm Ecosystem = "npm"
const EcosystemNuget Ecosystem = "nuget"
const EcosystemPython Ecosystem = "python"
const EcosystemJava Ecosystem = "java"
const EcosystemBuildObserver Ecosystem = "build-observer"
const EcosystemObserver Ecosystem = "observer"

// TODO: expand

const EcosystemUnknown Ecosystem = "unknown"

type BomMetadata cyclonedx.Metadata

type ScanConfig struct {
	Supplier struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
	}
	Component struct {
		Name    string `yaml:"name"`
		Group   string `yaml:"group"`
		Version string `yaml:"version"`
	}
}

type scanTarget struct {
	path     string
	files    map[string]Ecosystem
	metadata BomMetadata
	config   ScanConfig
}

func findScanTargets(initialTarget string, maxDepth uint) (map[string]scanTarget, error) {
	// resolve "." to the current working directory so we get sane naming
	if initialTarget == "." {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		initialTarget = cwd
	}

	initialTarget = filepath.Clean(initialTarget)
	initialDepth := strings.Count(initialTarget, string(os.PathSeparator))

	targets := map[string]scanTarget{}

	err := filepath.WalkDir(initialTarget, func(currentPath string, file fs.DirEntry, err error) error {
		depth := strings.Count(currentPath, string(os.PathSeparator)) - initialDepth

		if depth > int(maxDepth) {
			return filepath.SkipDir
		}

		// TODO: skip common dirs
		// TODO: slice set
		if file.Name() == "node_modules" {
			return filepath.SkipDir
		}

		// skip "hidden" dirs
		if file.IsDir() && file.Name() != "." && strings.HasPrefix(file.Name(), ".") {
			return filepath.SkipDir
		}

		// don't care about directories (yet)
		if file.IsDir() {
			return nil
		}

		relativePath := strings.TrimPrefix(currentPath, initialTarget)

		directoryPath := filepath.Dir(currentPath)

		// check if it's a "file-of-interest"
		ecosystem := IdentifyEcosystem(relativePath, file.Name())
		if ecosystem != EcosystemUnknown {
			target, found := targets[directoryPath]
			if !found {
				target = scanTarget{
					path:  directoryPath,
					files: map[string]Ecosystem{},
				}
				targets[directoryPath] = target
			}
			target.files[file.Name()] = ecosystem
		}

		return nil
	})

	return targets, err
}

func IdentifyEcosystem(path string, fileName string) Ecosystem {
	switch fileName {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc", "yarn.lock", "pnpm-lock.yaml":
		return EcosystemNpm
	case "go.mod", "go.sum":
		return EcosystemGo
	case "packages.lock.json", "project.assets.json", "packages.config":
		return EcosystemNuget
	case "build.gradle", "build.gradle.kts", "gradle.lockfile", "buildscript-gradle.lockfile", "settings.gradle", "settings.gradle.kts":
		return EcosystemJava
	case "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock":
		return EcosystemPython
	case "pom.xml":
		return EcosystemJava
	case "observer.yml", "observer.yaml":
		return EcosystemObserver
	case "build-observations.out", "build-observations.out.txt":
		return EcosystemBuildObserver
	}

	// nuget
	ext := filepath.Ext(fileName)
	if ext == ".csproj" || ext == ".vbproj" || ext == "*.fsproj" {
		return EcosystemNuget
	}

	return EcosystemUnknown
}

type RepoScanner interface {
	Id() string
	Priority() int
	Scan(scanTarget, string) error
}

func scannersForTarget(target scanTarget) []RepoScanner {
	scanners := map[string]RepoScanner{}
	for _, ecosystem := range target.files {
		scanner := scannerForEcosystem(ecosystem)
		if scanner == nil {
			log.Debug("skipping unsupported ecosystem", "ecosystem", ecosystem)
			continue
		}
		if _, ok := scanners[scanner.Id()]; !ok {
			scanners[scanner.Id()] = scanner
		}
	}

	log.Debug("scannersForTarget", "target", target, "scanners", maps.Keys(scanners))

	effectiveScanners := maps.Values(scanners)

	slices.SortFunc(effectiveScanners, func(a, b RepoScanner) int {
		return a.Priority() - b.Priority()
	})

	return effectiveScanners
}

func scannerForEcosystem(ecosystem Ecosystem) RepoScanner {
	switch ecosystem {
	case EcosystemObserver:
		return &configRepoScanner{}
	case EcosystemBuildObserver:
		return &buildopsScanner{}
	default:
		//return &trivyRepoScanner{}
		return nil
	}
}

type configRepoScanner struct{}

func (s *configRepoScanner) Id() string {
	return "config"
}

func (s *configRepoScanner) Priority() int {
	return 100
}

func (s *configRepoScanner) Scan(target scanTarget, _ string) error {
	for filename, ecosystem := range target.files {
		if filename == "observer.yml" || filename == "observer.yaml" {
			log.Debug("found observer config file", "filename", filename, "ecosystem", ecosystem)
			bs, err := os.ReadFile(filepath.Join(target.path, filename))
			if err != nil {
				return err
			}

			err = yaml.Unmarshal(bs, &target.config)
			if err != nil {
				return err
			}

			log.Debug("loaded config", "config", target.config)
		}
	}

	return nil
}

type trivyRepoScanner struct {
}

func (s *trivyRepoScanner) Id() string {
	return "trivy"
}

func (s *trivyRepoScanner) Priority() int {
	return 1000
}

func (s *trivyRepoScanner) Scan(target scanTarget, output string) error {
	output, err := Trivy("fs", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", output, target.path)
	if err != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(err, &extCmdErr) {
			log.Error("failed to create SBOM for repository with 'trivy' generator", "path", target.path, "exitcode", extCmdErr.ExitCode)
			_, _ = fmt.Fprint(os.Stderr, "-- Trivy output --\n")
			_, _ = fmt.Fprint(os.Stderr, extCmdErr.StdErr)
			_, _ = fmt.Fprint(os.Stderr, "\n------------------\n")
			return err
		}

		log.Error("failed to create sbom for repository using Trivy", "err", err)
		return err
	}

	return nil
}
