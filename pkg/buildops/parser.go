package buildops

import (
	"bufio"
	"fmt"
	"golang.org/x/exp/maps"
	"os"
	"sbom.observer/cli/pkg/licenses"
	"sort"
	"strings"
)

func ParseFile(filename string) ([]string, []string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}

	var opens []string
	var executions []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "open") {
			opens = append(opens, line)
		}

		if strings.HasPrefix(line, "exec") {
			executions = append(executions, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return opens, executions, nil
}

// DependencyObservations filters the build observations to only include dependency related opens and execs
// this means external includes (i.e. #include <stdio.h> -> /usr/include/* etc) and compilers calls (/usr/bin/cc etc)
func DependencyObservations(opens []string, executions []string) ([]string, []string) {
	includes := map[string]struct{}{}
	calls := map[string]struct{}{}

	for _, open := range opens {
		if isExternalInclude(open) {
			includes[open] = struct{}{}
		}
	}

	for _, exec := range executions {
		if isCompilerCall(exec) {
			calls[exec] = struct{}{}
		}
	}

	resultOpens := maps.Keys(includes)
	resultExecutions := maps.Keys(calls)

	// sort opens and executions
	sort.Strings(resultOpens)
	sort.Strings(resultExecutions)

	return resultOpens, resultExecutions
}

func isExternalInclude(open string) bool {
	// TODO: should probable include everything in /usr/include and /usr/local/include as well
	return strings.Contains(open, "/usr") && strings.HasSuffix(open, ".h")
}

func isCompilerCall(exec string) bool {
	return strings.HasSuffix(exec, "/cc") ||
		strings.HasSuffix(exec, "/cc1") ||
		strings.HasSuffix(exec, "/gcc") ||
		strings.HasSuffix(exec, "/clang") ||
		strings.HasSuffix(exec, "/c++") ||
		strings.HasSuffix(exec, "/g++") ||
		strings.HasSuffix(exec, "/ld") ||
		strings.HasSuffix(exec, "/as") ||
		strings.HasSuffix(exec, "/go")
}

// TODO: replace this with pkg/os/Package
type Package struct {
	Id              string
	Arch            string
	Name            string
	Version         string
	Dependencies    []string
	Files           []string
	IsSourcePackage bool
	Licenses        []licenses.License
}

type BuildDependencies struct {
	Code       []Package
	Tools      []Package
	Transitive []Package
	// NOTE: Code and Tools might contain the same package
}

func ResolveDependencies(opens []string, executions []string) (*BuildDependencies, error) {
	// figure out if running in a supported environment (dpkg based, rpm based )
	var packageManager = "unknown"

	if _, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		packageManager = "dpkg"
	}

	for _, db := range []string{
		"var/lib/rpm/Packages",
		"var/lib/rpm/Packages.db",
		"var/lib/rpm/rpmdb.sqlite",
		"usr/lib/sysimage/rpm/Packages",
		"usr/lib/sysimage/rpm/Packages.db",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
	} {
		if _, err := os.Stat(db); err == nil {
			packageManager = "rpm"
		}
	}

	switch packageManager {
	case "dpkg":
		return resolveDpkgDependencies(opens, executions)
	default:
		return nil, fmt.Errorf("unsupported build environment '%s' - cannot resolve dependencies", packageManager)
	}
}
