package buildops

import (
	"bufio"
	"errors"
	"golang.org/x/exp/maps"
	"os"
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
	return strings.Contains(open, "/usr") && strings.HasSuffix(open, ".h")
}

func isCompilerCall(exec string) bool {
	return strings.HasSuffix(exec, "/cc") ||
		strings.HasSuffix(exec, "/gcc") ||
		strings.HasSuffix(exec, "/clang") ||
		strings.HasSuffix(exec, "/c++") ||
		strings.HasSuffix(exec, "/g++") ||
		strings.HasSuffix(exec, "/ld") ||
		strings.HasSuffix(exec, "/as")

}

// TODO: remove this type
type Package struct {
	Id              string
	Debug           string
	Arch            string
	Name            string
	Version         string
	Dependencies    []string
	IsSourcePackage bool
	Files           []string
}

type BuildDependencies struct {
	Code  []Package
	Tools []Package
}

func ResolveDependencies(opens []string, executions []string) (*BuildDependencies, error) {
	//TODO: figure out if its a supported environment
	packageManager := "dpkg"
	switch packageManager {
	case "dpkg":
		return resolveDpkgDependencies(opens, executions)
	default:
		return nil, errors.New("unsupported build environment - cannot resolve dependencies")
	}
}
