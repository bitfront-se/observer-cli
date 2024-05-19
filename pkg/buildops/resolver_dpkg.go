package buildops

import (
	"cmp"
	"fmt"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs/dpkg"
	"slices"
	"strings"
)

// TODO: move package

func resolveDpkgDependencies(opens []string, executions []string) (*BuildDependencies, error) {
	indexer := dpkg.NewIndexer()
	err := indexer.Create()
	if err != nil {
		return nil, err
	}

	code := map[string]*Package{}
	tools := map[string]*Package{}

	// parse filename form lines and deduplicate (more than one compiler might open the same file)
	includeFiles := map[string]struct{}{}
	for i, row := range opens {
		// open    make    /lib/x86_64-linux-gnu/libc.so.6
		fields := strings.Fields(row)
		if len(fields) != 3 {
			return nil, fmt.Errorf("parse error: %d %s", i, row)
		}

		fileName := fields[2]

		if fileName == "" {
			return nil, fmt.Errorf("parse error: %d %s", i)
		}

		includeFiles[fileName] = struct{}{}
	}

	log.Infof("resolving packages for %d observed files", len(includeFiles))

	for fileName := range includeFiles {
		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Debug: fileName,
			Id:    osPkg.Name + "@" + osPkg.Version,
			Name:  osPkg.Name,
			Arch:  osPkg.Architecture,
		}

		// TODO: bug? what about multiple versions of the same package installed?
		code[pkg.Id] = &pkg

		if osPkg.SourceName != "" && (osPkg.Name != osPkg.SourceName || osPkg.Version != osPkg.SourceVersion) {
			sourcePackage := Package{
				Debug:           fmt.Sprintf("<%s %s>", pkg.Name, pkg.Version),
				Id:              fmt.Sprintf("%s@%s", osPkg.SourceName, osPkg.SourceVersion),
				Name:            osPkg.SourceName,
				Version:         osPkg.SourceVersion,
				IsSourcePackage: true,
			}

			pkg.Dependencies = append(pkg.Dependencies, sourcePackage.Id)

			if _, found := code[sourcePackage.Id]; !found {
				code[sourcePackage.Id] = &sourcePackage
			}
		}
	}

	for i, row := range executions {
		// TODO: move this parsing up
		fields := strings.Fields(row)
		if len(fields) != 2 {
			return nil, fmt.Errorf("parse error: %d %s", i, row)
		}

		fileName := fields[1]

		if fileName == "" {
			return nil, fmt.Errorf("parse error: %d %s", i, row)
		}

		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Debug: fileName,
			Id:    osPkg.Name + "@" + osPkg.Version,
			Name:  osPkg.Name,
			Arch:  osPkg.Architecture,
			Files: []string{fileName},
		}

		tools[pkg.Id] = &pkg
	}

	// gather results
	result := &BuildDependencies{}

	for _, pkg := range code {
		result.Code = append(result.Code, *pkg)
	}

	for _, pkg := range tools {
		result.Tools = append(result.Tools, *pkg)
	}

	slices.SortFunc(result.Code, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	slices.SortFunc(result.Tools, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	return result, nil
}
