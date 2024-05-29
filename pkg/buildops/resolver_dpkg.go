package buildops

import (
	"cmp"
	"fmt"
	"golang.org/x/exp/maps"
	"path/filepath"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs/dpkg"
	"slices"
	"strings"
)

// TODO: move package

func resolveDpkgDependencies(opens []string, executions []string) (*BuildDependencies, error) {
	log := log.Logger.WithPrefix("buildops")

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
			return nil, fmt.Errorf("parse error: %d missing filename in line '%s'", i, row)
		}

		includeFiles[fileName] = struct{}{}
	}

	log.Debugf("resolving package attributions for %d observed files", len(includeFiles))

	// TODO: split this loop
	for fileName := range includeFiles {
		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Id:           osPkg.Name + "@" + osPkg.Version,
			Name:         osPkg.Name,
			Version:      osPkg.Version,
			Arch:         osPkg.Architecture,
			Dependencies: osPkg.Dependencies,
		}

		licensesForPackage, err := indexer.LicensesForPackage(osPkg.Name)
		if err != nil {
			log.Error("failed to get licenses for package", "pkg", osPkg.Name, "err", err)
		}

		pkg.Licenses = licensesForPackage

		if len(pkg.Licenses) == 0 {
			log.Warn("no licenses found for package", "pkg", osPkg.Name)
		}

		// TODO: bug? what about multiple versions of the same package installed?
		code[pkg.Id] = &pkg

		if osPkg.SourceName != "" && (osPkg.Name != osPkg.SourceName || osPkg.Version != osPkg.SourceVersion) {
			sourcePackage := Package{
				Id:              fmt.Sprintf("%s@%s", osPkg.SourceName, osPkg.SourceVersion),
				Name:            osPkg.SourceName,
				Version:         osPkg.SourceVersion,
				IsSourcePackage: true,
			}

			pkg.Dependencies = append(pkg.Dependencies, sourcePackage.Name)

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

		// resolve symlinks (/usr/bin/cc ->/etc/alternatives/cc -> /usr/bin/gcc -> /usr/bin/gcc-12 -> /usr/bin/x86_64-linux-gnu-gcc-12)
		fileName, err = filepath.EvalSymlinks(fileName)
		if err != nil {
			log.Warnf("failed to resolve symlinks for %s: %v", fileName, err)
		}

		osPkg, found := indexer.PackageForFile(fileName)
		if !found {
			return nil, fmt.Errorf("failed to resolve package for file %s: not found", fileName)
		}

		// TODO: remove this package type
		pkg := Package{
			Id:           osPkg.Name + "@" + osPkg.Version,
			Name:         osPkg.Name,
			Version:      osPkg.Version,
			Arch:         osPkg.Architecture,
			Dependencies: osPkg.Dependencies,
			Files:        []string{fileName},
		}

		licensesForPackage, err := indexer.LicensesForPackage(osPkg.Name)
		if err != nil {
			log.Error("failed to get licenses for package", "pkg", osPkg.Name, "err", err)
		}

		pkg.Licenses = licensesForPackage

		if len(pkg.Licenses) == 0 {
			log.Warn("no licenses found for package", "pkg", osPkg.Name)
		}

		tools[pkg.Id] = &pkg
	}

	// transitive dependencies
	var transitive []Package
	for _, pkg := range append(maps.Values(code), maps.Values(tools)...) {
		transitive = resolveDependencies(pkg.Dependencies, transitive, indexer)
	}

	// gather results
	result := &BuildDependencies{}

	for _, pkg := range code {
		result.Code = append(result.Code, *pkg)
	}

	for _, pkg := range tools {
		result.Tools = append(result.Tools, *pkg)
	}

	result.Transitive = transitive

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

	slices.SortFunc(result.Transitive, func(a Package, b Package) int {
		if a.Name == b.Name {
			return cmp.Compare(a.Version, b.Version)
		}
		return cmp.Compare(a.Name, b.Name)
	})

	return result, nil
}

func resolveDependencies(names []string, collection []Package, indexer *dpkg.Indexer) []Package {
	for _, dep := range names {
		depPkg := indexer.InstalledPackage(dep)
		if depPkg == nil {
			continue
		}

		if slices.ContainsFunc(collection, func(pkg Package) bool { return pkg.Name == depPkg.Name && pkg.Version == depPkg.Version }) {
			continue
		}

		osDependencyPackage := Package{
			Id:           fmt.Sprintf("%s@%s", depPkg.Name, depPkg.Version),
			Arch:         depPkg.Architecture,
			Name:         depPkg.Name,
			Version:      depPkg.Version,
			Dependencies: depPkg.Dependencies,
		}

		collection = append(collection, osDependencyPackage)
		collection = resolveDependencies(osDependencyPackage.Dependencies, collection, indexer)
	}

	return collection
}
