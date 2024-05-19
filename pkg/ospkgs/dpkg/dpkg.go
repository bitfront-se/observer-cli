package dpkg

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"sbom.observer/cli/pkg/log"
	"sbom.observer/cli/pkg/ospkgs"
	"sort"
	"strings"
	"time"
)

// dkpg package contains code to parse dpkg various /var/lib/dpkg/* file types and provide
// BOM information about the packages installed on the system.

const (
	infoPath = "/var/lib/dpkg/info/"
)

var (
	statusPaths               = []string{"/var/lib/dpkg/status", "/var/lib/dpkg/status.d"}
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`(?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

type Indexer struct {
	files    map[string]string
	packages map[string]*ospkgs.Package
}

func NewIndexer() *Indexer {
	return &Indexer{
		files:    make(map[string]string),
		packages: make(map[string]*ospkgs.Package),
	}
}

func (i *Indexer) PackageNameForFile(filename string) (string, bool) {
	pkg, ok := i.files[filename]
	return pkg, ok
}

func (i *Indexer) PackageForFile(filename string) (*ospkgs.Package, bool) {
	name, ok := i.files[filename]
	if !ok {
		return nil, false
	}

	pkg, ok := i.packages[name]

	if !ok {
		// name can contain an architecture 'linux-libc-dev:amd64'
		// we only need the package name and architecture
		parts := strings.Split(name, ":")

		pkg, ok = i.packages[parts[0]]
	}

	return pkg, ok
}

//func (i *Indexer) InstalledPackages(pkg *ospkgs.Package) []string {
//	var installedFiles []string
//	for fileName, pkgName := range i.files {
//		if pkgName == pkg.Name {
//			installedFiles = append(installedFiles, fileName)
//		}
//	}
//	sort.Strings(installedFiles)
//	return installedFiles
//}

func (i *Indexer) Create() error {
	log.Debug("creating dpkg file index")
	start := time.Now()

	// index files in /var/lib/dpkg/info
	err := filepath.WalkDir(infoPath, func(currentPath string, file fs.DirEntry, err error) error {
		if currentPath == infoPath {
			return nil
		}

		// skip directories and "hidden" files
		if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
			return filepath.SkipDir
		}

		if filepath.Ext(file.Name()) == ".list" {
			err = i.parseListFile(currentPath)
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to index %s: %w", infoPath, err)
	}

	// input format is like:
	// /.
	// /usr
	// /usr/lib
	// /usr/lib/gcc
	// /usr/lib/gcc/x86_64-linux-gnu
	// /usr/lib/gcc/x86_64-linux-gnu/12
	// /usr/lib/gcc/x86_64-linux-gnu/12/crtbegin.o
	// /usr/lib/xxxx
	// /usr/lib/xxxx/some-other-file
	// index now contains nonsense data for all directories (many packages declare directories as files)

	// remove directories from index
	for file := range i.files {
		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		if stat.IsDir() {
			delete(i.files, file)
		}
	}

	//lines := []string{}
	//for file, pkg := range i.files {
	//	lines = append(lines, fmt.Sprintf("%s: %s", file, pkg))
	//}
	//sort.Strings(lines)
	//
	//for _, line := range lines {
	//	if strings.Contains(line, "libc6-dev") {
	//		log.Debug(line)
	//	}
	//}

	took := time.Now().Sub(start) / time.Millisecond
	log.Debugf("indexed %d files in %dms", len(i.files), took)

	// index /var/lib/dpkg/status, /var/lib/dpkg/status/* and /var/lib/dpkg/status.d/*
	log.Debugf("creating dpkg package index")
	start = time.Now()
	for _, statusPath := range statusPaths {
		err := filepath.WalkDir(statusPath, func(currentPath string, file fs.DirEntry, err error) error {
			if file == nil {
				return filepath.SkipDir
			}

			if file.IsDir() && currentPath == statusPath {
				return nil
			}

			// skip directories and "hidden" files
			if file.IsDir() || strings.HasPrefix(file.Name(), ".") {
				return filepath.SkipDir
			}

			// TODO: update for status.d/*
			if file.Name() == "status" {
				err = i.parseStatusFile(currentPath)
				if err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to index %s: %w", statusPath, err)
		}
	}

	took = time.Now().Sub(start) / time.Millisecond
	log.Debugf("indexed %d packages in %dms", len(i.packages), took)

	//for _, pkg := range i.packages {
	//	log.Debugf("Package: %s %s %s -> %s %s -> %s", pkg.Name, pkg.Version, pkg.Architecture, pkg.SourceName, pkg.SourceVersion, pkg.Maintainer)
	//}

	return nil
}

func (i *Indexer) parseListFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	rows := make([]string, 0, 100)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rows = append(rows, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("bufio.Scan error: %w", err)
	}

	packageName := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))

	sort.Strings(rows)
	for x := 1; x < len(rows); x++ {
		i.files[rows[x]] = packageName
	}

	return nil
}

func (i *Indexer) parseStatusFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	buff := bytes.NewBuffer(make([]byte, 0, 128*1024))

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		buff.Write(line)
		buff.Write([]byte("\n"))
		if len(line) == 0 || len(bytes.TrimSpace(line)) == 0 {
			pkg, err := i.parseStatusPackage(buff)
			if err != nil {
				return err
			}

			i.packages[pkg.Name] = pkg

			buff.Reset()
			continue
		}
	}

	// parse last package
	if buff.Len() > 0 {
		pkg, err := i.parseStatusPackage(buff)
		if err != nil {
			return err
		}

		i.packages[pkg.Name] = pkg
	}

	return nil
}

func (i *Indexer) parseStatusPackage(buff *bytes.Buffer) (*ospkgs.Package, error) {
	// input is MIME header formatted ex:
	/*
		Package: adduser
		Status: install ok installed
		Priority: important
		Section: admin
		Installed-Size: 686
		Maintainer: Debian Adduser Developers <adduser@packages.debian.org>
		Architecture: all
		Multi-Arch: foreign
		Version: 3.134
		Depends: passwd
		Suggests: liblocale-gettext-perl, perl, cron, quota
		Conffiles:
		 /etc/adduser.conf cc3493ecd2d09837ffdcc3e25fdfff18
		 /etc/deluser.conf 11a06baf8245fd8d690b99024d228c1f
		Description: add and remove users and groups
		 This package includes the 'adduser' and 'deluser' commands for creating
		 and removing users.
		 xxxxxxx
		 easier and more stable to write and maintain.
	*/
	reader := textproto.NewReader(bufio.NewReader(buff))
	values, err := reader.ReadMIMEHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read MIME header: %w", err)
	}

	pkg := ospkgs.Package{
		Name:         values.Get("Package"),
		Version:      values.Get("Version"),
		Architecture: values.Get("Architecture"),
		Maintainer:   values.Get("Maintainer"),
	}

	// Source line (Optional). Package name and optionally version
	if src := values.Get("Source"); src != "" {
		// TODO: rewrite to use CG names instead
		srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(src, -1)[0]
		md := make(map[string]string)
		for i, n := range srcCapture {
			md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
		}
		pkg.SourceName = md["name"]
		pkg.SourceVersion = md["version"]

		// if not version is provided in the source line, the bin package is based on the upstream version
		// see https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/pkg-format.c#n338
		if pkg.SourceVersion == "" {
			pkg.SourceVersion = pkg.Version
		}

		// any revision and epoch should be stripped (7.88.1-10+deb12u5 -> 7.88.1)
		// see https://git.dpkg.org/cgit/dpkg/dpkg.git/tree/lib/dpkg/version.h#n38
		pkg.SourceVersion = strings.Split(pkg.SourceVersion, "-")[0]
	}

	return &pkg, nil
}
