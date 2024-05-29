package dpkg

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sbom.observer/cli/pkg/licenses"
	"strings"
)

var (
	commonLicenseFile      = regexp.MustCompile(`/?usr/share/common-licenses/(?P<licensefile>[0-9A-Za-z_.-]+[0-9A-Za-z+])`)
	commonLicenseFileGroup = commonLicenseFile.SubexpIndex("licensefile")
)

func (i *Indexer) LicensesForPackage(name string) ([]licenses.License, error) {
	pkg, ok := i.packages[name]
	if !ok {
		return nil, nil
	}

	filename := filepath.Join("/usr/share/doc", pkg.Name, "copyright")
	return i.parseCopyrightFile(filename)
}

/*
Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: zlib
Upstream-Contact: zlib@gzip.org
Source: http://zlib.net/
Comment: This is the pre-packaged Debian Linux version of the zlib compression

	library.  It was packaged by Michael Alan Dorman <mdorman@debian.org>
	from sources originally retrieved from ftp.uu.net in the directory
	/pub/archiving/zip/zlib as the file zlib-1.0.4.tar.gz.
	.
	The deflate format used by zlib was defined by Phil Katz. The deflate
	and zlib specifications were written by Peter Deutsch. Thanks to all the
	people who reported problems and suggested various improvements in zlib;
	they are too numerous to cite here.

Files-Excluded:

	contrib/ada
	contrib/amd64
	contrib/asm686
	contrib/blast
	contrib/delphi
	contrib/dotzlib
	contrib/gcc_gvmat64
	contrib/infback9
	contrib/inflate86
	contrib/iostream
	contrib/iostream2
	contrib/iostream3
	contrib/masmx64
	contrib/masmx86
	contrib/pascal
	contrib/puff
	contrib/testzlib
	contrib/untgz
	contrib/vstudio
	doc/rfc1950.txt
	doc/rfc1951.txt
	doc/rfc1952.txt
	win32

Files: *
Copyright: 1995-2013 Jean-loup Gailly and Mark Adler
License: Zlib

Files: amiga/Makefile.pup
Copyright: 1998 by Andreas R. Kleinert
License: Zlib

Files: contrib/minizip/*
Copyright: 1998-2010 Gilles Vollant

	2007-2008 Even Rouault
	2009-2010 Mathias Svensson

License: Zlib

Files: debian/*
Copyright: 2000-2017 Mark Brown
License: Zlib

License: Zlib

	This software is provided 'as-is', without any express or implied
	warranty.  In no event will the authors be held liable for any damages
	arising from the use of this software.
	.
	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:
	.
	1. The origin of this software must not be misrepresented; you must not
	   claim that you wrote the original software. If you use this software
	   in a product, an acknowledgment in the product documentation would be
	   appreciated but is not required.
	2. Altered source versions must be plainly marked as such, and must not be
	   misrepresented as being the original software.
	3. This notice may not be removed or altered from any source distribution.
	.
	Jean-loup Gailly        Mark Adler
	jloup@gzip.org          madler@alumni.caltech.edu
	.
	If you use the zlib library in a product, we would appreciate *not* receiving
	lengthy legal documents to sign.  The sources are provided for free but without
	warranty of any kind.  The library has been entirely written by Jean-loup
	Gailly and Mark Adler; it does not include third-party code.
	.
	If you redistribute modified sources, we would appreciate that you include in
	the file ChangeLog history information documenting your changes.  Please read
	the FAQ for more information on the distribution of modified source versions.
*/
func (i *Indexer) parseCopyrightFile(filename string) ([]licenses.License, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	var result []licenses.License

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.Contains(line, "/usr/share/common-licenses"):
			matches := commonLicenseFile.FindStringSubmatch(line)
			if len(matches) > 0 {
				ref := matches[0]

				lss, err := i.detector.DetectFile(ref)
				if err != nil {
					return nil, err
				}

				result = append(result, lss...)
			}
		}
	}

	// NOTE: Running the license detector on the raw */copyright file is very naive but works surprisingly well
	//       but provides a lot of "false" positives for files not used by applications (e.g. gcc-12)
	lss, err := i.detector.DetectFile(filename)
	if err != nil {
		return nil, err
	}

	result = append(result, lss...)

	// de-duplicate found licenses
	var deduped []licenses.License
	for _, l := range result {
		found := false
		for _, r := range deduped {
			if l.Id == r.Id && l.Expression == r.Expression {
				found = true
				break
			}
		}
		if !found {
			deduped = append(deduped, l)
		}
	}

	return deduped, err
}
