package licenses

import (
	"github.com/google/licensecheck"
	"os"
	"path/filepath"
)

// NOTE: This is just the skeleton of the license detector code from Bytesafe. Expect more of the code to be migrated here in the future.

type Detector struct {
}

func NewLicenseDetector() *Detector {
	return &Detector{}
}

func (d *Detector) DetectFile(pathFileName string) ([]License, error) {
	bs, err := os.ReadFile(pathFileName)
	if err != nil {
		return nil, err
	}

	// handle specific file types
	//if path.Base(pathFileName) == "package.json" {
	//	return detectPackageJson(pathFileName, text)
	//}

	//if path.Ext(pathFileName) == ".pom" {
	//	return d.detectMavenPom(pathFileName, text)
	//}

	//if path.Ext(pathFileName) == ".nuspec" {
	//	return d.detectNuSpec(pathFileName, text)
	//}

	return d.detectBlob(pathFileName, bs)
}

type License struct {
	File       string
	Id         string
	Expression string
	Declared   bool
	Confidence float64
}

func (d *Detector) detectBlob(pathFileName string, text []byte) ([]License, error) {
	result := licensecheck.Scan(text)

	if len(result.Match) == 0 {
		// If no license match on file then it might be that some license reference is missing for this type of license.
		// If file is of obviously license type, here file name is set to LICENSE.xxx (or LICENCE) and is stored in package root,
		// then it is most likely a license. Do set this file as a LICENSE with id = UNKNOWN.
		if filepath.Base(pathFileName) == "LICENSE" || filepath.Base(pathFileName) == "LICENCE" {
			return []License{{
				Id:   "UNKNOWN",
				File: pathFileName,
			}}, nil
		}

		return nil, nil
	}
	var licenses []License
	for _, m := range result.Match {
		licenses = append(licenses, License{
			File:       pathFileName,
			Id:         m.ID,
			Declared:   false,
			Confidence: 0.8,
		})
	}

	// Validate if all extracted license id:s (strings) do match any known defined licence id.
	//licenses = d.validateLicences(licenses)

	return licenses, nil
}
