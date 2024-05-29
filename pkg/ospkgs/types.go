package ospkgs

type Package struct {
	Name          string
	Version       string
	Architecture  string
	Maintainer    string
	SourceName    string
	SourceVersion string
	Provides      []string
	Dependencies  []string
}
