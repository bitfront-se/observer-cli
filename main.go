package main

import (
	"sbom.observer/cli/pkg/cmd"
	"sbom.observer/cli/pkg/types"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	types.Version = version
	types.Commit = commit
	types.Date = date

	cmd.Execute()
}
