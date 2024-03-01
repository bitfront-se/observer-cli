package main

import (
	"sbom.observer/cli/pkg/cmd"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cmd.Execute(version)
}
