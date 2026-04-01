// Package main is the entrypoint for gpgsmith.
package main

import (
	"os"

	gpgsmith "github.com/excavador/locksmith/pkg/gpgsmith"
)

var (
	Version   = "dev"
	Commit    = "none"
	Date      = "unknown"
	GoVersion = "unknown"
)

func main() {
	os.Exit(gpgsmith.Main(Version, Commit, Date, GoVersion))
}
