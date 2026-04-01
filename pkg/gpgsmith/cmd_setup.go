package gpgsmith

import (
	"github.com/urfave/cli/v3"
)

func setupCmd() *cli.Command {
	return &cli.Command{
		Name:   "setup",
		Usage:  "first-time wizard: vault create + keys create + card provision",
		Action: notImplemented,
	}
}
