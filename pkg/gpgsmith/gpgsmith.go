// Package gpgsmith provides the CLI application for gpgsmith.
package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/urfave/cli/v3"
)

type (
	ctxKey struct{}
)

func loggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// Main runs the gpgsmith CLI application and returns the exit code.
func Main(version, commit, date string) int {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	verbose := false

	app := &cli.Command{
		Name:    "gpgsmith",
		Usage:   "GPG key lifecycle manager with YubiKey support",
		Version: version,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:        "verbose",
				Usage:       "enable debug logging",
				Destination: &verbose,
			},
			&cli.BoolFlag{
				Name:  "dry-run",
				Usage: "print commands without executing",
			},
			&cli.StringFlag{
				Name:  "vault-dir",
				Usage: "override vault directory",
			},
		},
		Before: func(ctx context.Context, _ *cli.Command) (context.Context, error) {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: level,
			}))
			return context.WithValue(ctx, ctxKey{}, logger), nil
		},
		Commands: []*cli.Command{
			setupCmd(),
			vaultCmd(),
			keysCmd(),
			cardCmd(),
			auditCmd(),
			{
				Name:  "version",
				Usage: "show version information",
				Action: func(_ context.Context, _ *cli.Command) error {
					fmt.Println("gpgsmith " + version)
					fmt.Println("commit: " + commit)
					fmt.Println("built: " + date)
					fmt.Println("go: " + runtime.Version())
					return nil
				},
			},
		},
	}

	if err := app.Run(ctx, os.Args); err != nil {
		logger := loggerFrom(ctx)
		logger.ErrorContext(ctx, "fatal error", slog.String("error", err.Error()))
		return 1
	}
	return 0
}

func notImplemented(ctx context.Context, _ *cli.Command) error {
	loggerFrom(ctx).WarnContext(ctx, "not implemented yet")
	return nil
}
