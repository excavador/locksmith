package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"text/tabwriter"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	"github.com/excavador/locksmith/pkg/vault"
)

func vaultCmd() *cli.Command {
	return &cli.Command{
		Name:  "vault",
		Usage: "manage encrypted vault",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "create a new vault",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "no-interactive",
						Usage: "output env exports instead of spawning a shell",
					},
				},
				Action: vaultCreate,
			},
			{
				Name:      "import",
				Usage:     "import existing GNUPGHOME as first snapshot",
				ArgsUsage: "<path>",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "no-interactive",
						Usage: "output env exports instead of spawning a shell",
					},
				},
				Action: vaultImport,
			},
			{
				Name:  "open",
				Usage: "decrypt latest snapshot and start session",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "no-interactive",
						Usage: "output env exports instead of spawning a shell",
					},
				},
				Action: vaultOpen,
			},
			{
				Name:      "seal",
				Usage:     "save current session as new snapshot",
				ArgsUsage: "<message>",
				Action:    vaultSeal,
			},
			{
				Name:   "discard",
				Usage:  "discard session without saving",
				Action: vaultDiscard,
			},
			{
				Name:   "list",
				Usage:  "list all snapshots",
				Action: vaultList,
			},
			{
				Name:      "restore",
				Usage:     "decrypt a specific snapshot",
				ArgsUsage: "<ref>",
				Action:    vaultRestore,
			},
			{
				Name:  "config",
				Usage: "vault configuration",
				Commands: []*cli.Command{
					{Name: "show", Usage: "show vault config", Action: vaultConfigShow},
					{Name: "set", Usage: "set a vault config value", Action: vaultConfigSet},
				},
			},
		},
	}
}

func loadVault(ctx context.Context, cmd *cli.Command) (*vault.Vault, error) {
	return loadVaultWithOpts(ctx, cmd, false)
}

func loadVaultFirstUse(ctx context.Context, cmd *cli.Command) (*vault.Vault, error) {
	return loadVaultWithOpts(ctx, cmd, true)
}

func loadVaultWithOpts(ctx context.Context, cmd *cli.Command, confirmPassphrase bool) (*vault.Vault, error) {
	logger := loggerFrom(ctx)

	var cfg *vault.Config

	vaultDir := cmd.Root().String("vault-dir")
	if vaultDir != "" {
		cfg = &vault.Config{VaultDir: vaultDir}
	} else {
		var err error
		cfg, err = vault.LoadConfig("")
		if err != nil {
			return nil, fmt.Errorf("load vault config: %w (use --vault-dir or create config)", err)
		}
	}

	// If identity file is configured, use key-file mode.
	if cfg.Identity != "" {
		return vault.New(cfg, logger)
	}

	// Check GPGSMITH_VAULT_KEY env var before prompting.
	passphrase := os.Getenv("GPGSMITH_VAULT_KEY")
	if passphrase == "" {
		var err error
		if confirmPassphrase {
			passphrase, err = readPassphraseWithConfirm()
		} else {
			passphrase, err = readPassphrase("Vault passphrase: ")
		}
		if err != nil {
			return nil, err
		}
	}

	return vault.NewWithPassphrase(cfg, passphrase, logger)
}

func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	fd := os.Stdin.Fd()
	pass, err := term.ReadPassword(int(fd)) //nolint:gosec // fd is always stdin
	fmt.Fprintln(os.Stderr)

	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}

	if len(pass) == 0 {
		return "", fmt.Errorf("passphrase cannot be empty")
	}

	return string(pass), nil
}

func readPassphraseWithConfirm() (string, error) {
	return confirmPassphrases(readPassphrase)
}

func confirmPassphrases(readFn func(string) (string, error)) (string, error) {
	pass, err := readFn("Vault passphrase: ")
	if err != nil {
		return "", err
	}

	confirm, err := readFn("Confirm passphrase: ")
	if err != nil {
		return "", err
	}

	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}

	return pass, nil
}

func vaultCreate(ctx context.Context, cmd *cli.Command) error {
	logger := loggerFrom(ctx)

	vaultDir := cmd.Root().String("vault-dir")

	// If no --vault-dir, try loading from existing config.
	if vaultDir == "" {
		cfg, err := vault.LoadConfig("")
		if err == nil {
			vaultDir = cfg.VaultDir
		}
	}

	// If still no vault dir, use a sensible default.
	if vaultDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("determine home directory: %w", err)
		}
		vaultDir = filepath.Join(home, "Dropbox", "Private", "vault")
		logger.InfoContext(ctx, "no vault dir specified, using default",
			slog.String("dir", vaultDir),
		)
	}

	cfg := &vault.Config{VaultDir: vaultDir}
	v, err := vault.New(cfg, logger)
	if err != nil {
		return err
	}

	if err := v.Create(ctx); err != nil {
		return err
	}

	// Save config so future commands work without --vault-dir.
	if err := vault.SaveConfig("", cfg); err != nil {
		return err
	}

	// Open a session on the new empty vault.
	workdir, err := vault.SecureTmpDir()
	if err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	return startSession(ctx, v, workdir, cmd, logger)
}

func vaultImport(ctx context.Context, cmd *cli.Command) error {
	sourcePath := cmd.Args().First()
	if sourcePath == "" {
		return fmt.Errorf("import requires a source path")
	}

	v, err := loadVaultFirstUse(ctx, cmd)
	if err != nil {
		return err
	}

	snap, err := v.Import(ctx, sourcePath)
	if err != nil {
		return err
	}

	logger := loggerFrom(ctx)
	logger.InfoContext(ctx, "imported snapshot",
		slog.String("snapshot", filepath.Base(snap.Path)),
	)

	// Open the just-imported snapshot and start a session.
	workdir, _, err := v.Open(ctx)
	if err != nil {
		return fmt.Errorf("open after import: %w", err)
	}

	return startSession(ctx, v, workdir, cmd, logger)
}

func vaultOpen(ctx context.Context, cmd *cli.Command) error {
	v, err := loadVault(ctx, cmd)
	if err != nil {
		return err
	}

	workdir, snap, err := v.Open(ctx)
	if err != nil {
		return err
	}

	logger := loggerFrom(ctx)
	logger.InfoContext(ctx, "opened snapshot",
		slog.String("snapshot", filepath.Base(snap.Path)),
	)

	return startSession(ctx, v, workdir, cmd, logger)
}

func startSession(ctx context.Context, v *vault.Vault, workdir string, cmd *cli.Command, logger *slog.Logger) error {
	noInteractive := cmd.Bool("no-interactive")
	isTTY := isTerminal()

	if isTTY && !noInteractive {
		return runInteractiveSession(ctx, v, workdir, logger)
	}

	// Scripted mode: output env exports.
	fmt.Printf("export GNUPGHOME=%s;\n", workdir)
	if pass := v.Passphrase(); pass != "" {
		fmt.Printf("export GPGSMITH_VAULT_KEY='%s';\n", shellEscapeSingleQuote(pass))
	}
	return nil
}

func runInteractiveSession(ctx context.Context, v *vault.Vault, workdir string, logger *slog.Logger) error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	fmt.Fprintln(os.Stderr, "Entering gpgsmith shell. GNUPGHOME is set.")
	fmt.Fprintln(os.Stderr, "Run gpgsmith commands or raw gpg. Type 'exit' when done.")

	shellCmd := exec.CommandContext(ctx, shell) //nolint:gosec // shell from user's env
	shellCmd.Stdin = os.Stdin
	shellCmd.Stdout = os.Stdout
	shellCmd.Stderr = os.Stderr
	shellCmd.Env = append(os.Environ(), "GNUPGHOME="+workdir)

	if err := shellCmd.Run(); err != nil {
		logger.DebugContext(ctx, "shell exited",
			slog.String("error", err.Error()),
		)
	}

	// Prompt to seal or discard.
	fmt.Fprint(os.Stderr, "Seal vault? [Y/n/message]: ")

	var input string
	if _, err := fmt.Scanln(&input); err != nil || input == "" {
		input = "y"
	}

	switch input {
	case "n", "N", "no":
		return v.Discard(ctx, workdir)
	case "y", "Y", "yes":
		snap, err := v.Seal(ctx, workdir, "manual-session")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Sealed:", filepath.Base(snap.Path))
		return nil
	default:
		snap, err := v.Seal(ctx, workdir, input)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Sealed:", filepath.Base(snap.Path))
		return nil
	}
}

func vaultSeal(ctx context.Context, cmd *cli.Command) error {
	message := cmd.Args().First()
	if message == "" {
		return fmt.Errorf("seal requires a message")
	}

	gnupghome := os.Getenv("GNUPGHOME")
	if gnupghome == "" {
		return fmt.Errorf("GNUPGHOME not set (run vault open first)")
	}

	v, err := loadVault(ctx, cmd)
	if err != nil {
		return err
	}

	snap, err := v.Seal(ctx, gnupghome, message)
	if err != nil {
		return err
	}

	// Scripted mode: output unset + snapshot name.
	fmt.Printf("unset GNUPGHOME;\n")
	fmt.Printf("unset GPGSMITH_VAULT_KEY;\n")
	fmt.Fprintln(os.Stderr, "Sealed:", filepath.Base(snap.Path))
	return nil
}

func vaultDiscard(ctx context.Context, cmd *cli.Command) error {
	gnupghome := os.Getenv("GNUPGHOME")
	if gnupghome == "" {
		return fmt.Errorf("GNUPGHOME not set (run vault open first)")
	}

	v, err := loadVault(ctx, cmd)
	if err != nil {
		return err
	}

	if err := v.Discard(ctx, gnupghome); err != nil {
		return err
	}

	fmt.Printf("unset GNUPGHOME;\n")
	fmt.Printf("unset GPGSMITH_VAULT_KEY;\n")
	return nil
}

func vaultList(ctx context.Context, cmd *cli.Command) error {
	v, err := loadVault(ctx, cmd)
	if err != nil {
		return err
	}

	snapshots, err := v.List(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tMESSAGE")
	for _, s := range snapshots {
		_, _ = fmt.Fprintf(w, "%s\t%s\n", s.Timestamp.Format("2006-01-02 15:04:05"), s.Message)
	}
	return w.Flush()
}

func vaultRestore(ctx context.Context, cmd *cli.Command) error {
	ref := cmd.Args().First()
	if ref == "" {
		return fmt.Errorf("restore requires a snapshot reference")
	}

	v, err := loadVault(ctx, cmd)
	if err != nil {
		return err
	}

	workdir, err := v.Restore(ctx, ref)
	if err != nil {
		return err
	}

	fmt.Printf("export GNUPGHOME=%s;\n", workdir)
	return nil
}

func vaultConfigShow(ctx context.Context, _ *cli.Command) error {
	cfg, err := vault.LoadConfig("")
	if err != nil {
		return err
	}
	_ = ctx
	fmt.Printf("vault_dir: %s\n", cfg.VaultDir)
	fmt.Printf("identity: %s\n", cfg.Identity)
	fmt.Printf("gpg_binary: %s\n", cfg.GPGBinary)
	return nil
}

func vaultConfigSet(_ context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // key + value pair
		return fmt.Errorf("usage: vault config set <key> <value>")
	}

	key := args.Get(0)
	value := args.Get(1)

	cfg, err := vault.LoadConfig("")
	if err != nil {
		// Start from an empty config if none exists.
		cfg = &vault.Config{}
	}

	switch key {
	case "vault_dir":
		cfg.VaultDir = value
	case "identity":
		cfg.Identity = value
	case "gpg_binary":
		cfg.GPGBinary = value
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return vault.SaveConfig("", cfg)
}
