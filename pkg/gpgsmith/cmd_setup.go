package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/vault"
)

func setupCmd() *cli.Command {
	return &cli.Command{
		Name:  "setup",
		Usage: "first-time wizard: vault create + keys create + card provision",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "real name for the key UID"},
			&cli.StringFlag{Name: "email", Usage: "email address for the key UID"},
			&cli.StringFlag{Name: "algo", Usage: "key algorithm", Value: "rsa4096"},
			&cli.StringFlag{Name: "subkey-algo", Usage: "subkey algorithm (default: same as master)"},
			&cli.StringFlag{Name: "subkey-expiry", Usage: "subkey expiry", Value: "2y"},
			&cli.BoolFlag{Name: "no-interactive", Usage: "output env exports instead of spawning a shell"},
		},
		Action: setup,
	}
}

func setup(ctx context.Context, cmd *cli.Command) error {
	if os.Getenv("GPGSMITH_SESSION") == "1" {
		return fmt.Errorf("already in a gpgsmith session, exit first")
	}

	logger := loggerFrom(ctx)

	// --- Step 1: Create vault ---
	fmt.Fprintln(os.Stderr, "=== Step 1: Create vault ===")

	vaultDir := cmd.Root().String("vault-dir")

	if vaultDir == "" {
		cfg, err := vault.LoadConfig("")
		if err == nil {
			vaultDir = cfg.VaultDir
		}
	}

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

	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		return fmt.Errorf("vault create: %w", err)
	}

	cfg := &vault.Config{VaultDir: vaultDir}
	if err := vault.SaveConfig("", cfg); err != nil {
		return err
	}

	v, err := loadVaultFirstUse(ctx, cmd)
	if err != nil {
		return err
	}

	// Create a temporary working directory as our session.
	workdir, err := vault.SecureTmpDir()
	if err != nil {
		return fmt.Errorf("create session dir: %w", err)
	}

	// Configure gpg + gpg-agent for loopback pinentry mode in this workdir,
	// so the master-key passphrase can be supplied via --passphrase-fd.
	if err := gpg.WriteAgentConfig(workdir); err != nil {
		return fmt.Errorf("configure gpg agent: %w", err)
	}

	// --- Step 2: Generate master key + subkeys ---
	fmt.Fprintln(os.Stderr, "\n=== Step 2: Generate GPG keys ===")

	if err := setupGenerateKeys(ctx, cmd, workdir, v.Passphrase(), logger); err != nil {
		return err
	}

	// --- Step 3: Start session ---
	fmt.Fprintln(os.Stderr, "\n=== Setup complete ===")
	fmt.Fprintln(os.Stderr, "You are now in a gpgsmith session. Run 'gpgsmith card provision <label>' to provision a YubiKey.")
	fmt.Fprintln(os.Stderr, "Type 'exit' when done to seal the vault.")

	return startSession(ctx, v, workdir, cmd, logger)
}

func setupGenerateKeys(ctx context.Context, cmd *cli.Command, workdir, passphrase string, logger *slog.Logger) error {
	name := cmd.String("name")
	email := cmd.String("email")

	var err error
	if name == "" {
		name, err = promptLine("Real name: ")
		if err != nil {
			return fmt.Errorf("read name: %w", err)
		}
	}
	if email == "" {
		email, err = promptLine("Email: ")
		if err != nil {
			return fmt.Errorf("read email: %w", err)
		}
	}

	if name == "" {
		return fmt.Errorf("name is required")
	}
	if email == "" {
		return fmt.Errorf("email is required")
	}

	client, gpgErr := gpg.New(gpg.Options{
		HomeDir:    workdir,
		Logger:     logger,
		Passphrase: passphrase,
	})
	if gpgErr != nil {
		return gpgErr
	}

	algo := cmd.String("algo")

	fp, err := client.GenerateMasterKey(ctx, gpg.MasterKeyOpts{
		NameReal:  name,
		NameEmail: email,
		Algo:      algo,
		Expiry:    "0",
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Master key: %s\n", fp)

	subkeyAlgo := cmd.String("subkey-algo")
	if subkeyAlgo == "" {
		subkeyAlgo = algo
	}
	subkeyExpiry := cmd.String("subkey-expiry")

	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: fp,
		Algo:     subkeyAlgo,
		Expiry:   subkeyExpiry,
	}); err != nil {
		return fmt.Errorf("generate subkeys: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Subkeys (S/E/A): %s, expires %s\n", subkeyAlgo, subkeyExpiry)

	gpgCfg := &gpg.Config{
		MasterFP:     fp,
		SubkeyAlgo:   subkeyAlgo,
		SubkeyExpiry: subkeyExpiry,
	}
	if err := client.SaveConfig(gpgCfg); err != nil {
		return fmt.Errorf("save gpg config: %w", err)
	}

	// Initialize server registry with defaults.
	if _, regErr := client.LoadServerRegistry(); regErr != nil {
		logger.WarnContext(ctx, "could not initialize server registry",
			slog.String("error", regErr.Error()),
		)
	}

	return audit.Append(workdir, audit.Entry{
		Action:  "setup",
		Details: fmt.Sprintf("master %s (%s <%s>) + S/E/A %s expires %s", fp[:16], name, email, subkeyAlgo, subkeyExpiry),
		Metadata: map[string]string{
			"master_fp": fp,
			"uid":       fmt.Sprintf("%s <%s>", name, email),
		},
	})
}
