package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
)

func setupCmd() *cli.Command {
	return &cli.Command{
		Name:  "setup",
		Usage: "first-time wizard: vault create + keys create",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "name", Usage: "real name for the key UID"},
			&cli.StringFlag{Name: "email", Usage: "email address for the key UID"},
			&cli.StringFlag{Name: "vault-name", Usage: "new vault name", Value: "default"},
			&cli.StringFlag{Name: "vault-path", Usage: "new vault directory path"},
			&cli.StringFlag{Name: "algo", Usage: "key algorithm", Value: "rsa4096"},
			&cli.StringFlag{Name: "subkey-algo", Usage: "subkey algorithm"},
			&cli.StringFlag{Name: "subkey-expiry", Usage: "subkey expiry", Value: "2y"},
		},
		Action: setup,
	}
}

func setup(ctx context.Context, cmd *cli.Command) error {
	fmt.Fprintln(os.Stderr, "=== gpgsmith setup ===")

	vaultName := cmd.String("vault-name")
	vaultPath := cmd.String("vault-path")
	var err error

	if vaultPath == "" {
		home, _ := os.UserHomeDir()
		suggested := filepath.Join(home, "Dropbox", "Private", "vault")
		fmt.Fprintf(os.Stderr, "(default vault path: %s)\n", suggested)
		vaultPath, err = promptLine("Vault directory path [" + suggested + "]: ")
		if err != nil {
			return err
		}
		if vaultPath == "" {
			vaultPath = suggested
		}
	}

	name := cmd.String("name")
	email := cmd.String("email")
	if name == "" {
		name, err = promptLine("Real name: ")
		if err != nil {
			return err
		}
	}
	if email == "" {
		email, err = promptLine("Email: ")
		if err != nil {
			return err
		}
	}
	if name == "" || email == "" {
		return fmt.Errorf("name and email are required")
	}

	passphrase, err := readPassphraseWithConfirm()
	if err != nil {
		return err
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("setup: %w", err)
	}
	defer client.Close()

	fmt.Fprintln(os.Stderr, "\n[1/2] Creating vault...")
	createResp, err := client.Vault.Create(ctx, connect.NewRequest(&v1.CreateVaultRequest{
		Name:       vaultName,
		Path:       vaultPath,
		Passphrase: passphrase,
	}))
	if err != nil {
		return fmt.Errorf("setup: create vault: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  created %s (%s)\n", vaultName, filepath.Base(createResp.Msg.GetSnapshot().GetFilename()))

	fmt.Fprintln(os.Stderr, "\n[2/2] Generating GPG keys...")
	keyResp, err := client.Key.Create(ctx, connect.NewRequest(&v1.CreateRequest{
		VaultName:    vaultName,
		Name:         name,
		Email:        email,
		Algo:         cmd.String("algo"),
		Expiry:       "0",
		SubkeyAlgo:   cmd.String("subkey-algo"),
		SubkeyExpiry: cmd.String("subkey-expiry"),
	}))
	if err != nil {
		return fmt.Errorf("setup: create key: %w", err)
	}
	fmt.Fprintf(os.Stderr, "  master: %s\n", keyResp.Msg.GetMasterFp())
	fmt.Fprintln(os.Stderr, "\nSetup complete. Run `gpgsmith keys status` to inspect.")
	return nil
}
