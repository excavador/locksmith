package gpgsmith

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v3"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
)

func keysCmd() *cli.Command {
	return &cli.Command{
		Name:  "keys",
		Usage: "GPG key operations",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "generate new master key and subkeys",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "real name for the key UID"},
					&cli.StringFlag{Name: "email", Usage: "email address for the key UID"},
					&cli.StringFlag{Name: "algo", Usage: "key algorithm", Value: "rsa4096"},
					&cli.StringFlag{Name: "expiry", Usage: "master key expiry", Value: "0"},
					&cli.StringFlag{Name: "subkey-algo", Usage: "subkey algorithm (default: same as master)"},
					&cli.StringFlag{Name: "subkey-expiry", Usage: "subkey expiry", Value: "2y"},
				},
				Action: keysCreate,
			},
			{Name: "generate", Usage: "add new S/E/A subkeys", Action: keysGenerate},
			{Name: "list", Usage: "list keys and subkeys", Action: keysList},
			{
				Name:      "revoke",
				Usage:     "revoke a specific subkey",
				ArgsUsage: "<key-id>",
				Action:    keysRevoke,
			},
			{Name: "export", Usage: "export public key to local ~/.gnupg keyring", Action: keysExport},
			{Name: "ssh-pubkey", Usage: "export auth subkey as SSH public key", Action: keysSSHPubKey},
			{Name: "status", Usage: "show key and card info", Action: keysStatus},
			{
				Name:    "identity",
				Aliases: []string{"uid"},
				Usage:   "manage identities on the master key",
				Commands: []*cli.Command{
					{Name: "list", Usage: "list identities", Action: keysIdentityList},
					{
						Name:      "add",
						Usage:     "add a new identity",
						ArgsUsage: "<identity>",
						Action:    keysIdentityAdd,
					},
					{
						Name:      "revoke",
						Usage:     "revoke an identity by exact match or 1-based index",
						ArgsUsage: "<identity-or-index>",
						Action:    keysIdentityRevoke,
					},
					{
						Name:      "primary",
						Usage:     "set an identity as primary",
						ArgsUsage: "<identity-or-index>",
						Action:    keysIdentityPrimary,
					},
				},
			},
		},
	}
}

func keysCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	email := cmd.String("email")

	var err error
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

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys create: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys create: %w", err)
	}

	resp, err := client.Key.Create(ctx, connect.NewRequest(&v1.CreateRequest{
		VaultName:    vaultName,
		Name:         name,
		Email:        email,
		Algo:         cmd.String("algo"),
		Expiry:       cmd.String("expiry"),
		SubkeyAlgo:   cmd.String("subkey-algo"),
		SubkeyExpiry: cmd.String("subkey-expiry"),
	}))
	if err != nil {
		return fmt.Errorf("keys create: %w", err)
	}
	fmt.Fprintf(os.Stderr, "master: %s\n", resp.Msg.GetMasterFp())
	for _, sk := range resp.Msg.GetSubkeys() {
		fmt.Fprintf(os.Stderr, "  subkey %s (%s)\n", sk.GetKeyId(), sk.GetUsage())
	}
	return nil
}

func keysGenerate(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys generate: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys generate: %w", err)
	}

	resp, err := client.Key.Generate(ctx, connect.NewRequest(&v1.GenerateRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("keys generate: %w", err)
	}
	for _, sk := range resp.Msg.GetSubkeys() {
		fmt.Fprintf(os.Stderr, "subkey %s (%s)\n", sk.GetKeyId(), sk.GetUsage())
	}
	return nil
}

func keysList(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys list: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys list: %w", err)
	}

	resp, err := client.Key.List(ctx, connect.NewRequest(&v1.ListKeysRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("keys list: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "KEY ID\tALGO\tUSAGE\tVALIDITY\tCREATED\tEXPIRES\tCARD")
	for _, k := range resp.Msg.GetKeys() {
		expires := "-"
		if e := k.GetExpires(); e != nil && !e.AsTime().IsZero() {
			expires = e.AsTime().Format("2006-01-02")
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			k.GetKeyId(),
			k.GetAlgorithm(),
			k.GetUsage(),
			dash(k.GetValidity()),
			k.GetCreated().AsTime().Format("2006-01-02"),
			expires,
			dash(k.GetCardSerial()),
		)
	}
	return w.Flush()
}

func keysRevoke(ctx context.Context, cmd *cli.Command) error {
	keyID := cmd.Args().First()
	if keyID == "" {
		return fmt.Errorf("keys revoke: missing <key-id>")
	}

	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys revoke: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys revoke: %w", err)
	}

	_, err = client.Key.Revoke(ctx, connect.NewRequest(&v1.RevokeRequest{
		VaultName: vaultName,
		KeyId:     keyID,
	}))
	if err != nil {
		return fmt.Errorf("keys revoke: %w", err)
	}
	fmt.Fprintf(os.Stderr, "revoked %s\n", keyID)
	return nil
}

func keysExport(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys export: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys export: %w", err)
	}

	resp, err := client.Key.Export(ctx, connect.NewRequest(&v1.ExportKeyRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("keys export: %w", err)
	}
	fmt.Fprintf(os.Stderr, "exported to %s\n", resp.Msg.GetTarget())
	return nil
}

func keysSSHPubKey(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys ssh-pubkey: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys ssh-pubkey: %w", err)
	}

	resp, err := client.Key.SSHPubKey(ctx, connect.NewRequest(&v1.SSHPubKeyRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("keys ssh-pubkey: %w", err)
	}
	fmt.Println(resp.Msg.GetPath())
	return nil
}

func keysStatus(ctx context.Context, cmd *cli.Command) error {
	client, err := ensureClient(ctx)
	if err != nil {
		return fmt.Errorf("keys status: %w", err)
	}
	defer client.Close()

	vaultName, err := resolveVaultName(ctx, client, cmd)
	if err != nil {
		return fmt.Errorf("keys status: %w", err)
	}

	resp, err := client.Key.Status(ctx, connect.NewRequest(&v1.KeyStatusRequest{VaultName: vaultName}))
	if err != nil {
		return fmt.Errorf("keys status: %w", err)
	}

	fmt.Println("=== Keys ===")
	for _, k := range resp.Msg.GetKeys() {
		fmt.Printf("  %s  %s  %s\n", k.GetKeyId(), k.GetAlgorithm(), k.GetUsage())
	}

	card := resp.Msg.GetCard()
	fmt.Println("\n=== Card ===")
	if card == nil || card.GetSerial() == "" {
		fmt.Println("  no card detected")
		return nil
	}
	fmt.Printf("  Serial: %s\n", card.GetSerial())
	fmt.Printf("  Model:  %s\n", card.GetModel())
	return nil
}
