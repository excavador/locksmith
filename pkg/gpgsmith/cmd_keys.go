package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/gpg"
)

func keysCmd() *cli.Command {
	return &cli.Command{
		Name:  "keys",
		Usage: "GPG key operations (requires GNUPGHOME set via vault open)",
		Commands: []*cli.Command{
			{Name: "create", Usage: "generate new master key and subkeys", Action: notImplemented},
			{Name: "generate", Usage: "add new S/E/A subkeys", Action: keysGenerate},
			{
				Name:  "to-card",
				Usage: "move subkeys to YubiKey",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "same-keys", Usage: "copy same subkeys to card (keeps backup)"},
					&cli.BoolFlag{Name: "unique-keys", Usage: "generate fresh subkeys for this card only"},
				},
				Action: keysToCard,
			},
			{Name: "list", Usage: "list keys and subkeys", Action: keysList},
			{
				Name:      "revoke",
				Usage:     "revoke a specific subkey",
				ArgsUsage: "<key-id>",
				Action:    keysRevoke,
			},
			{
				Name:  "publish",
				Usage: "publish public key to configured targets",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "target", Usage: "publish to a specific target only (keyserver, github)"},
				},
				Action: keysPublish,
			},
			{Name: "ssh-pubkey", Usage: "export auth subkey as SSH public key", Action: keysSSHPubKey},
			{Name: "status", Usage: "show key and card info", Action: keysStatus},
			{
				Name:  "config",
				Usage: "GPG configuration (inside GNUPGHOME)",
				Commands: []*cli.Command{
					{Name: "show", Usage: "show GPG config", Action: keysConfigShow},
					{Name: "set", Usage: "set a GPG config value", Action: keysConfigSet},
				},
			},
		},
	}
}

func newGPGClient(ctx context.Context) (*gpg.Client, error) {
	homeDir := os.Getenv("GNUPGHOME")
	if homeDir == "" {
		return nil, fmt.Errorf("GNUPGHOME not set (run vault open first)")
	}

	return gpg.New(gpg.Options{
		HomeDir: homeDir,
		Logger:  loggerFrom(ctx),
	})
}

func loadGPGConfig(client *gpg.Client) (*gpg.Config, error) {
	cfg, err := client.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load GPG config: %w (run keys config or auto-discover)", err)
	}
	return cfg, nil
}

func keysGenerate(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(client)
	if err != nil {
		return err
	}

	return client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	})
}

func keysToCard(ctx context.Context, cmd *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(client)
	if err != nil {
		return err
	}

	uniqueKeys := cmd.Bool("unique-keys")

	// --unique-keys: generate fresh subkeys before moving to card.
	if uniqueKeys {
		if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
			MasterFP: cfg.MasterFP,
			Algo:     cfg.SubkeyAlgo,
			Expiry:   cfg.SubkeyExpiry,
		}); err != nil {
			return fmt.Errorf("to-card: generate subkeys: %w", err)
		}
	}

	// S/E/A subkeys are typically indices 1, 2, 3 after the master key.
	indices := []int{1, 2, 3}

	return client.MoveToCard(ctx, cfg.MasterFP, indices)
}

func keysList(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	keys, err := client.ListSecretKeys(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "KEY ID\tALGO\tUSAGE\tCREATED\tEXPIRES\tCARD")
	for i := range keys {
		expires := "-"
		if !keys[i].Expires.IsZero() {
			expires = keys[i].Expires.Format("2006-01-02")
		}
		card := ""
		if keys[i].CardSerial != "" {
			card = keys[i].CardSerial
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			keys[i].KeyID,
			keys[i].Algorithm,
			keys[i].Usage,
			keys[i].Created.Format("2006-01-02"),
			expires,
			card,
		)
	}
	return w.Flush()
}

func keysRevoke(ctx context.Context, cmd *cli.Command) error {
	keyID := cmd.Args().First()
	if keyID == "" {
		return fmt.Errorf("revoke requires a key ID")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(client)
	if err != nil {
		return err
	}

	return client.Revoke(ctx, cfg.MasterFP, keyID)
}

func keysPublish(ctx context.Context, cmd *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(client)
	if err != nil {
		return err
	}

	targets := cfg.PublishTargets
	if targetFilter := cmd.String("target"); targetFilter != "" {
		var filtered []gpg.PublishTarget
		for _, t := range targets {
			if t.Type == targetFilter {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no publish target matching %q", targetFilter)
		}
		targets = filtered
	}

	results := client.Publish(ctx, cfg.MasterFP, targets)
	logger := loggerFrom(ctx)

	var firstErr error
	for _, r := range results {
		if r.Err != nil {
			logger.ErrorContext(ctx, "publish failed",
				slog.String("target", r.Target.Type),
				slog.String("error", r.Err.Error()),
			)
			if firstErr == nil {
				firstErr = r.Err
			}
		} else {
			logger.InfoContext(ctx, "published",
				slog.String("target", r.Target.Type),
			)
		}
	}

	return firstErr
}

func keysSSHPubKey(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(client)
	if err != nil {
		return err
	}

	path, err := client.ExportSSHPubKey(ctx, cfg.MasterFP)
	if err != nil {
		return err
	}

	fmt.Println(path)
	return nil
}

func keysStatus(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	keys, err := client.ListKeys(ctx)
	if err != nil {
		return err
	}

	fmt.Println("=== Keys ===")
	for i := range keys {
		fmt.Printf("  %s  %s  %s\n", keys[i].KeyID, keys[i].Algorithm, keys[i].Usage)
	}

	info, err := client.CardStatus(ctx)
	if err != nil {
		fmt.Println("\n=== Card ===")
		fmt.Println("  no card detected")
		return nil
	}

	fmt.Println("\n=== Card ===")
	fmt.Printf("  Serial: %s\n", info.Serial)
	fmt.Printf("  Model:  %s\n", info.Model)
	for _, kid := range info.KeyIDs {
		fmt.Printf("  Key:    %s\n", kid)
	}

	return nil
}

func keysConfigShow(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := client.LoadConfig()
	if err != nil {
		// Try auto-discover if no config exists.
		cfg, err = client.AutoDiscoverConfig(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "(auto-discovered, not yet saved)")
	}

	fmt.Printf("master_fp: %s\n", cfg.MasterFP)
	fmt.Printf("subkey_algo: %s\n", cfg.SubkeyAlgo)
	fmt.Printf("subkey_expiry: %s\n", cfg.SubkeyExpiry)
	for _, t := range cfg.PublishTargets {
		fmt.Printf("publish_target: %s %s\n", t.Type, t.URL)
	}
	return nil
}

func keysConfigSet(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args()
	if args.Len() < 2 { //nolint:mnd // key + value pair
		return fmt.Errorf("usage: keys config set <key> <value>")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, loadErr := client.LoadConfig()
	if loadErr != nil {
		cfg = &gpg.Config{}
	}

	key := args.Get(0)
	value := args.Get(1)

	switch key {
	case "master_fp":
		cfg.MasterFP = value
	case "subkey_algo":
		cfg.SubkeyAlgo = value
	case "subkey_expiry":
		cfg.SubkeyExpiry = value
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return client.SaveConfig(cfg)
}
