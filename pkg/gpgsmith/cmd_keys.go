package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
)

const (
	statusActive  = "active"
	statusRevoked = "revoked"
	statusExpired = "expired"
)

// keyStatus returns a human-readable status for a key based on validity and expiry.
func keyStatus(k *gpg.SubKey) string {
	switch k.Validity {
	case "r":
		return statusRevoked
	case "e":
		return statusExpired
	}
	if !k.Expires.IsZero() && k.Expires.Before(time.Now()) {
		return statusExpired
	}
	return statusActive
}

func keysCmd() *cli.Command {
	return &cli.Command{
		Name:  "keys",
		Usage: "GPG key operations (requires GNUPGHOME set via vault open)",
		Commands: []*cli.Command{
			{
				Name:  "create",
				Usage: "generate new master key and subkeys",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Usage: "real name for the key UID (required)"},
					&cli.StringFlag{Name: "email", Usage: "email address for the key UID (required)"},
					&cli.StringFlag{Name: "algo", Usage: "key algorithm", Value: "rsa4096"},
					&cli.StringFlag{Name: "expiry", Usage: "master key expiry (0 = no expiry)", Value: "0"},
					&cli.StringFlag{Name: "subkey-algo", Usage: "subkey algorithm (default: same as master)"},
					&cli.StringFlag{Name: "subkey-expiry", Usage: "subkey expiry", Value: "2y"},
				},
				Action: keysCreate,
			},
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
				Name:      "publish",
				Usage:     "publish public key (alias for 'server publish')",
				ArgsUsage: "[alias...]",
				Hidden:    true,
				Action:    serverPublish,
			},
			{Name: "export", Usage: "export public key to local ~/.gnupg keyring", Action: keysExport},
			{Name: "ssh-pubkey", Usage: "export auth subkey as SSH public key", Action: keysSSHPubKey},
			{
				Name:   "lookup",
				Usage:  "check which servers have your public key (alias for 'server lookup')",
				Hidden: true,
				Action: serverLookup,
			},
			{Name: "status", Usage: "show key and card info", Action: keysStatus},
			{
				Name:    "identity",
				Aliases: []string{"uid"},
				Usage:   "manage identities (name+email UIDs) on the master key",
				Commands: []*cli.Command{
					{
						Name:   "list",
						Usage:  "list identities on the master key",
						Action: keysIdentityList,
					},
					{
						Name:      "add",
						Usage:     `add a new identity (e.g. "Name <email@example.com>")`,
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
						Usage:     "set an identity as primary by exact match or 1-based index",
						ArgsUsage: "<identity-or-index>",
						Action:    keysIdentityPrimary,
					},
				},
			},
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
		HomeDir:    homeDir,
		Logger:     loggerFrom(ctx),
		Passphrase: os.Getenv("GPGSMITH_VAULT_KEY"),
	})
}

func loadGPGConfig(ctx context.Context, client *gpg.Client) (*gpg.Config, error) {
	cfg, err := client.LoadConfig()
	if err != nil {
		// Fall back to auto-discover + save when config file doesn't exist.
		cfg, adErr := client.AutoDiscoverConfig(ctx)
		if adErr != nil {
			return nil, fmt.Errorf("load GPG config: %w (auto-discover also failed: %w)", err, adErr)
		}
		if saveErr := client.SaveConfig(cfg); saveErr != nil {
			return nil, fmt.Errorf("load GPG config: auto-discovered but failed to save: %w", saveErr)
		}
		fmt.Fprintln(os.Stderr, "gpgsmith.yaml auto-discovered and saved")
		return cfg, nil
	}
	return cfg, nil
}

func keysCreate(ctx context.Context, cmd *cli.Command) error {
	name := cmd.String("name")
	email := cmd.String("email")

	if name == "" || email == "" {
		// Prompt interactively if flags not provided.
		if name == "" {
			var err error
			name, err = promptLine("Real name: ")
			if err != nil {
				return fmt.Errorf("read name: %w", err)
			}
		}
		if email == "" {
			var err error
			email, err = promptLine("Email: ")
			if err != nil {
				return fmt.Errorf("read email: %w", err)
			}
		}
	}

	if name == "" {
		return fmt.Errorf("name is required")
	}
	if email == "" {
		return fmt.Errorf("email is required")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	algo := cmd.String("algo")
	expiry := cmd.String("expiry")

	// Generate master key (certify-only).
	fp, err := client.GenerateMasterKey(ctx, gpg.MasterKeyOpts{
		NameReal:  name,
		NameEmail: email,
		Algo:      algo,
		Expiry:    expiry,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Master key created: %s\n", fp)

	// Save gpgsmith.yaml with the new master fingerprint.
	subkeyAlgo := cmd.String("subkey-algo")
	if subkeyAlgo == "" {
		subkeyAlgo = algo
	}
	subkeyExpiry := cmd.String("subkey-expiry")

	cfg := &gpg.Config{
		MasterFP:     fp,
		SubkeyAlgo:   subkeyAlgo,
		SubkeyExpiry: subkeyExpiry,
	}
	if err := client.SaveConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	// Generate S/E/A subkeys.
	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: fp,
		Algo:     subkeyAlgo,
		Expiry:   subkeyExpiry,
	}); err != nil {
		return fmt.Errorf("generate subkeys: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Subkeys (S/E/A) created: %s, expires %s\n", subkeyAlgo, subkeyExpiry)

	// Initialize server registry with defaults.
	if _, regErr := client.LoadServerRegistry(); regErr != nil {
		loggerFrom(ctx).WarnContext(ctx, "could not initialize server registry",
			slog.String("error", regErr.Error()),
		)
	}

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "create-key",
		Details: fmt.Sprintf("master %s (%s <%s>) + S/E/A %s expires %s", fp[:16], name, email, subkeyAlgo, subkeyExpiry),
		Metadata: map[string]string{
			"master_fp": fp,
			"uid":       fmt.Sprintf("%s <%s>", name, email),
		},
	})
}

func keysGenerate(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return err
	}

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "generate-subkeys",
		Details: fmt.Sprintf("S/E/A %s expires %s", cfg.SubkeyAlgo, cfg.SubkeyExpiry),
	})
}

func keysToCard(ctx context.Context, cmd *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
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

	// Find the latest S/E/A subkeys to move to card.
	keys, err := client.ListSecretKeys(ctx)
	if err != nil {
		return fmt.Errorf("to-card: %w", err)
	}

	keyIDs := gpg.LatestSubkeyIDs(keys)
	if len(keyIDs) == 0 {
		return fmt.Errorf("to-card: no S/E/A subkeys found")
	}

	if err := client.MoveToCard(ctx, cfg.MasterFP, keyIDs); err != nil {
		return err
	}

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "to-card",
		Details: fmt.Sprintf("moved %d subkeys to card", len(keyIDs)),
		Metadata: map[string]string{
			"subkeys": strings.Join(keyIDs, ","),
		},
	})
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

	inv, _ := client.LoadInventory()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "KEY ID\tALGO\tUSAGE\tSTATUS\tCREATED\tEXPIRES\tCARD")
	for i := range keys {
		expires := "-"
		if !keys[i].Expires.IsZero() {
			expires = keys[i].Expires.Format("2006-01-02")
		}
		status := keyStatus(&keys[i])
		card := ""
		if keys[i].CardSerial != "" {
			if inv != nil {
				if entry := inv.FindByLabel(keys[i].CardSerial); entry != nil && entry.Label != "" {
					card = entry.Label
				} else {
					card = keys[i].CardSerial
				}
			} else {
				card = keys[i].CardSerial
			}
		}
		if card == "" && inv != nil {
			for j := range inv.YubiKeys {
				for k := range inv.YubiKeys[j].Subkeys {
					if inv.YubiKeys[j].Subkeys[k].KeyID == keys[i].KeyID {
						card = inv.YubiKeys[j].Label
						break
					}
				}
				if card != "" {
					break
				}
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			keys[i].KeyID,
			keys[i].Algorithm,
			keys[i].Usage,
			status,
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

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	if err := client.Revoke(ctx, cfg.MasterFP, keyID); err != nil {
		return err
	}

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "revoke-subkey",
		Details: fmt.Sprintf("revoked subkey %s", keyID),
		Metadata: map[string]string{
			"key_id": keyID,
		},
	})
}

func keysExport(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	return client.ExportPubKeyToLocal(ctx, cfg.MasterFP)
}

func keysSSHPubKey(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
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
	if len(cfg.PublishTargets) > 0 {
		fmt.Println("publish_targets: (legacy, use 'server list' instead)")
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
