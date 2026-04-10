package gpgsmith

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/excavador/locksmith/pkg/audit"
	"github.com/excavador/locksmith/pkg/gpg"
)

func cardCmd() *cli.Command {
	return &cli.Command{
		Name:  "card",
		Usage: "high-level YubiKey workflows (requires GNUPGHOME set via vault open)",
		Commands: []*cli.Command{
			{
				Name:      "provision",
				Usage:     "generate subkeys + to-card + publish + ssh-pubkey",
				ArgsUsage: "<label>",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "same-keys", Usage: "copy same subkeys to card"},
					&cli.BoolFlag{Name: "unique-keys", Usage: "generate fresh subkeys for this card"},
					&cli.StringFlag{Name: "description", Usage: "optional card description"},
				},
				Action: cardProvision,
			},
			{
				Name:      "rotate",
				Usage:     "revoke old + generate new + to-card + publish + ssh",
				ArgsUsage: "<label>",
				Action:    cardRotate,
			},
			{
				Name:      "revoke",
				Usage:     "revoke all subkeys for a card + publish revocation",
				ArgsUsage: "<label>",
				Action:    cardRevoke,
			},
			{
				Name:   "inventory",
				Usage:  "list all known YubiKeys",
				Action: cardInventory,
			},
			{
				Name:   "discover",
				Usage:  "detect connected YubiKey and add to inventory",
				Action: cardDiscover,
			},
		},
	}
}

func cardProvision(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("provision requires a card label")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	// Generate subkeys.
	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return fmt.Errorf("provision: generate subkeys: %w", err)
	}

	// Find the latest S/E/A subkeys and move to card.
	keys, listErr := client.ListSecretKeys(ctx)
	if listErr != nil {
		return fmt.Errorf("provision: list keys: %w", listErr)
	}

	keyIDs := gpg.LatestSubkeyIDs(keys)
	if len(keyIDs) == 0 {
		return fmt.Errorf("provision: no S/E/A subkeys found")
	}

	if err := client.MoveToCard(ctx, cfg.MasterFP, keyIDs); err != nil {
		return fmt.Errorf("provision: to-card: %w", err)
	}

	// Publish to enabled servers.
	targets, _ := enabledPublishTargets(client)
	results := client.Publish(ctx, cfg.MasterFP, targets)
	logger := loggerFrom(ctx)
	for _, r := range results {
		if r.Err != nil {
			logger.WarnContext(ctx, "publish failed",
				slog.String("target", r.Target.Type),
				slog.String("error", r.Err.Error()),
			)
		}
	}

	// SSH pubkey.
	sshPath, err := client.ExportSSHPubKey(ctx, cfg.MasterFP)
	if err != nil {
		logger.WarnContext(ctx, "ssh pubkey export failed",
			slog.String("error", err.Error()),
		)
	} else {
		fmt.Fprintln(os.Stderr, "SSH pubkey:", sshPath)
	}

	// Update inventory.
	inv, err := client.LoadInventory()
	if err != nil {
		return fmt.Errorf("provision: load inventory: %w", err)
	}

	info, cardErr := client.CardStatus(ctx)
	if cardErr != nil {
		return fmt.Errorf("provision: card status: %w", cardErr)
	}

	mode := "same-keys"
	if cmd.Bool("unique-keys") {
		mode = "unique-keys"
	}

	// Build subkey refs from the keys we just moved, using keyIDs from before
	// MoveToCard rather than CardSerial matching (GPG may not have updated
	// the card serial in its keyring yet).
	movedSet := make(map[string]struct{}, len(keyIDs))
	for _, id := range keyIDs {
		movedSet[id] = struct{}{}
	}
	var subkeys []gpg.SubKeyRef
	for i := range keys {
		if _, ok := movedSet[keys[i].KeyID]; ok {
			subkeys = append(subkeys, gpg.SubKeyRef{
				KeyID:   keys[i].KeyID,
				Usage:   gpg.UsageLabel(keys[i].Usage),
				Created: keys[i].Created,
				Expires: keys[i].Expires,
			})
		}
	}

	entry := gpg.YubiKeyEntry{
		Serial:        info.Serial,
		Label:         label,
		Model:         info.Model,
		Description:   cmd.String("description"),
		Provisioning:  mode,
		Subkeys:       subkeys,
		ProvisionedAt: time.Now().UTC(),
		Status:        "active",
	}

	inv.YubiKeys = append(inv.YubiKeys, entry)
	if err := client.SaveInventory(inv); err != nil {
		return fmt.Errorf("provision: save inventory: %w", err)
	}

	// Audit.
	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "provision-card",
		Details: fmt.Sprintf("provisioned %s (%s) as %q", info.Serial, info.Model, label),
		Metadata: map[string]string{
			"serial": info.Serial,
			"label":  label,
			"mode":   mode,
		},
	})
}

func cardRotate(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("rotate requires a card label or serial")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	// Find the card in inventory.
	inv, err := client.LoadInventory()
	if err != nil {
		return fmt.Errorf("rotate: load inventory: %w", err)
	}

	entry := inv.FindByLabel(label)
	if entry == nil {
		return fmt.Errorf("rotate: YubiKey %q not found in inventory", label)
	}

	// Revoke old subkeys.
	for i := range entry.Subkeys {
		if err := client.Revoke(ctx, cfg.MasterFP, entry.Subkeys[i].KeyID); err != nil {
			return fmt.Errorf("rotate: revoke %s: %w", entry.Subkeys[i].KeyID, err)
		}
	}

	// Generate new subkeys.
	if err := client.GenerateSubkeys(ctx, gpg.SubkeyOpts{
		MasterFP: cfg.MasterFP,
		Algo:     cfg.SubkeyAlgo,
		Expiry:   cfg.SubkeyExpiry,
	}); err != nil {
		return fmt.Errorf("rotate: generate subkeys: %w", err)
	}

	// Find the latest S/E/A subkeys (just generated) and move to card.
	rotateKeys, rotateListErr := client.ListSecretKeys(ctx)
	if rotateListErr != nil {
		return fmt.Errorf("rotate: list keys: %w", rotateListErr)
	}

	keyIDs := gpg.LatestSubkeyIDs(rotateKeys)
	if len(keyIDs) == 0 {
		return fmt.Errorf("rotate: no S/E/A subkeys found after generation")
	}

	if err := client.MoveToCard(ctx, cfg.MasterFP, keyIDs); err != nil {
		return fmt.Errorf("rotate: to-card: %w", err)
	}

	// Publish to enabled servers.
	rotateTargets, _ := enabledPublishTargets(client)
	results := client.Publish(ctx, cfg.MasterFP, rotateTargets)
	logger := loggerFrom(ctx)
	for _, r := range results {
		if r.Err != nil {
			logger.WarnContext(ctx, "publish failed",
				slog.String("target", r.Target.Type),
				slog.String("error", r.Err.Error()),
			)
		}
	}

	// SSH pubkey.
	if _, sshErr := client.ExportSSHPubKey(ctx, cfg.MasterFP); sshErr != nil {
		logger.WarnContext(ctx, "ssh pubkey export failed",
			slog.String("error", sshErr.Error()),
		)
	}

	// Update inventory subkey refs with the keys we just moved.
	// Use keyIDs from the generation step rather than CardSerial matching,
	// because GPG may not have updated the card serial in its keyring yet.
	movedSet := make(map[string]struct{}, len(keyIDs))
	for _, id := range keyIDs {
		movedSet[id] = struct{}{}
	}
	var newSubkeys []gpg.SubKeyRef
	for i := range rotateKeys {
		if _, ok := movedSet[rotateKeys[i].KeyID]; ok {
			newSubkeys = append(newSubkeys, gpg.SubKeyRef{
				KeyID:   rotateKeys[i].KeyID,
				Usage:   gpg.UsageLabel(rotateKeys[i].Usage),
				Created: rotateKeys[i].Created,
				Expires: rotateKeys[i].Expires,
			})
		}
	}
	entry.Subkeys = newSubkeys
	if err := client.SaveInventory(inv); err != nil {
		return fmt.Errorf("rotate: save inventory: %w", err)
	}

	// Audit.
	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "rotate-card",
		Details: fmt.Sprintf("rotated subkeys for %q (%s)", label, entry.Serial),
		Metadata: map[string]string{
			"serial": entry.Serial,
			"label":  label,
		},
	})
}

func cardRevoke(ctx context.Context, cmd *cli.Command) error {
	label := cmd.Args().First()
	if label == "" {
		return fmt.Errorf("revoke requires a card label or serial")
	}

	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	cfg, err := loadGPGConfig(ctx, client)
	if err != nil {
		return err
	}

	inv, err := client.LoadInventory()
	if err != nil {
		return fmt.Errorf("card revoke: load inventory: %w", err)
	}

	entry := inv.FindByLabel(label)
	if entry == nil {
		return fmt.Errorf("card revoke: YubiKey %q not found in inventory", label)
	}

	// Revoke all subkeys.
	for i := range entry.Subkeys {
		if err := client.Revoke(ctx, cfg.MasterFP, entry.Subkeys[i].KeyID); err != nil {
			return fmt.Errorf("card revoke: revoke %s: %w", entry.Subkeys[i].KeyID, err)
		}
	}

	entry.Status = "revoked"
	if err := client.SaveInventory(inv); err != nil {
		return fmt.Errorf("card revoke: save inventory: %w", err)
	}

	// Publish revocation to enabled servers.
	revokeTargets, _ := enabledPublishTargets(client)
	results := client.Publish(ctx, cfg.MasterFP, revokeTargets)
	logger := loggerFrom(ctx)
	for _, r := range results {
		if r.Err != nil {
			logger.WarnContext(ctx, "publish revocation failed",
				slog.String("target", r.Target.Type),
				slog.String("error", r.Err.Error()),
			)
		}
	}

	return audit.Append(client.HomeDir(), audit.Entry{
		Action:  "revoke-card",
		Details: fmt.Sprintf("revoked all subkeys for %q (%s)", label, entry.Serial),
		Metadata: map[string]string{
			"serial": entry.Serial,
			"label":  label,
		},
	})
}

func cardInventory(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	inv, err := client.LoadInventory()
	if err != nil {
		return err
	}

	if len(inv.YubiKeys) == 0 {
		fmt.Println("No YubiKeys in inventory.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SERIAL\tLABEL\tMODEL\tSTATUS\tSUBKEYS\tDESCRIPTION")
	for i := range inv.YubiKeys {
		e := &inv.YubiKeys[i]
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			e.Serial, e.Label, e.Model, e.Status, len(e.Subkeys), e.Description)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if !gpg.YkmanAvailable() {
		hasGeneric := false
		for i := range inv.YubiKeys {
			if inv.YubiKeys[i].Model == "" || inv.YubiKeys[i].Model == "Yubico YubiKey" {
				hasGeneric = true
				break
			}
		}
		if hasGeneric {
			fmt.Fprintln(os.Stderr, "\nTip: install ykman (yubikey-manager) for more specific model detection.")
		}
	}

	return nil
}

func cardDiscover(ctx context.Context, _ *cli.Command) error {
	client, err := newGPGClient(ctx)
	if err != nil {
		return err
	}

	entry, err := client.DiscoverCard(ctx)
	if err != nil {
		return err
	}

	// Check if card is already in inventory.
	inv, err := client.LoadInventory()
	if err != nil {
		return fmt.Errorf("discover: load inventory: %w", err)
	}

	if existing := inv.FindByLabel(entry.Serial); existing != nil {
		// Update model if ykman provided a more specific one.
		if entry.Model != "" && entry.Model != existing.Model &&
			(existing.Model == "" || existing.Model == "Yubico YubiKey") {
			existing.Model = entry.Model
		}
		// Always sync subkey refs to match what's actually on the card.
		existing.Subkeys = entry.Subkeys
		if err := client.SaveInventory(inv); err != nil {
			return fmt.Errorf("discover: save inventory: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Already in inventory as %q (%s)\n", existing.Label, existing.Serial)
		return nil
	}

	fmt.Printf("Found YubiKey: serial %s, model %s\n", entry.Serial, entry.Model)
	for i := range entry.Subkeys {
		fmt.Printf("  %s (%s)\n", entry.Subkeys[i].KeyID, entry.Subkeys[i].Usage)
	}

	// Prompt for label and description.
	label, err := promptLine("Label: ")
	if err != nil {
		return fmt.Errorf("read label: %w", err)
	}
	if label == "" {
		return fmt.Errorf("label is required")
	}
	entry.Label = label

	desc, err := promptLine("Description (optional): ")
	if err != nil {
		return fmt.Errorf("read description: %w", err)
	}
	entry.Description = desc

	// Save to inventory.
	inv.YubiKeys = append(inv.YubiKeys, *entry)
	if err := client.SaveInventory(inv); err != nil {
		return fmt.Errorf("discover: save inventory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Added %q (%s) to inventory.\n", label, entry.Serial)
	return nil
}
