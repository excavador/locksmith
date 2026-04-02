package gpg

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

type (
	// CardMode determines how keys are provisioned to a card.
	CardMode string
)

const (
	// CardModeSameKeys moves existing subkeys to the card.
	CardModeSameKeys CardMode = "same-keys"
	// CardModeUniqueKeys generates fresh subkeys before moving to card.
	CardModeUniqueKeys CardMode = "unique-keys"
)

// MoveToCard transfers subkeys to the connected smart card using --edit-key keytocard.
// keyIDs specifies which subkeys to move (by long key ID). The correct gpg subkey index
// and card slot are determined automatically from the keyring.
func (c *Client) MoveToCard(ctx context.Context, masterFP string, keyIDs []string) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("move to card: %w", err)
	}

	// List all keys to determine subkey indices and usages.
	keys, err := c.ListSecretKeys(ctx)
	if err != nil {
		return fmt.Errorf("move to card: %w", err)
	}

	// Build subkey index map (1-based, skipping the master key).
	// In gpg --edit-key, "key 1" selects the first subkey, "key 2" the second, etc.
	subkeyIdx := 0
	type subkeyInfo struct {
		index int    // 1-based gpg edit-key index
		usage string // S, E, A, etc.
	}
	idxMap := make(map[string]subkeyInfo)
	for i := range keys {
		if strings.Contains(keys[i].Usage, "C") {
			continue // skip master key
		}
		subkeyIdx++
		idxMap[keys[i].KeyID] = subkeyInfo{index: subkeyIdx, usage: keys[i].Usage}
	}

	for _, keyID := range keyIDs {
		info, ok := idxMap[keyID]
		if !ok {
			return fmt.Errorf("move to card: subkey %s not found in keyring", keyID)
		}

		slot := slotForUsage(info.usage)

		c.logger.InfoContext(ctx, "moving subkey to card",
			slog.String("key_id", keyID),
			slog.Int("subkey_index", info.index),
			slog.Int("slot", slot),
		)

		if err := c.keytocardSingle(ctx, masterFP, info.index, slot); err != nil {
			return fmt.Errorf("move subkey %s to card: %w", keyID, err)
		}
	}

	return nil
}

// keytocardSingle moves a single subkey to the card via gpg --edit-key.
// It uses --command-fd to feed interactive commands to gpg.
func (c *Client) keytocardSingle(ctx context.Context, masterFP string, subkeyIdx int, slot int) error {
	// Build the interactive command sequence:
	// key N -> keytocard -> slot -> save
	commands := fmt.Sprintf("key %d\nkeytocard\n%d\ny\nsave\n", subkeyIdx, slot)

	args := []string{
		"--homedir", c.homeDir,
		"--command-fd", "0",
		"--status-fd", "2",
		"--no-tty",
		"--edit-key", masterFP,
	}

	c.logger.DebugContext(ctx, "keytocard exec",
		slog.String("binary", c.binary),
		slog.String("args", strings.Join(args, " ")),
	)

	cmd := exec.CommandContext(ctx, c.binary, args...) //nolint:gosec // binary path from user config
	cmd.Stdin = strings.NewReader(commands)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		// Log full output at debug level; only include truncated stderr in the error
		// to avoid leaking key material from gpg's interactive output.
		c.logger.DebugContext(ctx, "keytocard failed",
			slog.String("stderr", stderr.String()),
			slog.String("stdout", string(out)),
		)
		return fmt.Errorf("keytocard: %w\nstderr: %s", err, truncate(stderr.String(), 200))
	}

	return nil
}

// slotForUsage returns the card slot number based on the subkey's usage capability.
// Slot 1 = Signature, Slot 2 = Encryption, Slot 3 = Authentication.
func slotForUsage(usage string) int {
	u := strings.ToUpper(usage)
	switch {
	case strings.Contains(u, "E"):
		return 2
	case strings.Contains(u, "A"):
		return 3
	default:
		return 1 // sign is default
	}
}
