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

// MoveToCard transfers subkeys to the connected smart card using a single --edit-key session.
// keyIDs specifies which subkeys to move (by long key ID). The correct gpg subkey index
// and card slot are determined automatically from the keyring.
// All subkeys are moved in one gpg process so the master key passphrase is requested only once.
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

	// Build a single interactive command sequence for all subkeys.
	// For each subkey: "key N" to select, "keytocard", slot number, "y" to confirm
	// replacement if slot is occupied, then "key N" again to deselect (toggle off)
	// before selecting the next one.
	//
	// NOTE: With --command-fd, GPG reads all interactive answers (including GET_BOOL
	// prompts like "Replace existing key?") from stdin. The --yes flag does NOT
	// auto-confirm when --command-fd is active. We must always provide "y" for the
	// replacement prompt. If the slot is empty, the "y" is consumed harmlessly as
	// an unknown edit-key command (GPG prints a warning and continues).
	var cmds strings.Builder
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

		fmt.Fprintf(&cmds, "key %d\nkeytocard\n%d\ny\nkey %d\n", info.index, slot, info.index)
	}
	cmds.WriteString("save\n")

	args := []string{
		"--homedir", c.homeDir,
		"--command-fd", "0",
		"--status-fd", "2",
		"--yes",
		"--no-tty",
		"--edit-key", masterFP,
	}

	c.logger.DebugContext(ctx, "keytocard exec",
		slog.String("binary", c.binary),
		slog.String("args", strings.Join(args, " ")),
	)

	cmd := exec.CommandContext(ctx, c.binary, args...) //nolint:gosec // binary path from user config
	cmd.Stdin = strings.NewReader(cmds.String())

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		c.logger.DebugContext(ctx, "keytocard failed",
			slog.String("stderr", stderr.String()),
			slog.String("stdout", string(out)),
		)
		return fmt.Errorf("keytocard: %w\nstderr: %s", err, truncate(stderr.String(), 200))
	}

	// Verify that the card now holds the expected keys by checking fingerprints.
	if verifyErr := c.verifyCardKeys(ctx, keys, keyIDs); verifyErr != nil {
		return verifyErr
	}

	return nil
}

// verifyCardKeys checks that the card's key fingerprints match the moved subkeys.
func (c *Client) verifyCardKeys(ctx context.Context, keys []SubKey, keyIDs []string) error {
	info, err := c.CardStatus(ctx)
	if err != nil {
		return fmt.Errorf("move to card: verify: %w", err)
	}

	cardFPs := make(map[string]bool, len(info.KeyIDs))
	for _, fp := range info.KeyIDs {
		cardFPs[fp] = true
	}

	for _, keyID := range keyIDs {
		// Find the fingerprint for this key ID.
		var fp string
		for i := range keys {
			if keys[i].KeyID == keyID {
				fp = keys[i].Fingerprint
				break
			}
		}
		if fp == "" {
			continue // can't verify without fingerprint
		}
		if !cardFPs[fp] {
			return fmt.Errorf("move to card: key %s was not written to card (card fingerprints do not match)", keyID)
		}
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
