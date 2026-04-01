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
// The slots parameter maps GPG slot numbers (1=sign, 2=encrypt, 3=auth) to subkey indices.
func (c *Client) MoveToCard(ctx context.Context, masterFP string, subkeyIndices []int) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("move to card: %w", err)
	}
	for _, idx := range subkeyIndices {
		c.logger.InfoContext(ctx, "moving subkey to card",
			slog.Int("subkey_index", idx),
		)

		if err := c.keytocardSingle(ctx, masterFP, idx); err != nil {
			return fmt.Errorf("move subkey %d to card: %w", idx, err)
		}
	}

	return nil
}

// keytocardSingle moves a single subkey to the card via gpg --edit-key.
// It uses --command-fd to feed interactive commands to gpg.
func (c *Client) keytocardSingle(ctx context.Context, masterFP string, subkeyIdx int) error {
	// Build the interactive command sequence:
	// key N -> keytocard -> slot -> save
	slot := c.slotForIndex(subkeyIdx)

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

// slotForIndex returns the card slot number for a subkey index.
// Convention: subkey 1 = sign (slot 1), subkey 2 = encrypt (slot 2), subkey 3 = auth (slot 3).
func (c *Client) slotForIndex(idx int) int {
	if idx >= 1 && idx <= 3 {
		return idx
	}
	return 1
}
