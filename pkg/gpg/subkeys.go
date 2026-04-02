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
	// SubkeyOpts configures subkey generation.
	SubkeyOpts struct {
		MasterFP string // master key fingerprint
		Algo     string // e.g. "rsa4096", "ed25519"
		Expiry   string // e.g. "2y", "1y"
	}
)

// GenerateSubkeys creates Sign, Encrypt, and Auth subkeys under the master key.
func (c *Client) GenerateSubkeys(ctx context.Context, opts SubkeyOpts) error {
	if opts.MasterFP == "" {
		return fmt.Errorf("generate subkeys: master fingerprint is required")
	}
	if err := ValidateFingerprint(opts.MasterFP); err != nil {
		return fmt.Errorf("generate subkeys: %w", err)
	}

	usages := []string{"sign", "encr", "auth"}
	for _, usage := range usages {
		if _, err := c.exec(ctx,
			"--quick-add-key", opts.MasterFP, opts.Algo, usage, opts.Expiry,
		); err != nil {
			return fmt.Errorf("generate subkey (%s): %w", usage, err)
		}

		c.logger.InfoContext(ctx, "generated subkey",
			slog.String("usage", usage),
			slog.String("algo", opts.Algo),
			slog.String("expiry", opts.Expiry),
		)
	}

	return nil
}

// Revoke revokes a specific subkey by its key ID using --edit-key revkey.
func (c *Client) Revoke(ctx context.Context, masterFP string, keyID string) error {
	if masterFP == "" {
		return fmt.Errorf("revoke: master fingerprint is required")
	}
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	if keyID == "" {
		return fmt.Errorf("revoke: key ID is required")
	}
	if err := ValidateKeyID(keyID); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	// Find the subkey index in the keyring.
	keys, err := c.ListSecretKeys(ctx)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	subkeyIdx := 0
	found := false
	for i := range keys {
		if strings.Contains(keys[i].Usage, "C") {
			continue // skip master key
		}
		subkeyIdx++
		if keys[i].KeyID == keyID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("revoke: subkey %s not found in keyring", keyID)
	}

	// Interactive flow for revkey:
	//   key N        — select subkey
	//   revkey       — start revocation
	//   y            — "Do you really want to revoke this subkey? (y/N)"
	//   0            — reason code: "No reason specified"
	//   (empty)      — reason description (optional)
	//   y            — "Is this correct? (y/N)"
	//   save         — save changes
	commands := fmt.Sprintf("key %d\nrevkey\ny\n0\n\ny\nsave\n", subkeyIdx)

	args := []string{
		"--homedir", c.homeDir,
		"--command-fd", "0",
		"--status-fd", "2",
		"--no-tty",
		"--edit-key", masterFP,
	}

	c.logger.DebugContext(ctx, "revkey exec",
		slog.String("binary", c.binary),
		slog.String("key_id", keyID),
		slog.Int("subkey_index", subkeyIdx),
	)

	cmd := exec.CommandContext(ctx, c.binary, args...) //nolint:gosec // binary path from user config
	cmd.Stdin = strings.NewReader(commands)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		c.logger.DebugContext(ctx, "revkey failed",
			slog.String("stderr", stderr.String()),
			slog.String("stdout", string(out)),
		)
		return fmt.Errorf("revoke subkey %s: %w\nstderr: %s", keyID, err, truncate(stderr.String(), 200))
	}

	c.logger.InfoContext(ctx, "revoked subkey",
		slog.String("key_id", keyID),
	)

	return nil
}
