package gpg

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ExportPubKeyToLocal exports the public key from the current GNUPGHOME and
// imports it into the user's default ~/.gnupg keyring. It also copies private
// key stubs for card-bound subkeys so the local keyring can use the card for
// signing outside the vault session.
func (c *Client) ExportPubKeyToLocal(ctx context.Context, masterFP string) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("export: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("export: get home dir: %w", err)
	}

	localGnupg := filepath.Join(home, ".gnupg")
	if _, err := os.Stat(localGnupg); os.IsNotExist(err) {
		return fmt.Errorf("export: %s does not exist", localGnupg)
	}

	// Export armored public key from vault GNUPGHOME.
	pubkey, err := c.exec(ctx, "--armor", "--export", masterFP)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if len(pubkey) == 0 {
		return fmt.Errorf("export: gpg returned empty output for %s", masterFP)
	}

	// Import public key into default ~/.gnupg.
	importCmd := exec.CommandContext(ctx, c.binary, //nolint:gosec // binary path from user config
		"--homedir", localGnupg, "--batch", "--no-tty", "--import")
	importCmd.Stdin = bytes.NewReader(pubkey)

	var stderr bytes.Buffer
	importCmd.Stderr = &stderr

	if err := importCmd.Run(); err != nil {
		return fmt.Errorf("export: import into %s: %w\nstderr: %s", localGnupg, err, stderr.String())
	}

	c.logger.InfoContext(ctx, "exported public key to local keyring",
		slog.String("target", localGnupg),
	)

	// Copy card-bound private key stubs so the local keyring can use the card.
	// These .key files contain card serial references, not actual private keys.
	copied, err := c.copyCardStubs(ctx, localGnupg)
	if err != nil {
		c.logger.WarnContext(ctx, "could not copy card stubs",
			slog.String("error", err.Error()),
		)
	} else if copied > 0 {
		c.logger.InfoContext(ctx, "copied card key stubs to local keyring",
			slog.Int("count", copied),
		)
	}

	return nil
}

// copyCardStubs copies private key stub files for card-bound subkeys from
// the vault GNUPGHOME to the target keyring's private-keys-v1.d directory.
func (c *Client) copyCardStubs(ctx context.Context, targetGnupg string) (int, error) {
	// List secret keys with keygrips and card serials.
	keys, err := c.ListSecretKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("list keys: %w", err)
	}

	srcDir := filepath.Join(c.homeDir, "private-keys-v1.d")
	dstDir := filepath.Join(targetGnupg, "private-keys-v1.d")

	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return 0, fmt.Errorf("create %s: %w", dstDir, err)
	}

	// Get keygrips for card-bound keys via --with-colons output.
	out, err := c.exec(ctx, "--with-colons", "--with-keygrip", "--list-secret-keys")
	if err != nil {
		return 0, fmt.Errorf("list keygrips: %w", err)
	}

	// Parse keygrip+card serial pairs. A card-bound key has a non-empty card
	// serial in field 15 of the ssb line, and the keygrip on the following grp line.
	_ = keys // keys used for context above
	var cardKeygrips []string
	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 2 || fields[0] != "ssb" {
			continue
		}
		// Field 15 (index 14) contains the card serial if key is on a card.
		if len(fields) > 14 && fields[14] != "" && strings.HasPrefix(fields[14], "D276") {
			// Next line should be the keygrip.
			if i+2 < len(lines) {
				grpFields := strings.Split(lines[i+2], ":")
				if len(grpFields) > 9 && grpFields[0] == "grp" && grpFields[9] != "" {
					cardKeygrips = append(cardKeygrips, grpFields[9])
				}
			}
		}
	}

	copied := 0
	for _, grip := range cardKeygrips {
		src := filepath.Join(srcDir, grip+".key")
		dst := filepath.Join(dstDir, grip+".key")

		data, readErr := os.ReadFile(src) //nolint:gosec // path from homeDir + constant
		if readErr != nil {
			continue // stub may not exist for all keys
		}

		if writeErr := os.WriteFile(dst, data, 0o600); writeErr != nil {
			return copied, fmt.Errorf("copy stub %s: %w", grip, writeErr)
		}
		copied++
	}

	return copied, nil
}
