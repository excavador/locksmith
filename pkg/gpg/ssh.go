package gpg

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// ExportSSHPubKey exports the authentication subkey as an SSH public key
// to ~/.ssh/gpgsmith-<keyid>.pub.
func (c *Client) ExportSSHPubKey(ctx context.Context, masterFP string) (string, error) {
	if err := ValidateFingerprint(masterFP); err != nil {
		return "", fmt.Errorf("export ssh pubkey: %w", err)
	}

	// Get the auth subkey.
	keys, err := c.ListKeys(ctx)
	if err != nil {
		return "", fmt.Errorf("export ssh pubkey: %w", err)
	}

	var authKey *SubKey
	for i := range keys {
		if strings.Contains(keys[i].Usage, "a") || strings.Contains(keys[i].Usage, "A") {
			authKey = &keys[i]
			break
		}
	}
	if authKey == nil {
		return "", fmt.Errorf("export ssh pubkey: no authentication subkey found")
	}

	// Export SSH public key via gpg.
	out, err := c.exec(ctx, "--export-ssh-key", masterFP)
	if err != nil {
		return "", fmt.Errorf("export ssh pubkey: %w", err)
	}

	sshPubKey := strings.TrimSpace(string(out))
	if sshPubKey == "" {
		return "", fmt.Errorf("export ssh pubkey: gpg returned empty output")
	}

	// Write to ~/.ssh/gpgsmith-<keyid>.pub.
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("export ssh pubkey: get home dir: %w", err)
	}

	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return "", fmt.Errorf("export ssh pubkey: create .ssh dir: %w", err)
	}

	filename := fmt.Sprintf("gpgsmith-%s.pub", authKey.KeyID)
	outPath := filepath.Join(sshDir, filename)

	if err := os.WriteFile(outPath, []byte(sshPubKey+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("export ssh pubkey: write %s: %w", outPath, err)
	}

	c.logger.InfoContext(ctx, "exported ssh public key",
		slog.String("path", outPath),
		slog.String("key_id", authKey.KeyID),
	)

	return outPath, nil
}
