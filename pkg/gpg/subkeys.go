package gpg

import (
	"context"
	"fmt"
	"log/slog"
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

// Revoke revokes a specific subkey by its key ID.
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

	if _, err := c.exec(ctx,
		"--quick-revoke-sig", masterFP, keyID,
	); err != nil {
		return fmt.Errorf("revoke subkey %s: %w", keyID, err)
	}

	c.logger.InfoContext(ctx, "revoked subkey",
		slog.String("key_id", keyID),
	)

	return nil
}
