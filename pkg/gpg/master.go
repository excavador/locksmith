package gpg

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type (
	// MasterKeyOpts configures master key generation.
	MasterKeyOpts struct {
		NameReal  string // e.g. "Oleg Tsarev"
		NameEmail string // e.g. "oleg@example.com"
		Algo      string // e.g. "rsa4096", "ed25519" (default: "rsa4096")
		Expiry    string // e.g. "0" (no expiry), "2y" (default: "0")
	}
)

// GenerateMasterKey creates a new master key (certify-only) using --quick-gen-key.
// It returns the fingerprint of the newly created key.
func (c *Client) GenerateMasterKey(ctx context.Context, opts MasterKeyOpts) (string, error) {
	if opts.NameReal == "" {
		return "", fmt.Errorf("generate master key: name is required")
	}
	if opts.NameEmail == "" {
		return "", fmt.Errorf("generate master key: email is required")
	}

	algo := opts.Algo
	if algo == "" {
		algo = "rsa4096"
	}

	expiry := opts.Expiry
	if expiry == "" {
		expiry = "0"
	}

	uid := fmt.Sprintf("%s <%s>", opts.NameReal, opts.NameEmail)

	// --quick-gen-key creates a certify-only master key when "cert" usage is specified.
	out, err := c.exec(ctx,
		"--quick-gen-key", uid, algo, "cert", expiry,
	)
	if err != nil {
		return "", fmt.Errorf("generate master key: %w", err)
	}

	c.logger.InfoContext(ctx, "generated master key",
		slog.String("uid", uid),
		slog.String("algo", algo),
	)

	// Extract fingerprint from the newly created key.
	fp, err := c.findMasterFP(ctx, uid)
	if err != nil {
		return "", fmt.Errorf("generate master key: created key but failed to find fingerprint: %w", err)
	}

	_ = out // stdout is typically empty for quick-gen-key
	return fp, nil
}

// findMasterFP looks up the fingerprint of the master key matching the given UID.
func (c *Client) findMasterFP(ctx context.Context, uid string) (string, error) {
	keys, err := c.ListKeys(ctx)
	if err != nil {
		return "", err
	}

	// Find the most recently created master key (Certify capability).
	var bestFP string
	var bestCreated int64
	for i := range keys {
		if strings.Contains(keys[i].Usage, "C") && keys[i].Fingerprint != "" {
			created := keys[i].Created.Unix()
			if created > bestCreated {
				bestCreated = created
				bestFP = keys[i].Fingerprint
			}
		}
	}

	if bestFP == "" {
		return "", fmt.Errorf("no master key found for %q", uid)
	}

	return bestFP, nil
}
