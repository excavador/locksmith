package gpg

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

type (
	// PublishResult holds the outcome of publishing to a single target.
	PublishResult struct {
		Target PublishTarget
		Err    error
	}

	// KeyserverLookupResult holds the result of looking up a key on a keyserver.
	KeyserverLookupResult struct {
		URL   string
		Found bool
		Err   error
	}
)

var (
	// WellKnownKeyservers is a list of popular keyservers for lookup.
	WellKnownKeyservers = []string{
		"hkps://keys.openpgp.org",
		"hkps://keyserver.ubuntu.com",
		"hkps://keys.mailvelope.com",
		"hkps://pgp.mit.edu",
	}
)

// Publish sends the public key to all configured publish targets.
// It continues on failure, collecting results for each target.
func (c *Client) Publish(ctx context.Context, masterFP string, targets []PublishTarget) []PublishResult {
	if err := ValidateFingerprint(masterFP); err != nil {
		return []PublishResult{{Err: fmt.Errorf("publish: %w", err)}}
	}

	var results []PublishResult

	for _, target := range targets {
		var err error
		switch target.Type {
		case "keyserver":
			err = c.publishToKeyserver(ctx, masterFP, target.URL)
		case "github":
			err = c.publishToGitHub(ctx, masterFP)
		default:
			err = fmt.Errorf("unknown publish target type: %s", target.Type)
		}

		results = append(results, PublishResult{Target: target, Err: err})
	}

	return results
}

// LookupKeyservers queries multiple keyservers to check if a key is published.
// Each keyserver query has a 15-second timeout to avoid hanging on unresponsive servers.
func (c *Client) LookupKeyservers(ctx context.Context, masterFP string, servers []string) []KeyserverLookupResult {
	const lookupTimeout = 15 * time.Second

	var results []KeyserverLookupResult

	for _, server := range servers {
		c.logger.DebugContext(ctx, "looking up key on keyserver",
			slog.String("server", server),
		)

		srvCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
		_, err := c.exec(srvCtx, "--keyserver", server, "--recv-keys", masterFP)
		cancel()

		found := err == nil

		results = append(results, KeyserverLookupResult{
			URL:   server,
			Found: found,
			Err:   err,
		})
	}

	return results
}

// LookupGitHub checks if the GPG key is registered on GitHub via `gh gpg-key list`.
func (c *Client) LookupGitHub(ctx context.Context, masterFP string) KeyserverLookupResult {
	ghPath, err := exec.LookPath("gh")
	if err != nil {
		return KeyserverLookupResult{URL: "github", Err: fmt.Errorf("gh CLI not found")}
	}

	cmd := exec.CommandContext(ctx, ghPath, "gpg-key", "list") //nolint:gosec // ghPath from LookPath
	out, err := cmd.Output()
	if err != nil {
		return KeyserverLookupResult{URL: "github", Err: fmt.Errorf("gh gpg-key list: %w", err)}
	}

	// Check if any line contains the key ID (last 16 chars of fingerprint).
	keyID := masterFP
	if len(keyID) > 16 {
		keyID = keyID[len(keyID)-16:]
	}

	found := strings.Contains(string(out), keyID)
	return KeyserverLookupResult{URL: "github", Found: found}
}

// publishToKeyserver sends the public key to a keyserver.
func (c *Client) publishToKeyserver(ctx context.Context, masterFP string, url string) error {
	c.logger.InfoContext(ctx, "publishing to keyserver",
		slog.String("url", url),
	)

	_, err := c.exec(ctx, "--keyserver", url, "--send-keys", masterFP)
	if err != nil {
		return fmt.Errorf("publish to keyserver %s: %w", url, err)
	}

	return nil
}

// publishToGitHub publishes GPG and SSH keys via the gh CLI.
// If the key already exists on GitHub, it is deleted and re-added to pick up
// new/revoked subkeys.
func (c *Client) publishToGitHub(ctx context.Context, masterFP string) error {
	c.logger.InfoContext(ctx, "publishing to github")

	ghPath, err := exec.LookPath("gh")
	if err != nil {
		return fmt.Errorf("gh CLI not found: install and authenticate gh to publish to GitHub")
	}

	// Export the public key in armor format.
	pubkey, err := c.exec(ctx, "--armor", "--export", masterFP)
	if err != nil {
		return fmt.Errorf("export public key: %w", err)
	}

	// Try to add the key. If it fails due to existing subkeys, delete and re-add.
	addCmd := exec.CommandContext(ctx, ghPath, "gpg-key", "add", "-") //nolint:gosec // ghPath from LookPath
	addCmd.Stdin = strings.NewReader(string(pubkey))

	if out, addErr := addCmd.CombinedOutput(); addErr != nil {
		outStr := strings.TrimSpace(string(out))
		if strings.Contains(outStr, "subkeys already exist") || strings.Contains(outStr, "already been added") {
			// Delete the existing key and re-add.
			if delErr := c.deleteGitHubGPGKey(ctx, ghPath, masterFP); delErr != nil {
				return fmt.Errorf("gh: key exists and delete failed: %w", delErr)
			}
			c.logger.InfoContext(ctx, "deleted old GPG key from github, re-adding")

			readdCmd := exec.CommandContext(ctx, ghPath, "gpg-key", "add", "-") //nolint:gosec // ghPath from LookPath
			readdCmd.Stdin = strings.NewReader(string(pubkey))
			if out2, err2 := readdCmd.CombinedOutput(); err2 != nil {
				return fmt.Errorf("gh gpg-key add (retry): %w\noutput: %s", err2, strings.TrimSpace(string(out2)))
			}
		} else {
			return fmt.Errorf("gh gpg-key add: %w\noutput: %s", addErr, outStr)
		}
	}

	// Also upload SSH public key if an auth subkey exists.
	sshPubkey, err := c.exec(ctx, "--export-ssh-key", masterFP)
	if err != nil {
		c.logger.DebugContext(ctx, "no SSH key to export for github", slog.String("error", err.Error()))
		return nil // GPG key was uploaded, SSH is optional
	}

	sshCmd := exec.CommandContext(ctx, ghPath, "ssh-key", "add", "-", "--title", "gpgsmith-"+masterFP[:16]) //nolint:gosec // ghPath from LookPath
	sshCmd.Stdin = strings.NewReader(string(sshPubkey))

	if out, err := sshCmd.CombinedOutput(); err != nil {
		c.logger.WarnContext(ctx, "gh ssh-key add failed",
			slog.String("output", strings.TrimSpace(string(out))),
		)
	}

	return nil
}

// deleteGitHubGPGKey finds and deletes the GPG key matching masterFP from GitHub.
func (c *Client) deleteGitHubGPGKey(ctx context.Context, ghPath string, masterFP string) error {
	keyID := masterFP
	if len(keyID) > 16 {
		keyID = keyID[len(keyID)-16:]
	}

	// List GPG keys via API to get the GitHub key ID.
	listCmd := exec.CommandContext(ctx, ghPath, "api", "user/gpg_keys", "--paginate", "--jq", //nolint:gosec // ghPath from LookPath
		fmt.Sprintf(`.[] | select(.key_id == %q) | .id`, keyID))
	out, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("list gpg keys: %w", err)
	}

	ghKeyID := strings.TrimSpace(string(out))
	if ghKeyID == "" {
		return fmt.Errorf("GPG key %s not found on GitHub", keyID)
	}

	// Delete the key.
	delCmd := exec.CommandContext(ctx, ghPath, "api", "-X", "DELETE", //nolint:gosec // ghPath from LookPath
		fmt.Sprintf("user/gpg_keys/%s", ghKeyID))
	if out, err := delCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("delete gpg key %s: %w\noutput: %s", ghKeyID, err, strings.TrimSpace(string(out)))
	}

	return nil
}
