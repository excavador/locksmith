package gpg

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

type (
	// PublishResult holds the outcome of publishing to a single target.
	PublishResult struct {
		Target PublishTarget
		Err    error
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
func (c *Client) publishToGitHub(ctx context.Context, masterFP string) error {
	c.logger.InfoContext(ctx, "publishing to github")

	// Check if gh is available.
	ghPath, err := exec.LookPath("gh")
	if err != nil {
		return fmt.Errorf("gh CLI not found: install and authenticate gh to publish to GitHub")
	}

	// Export the public key in armor format.
	pubkey, err := c.exec(ctx, "--armor", "--export", masterFP)
	if err != nil {
		return fmt.Errorf("export public key: %w", err)
	}

	// Add GPG key to GitHub.
	cmd := exec.CommandContext(ctx, ghPath, "gpg-key", "add", "-") //nolint:gosec // ghPath from LookPath
	cmd.Stdin = strings.NewReader(string(pubkey))

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gh gpg-key add: %w\noutput: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
