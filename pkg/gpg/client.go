// Package gpg provides GPG operations by shelling out to the gpg binary.
package gpg

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

type (
	// Options configures a new Client.
	Options struct {
		Binary     string // gpg binary path (default: "gpg")
		HomeDir    string // GNUPGHOME directory
		Logger     *slog.Logger
		Passphrase string // optional master-key passphrase, used with --pinentry-mode loopback
	}

	// Client wraps the gpg binary for key operations.
	Client struct {
		binary     string
		homeDir    string
		logger     *slog.Logger
		passphrase string
	}
)

// New creates a new GPG client. HomeDir is required.
func New(opts Options) (*Client, error) {
	if opts.HomeDir == "" {
		return nil, fmt.Errorf("gpg: home dir is required")
	}

	binary := opts.Binary
	if binary == "" {
		binary = "gpg"
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		binary:     binary,
		homeDir:    opts.HomeDir,
		logger:     logger,
		passphrase: opts.Passphrase,
	}, nil
}

// HasPassphrase reports whether a passphrase is configured for this client.
func (c *Client) HasPassphrase() bool {
	return c.passphrase != ""
}

// HomeDir returns the GNUPGHOME directory.
func (c *Client) HomeDir() string {
	return c.homeDir
}

var (
	// fingerprintRe matches a 40-character hex GPG fingerprint.
	fingerprintRe = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	// keyIDRe matches a 16-character hex GPG key ID.
	keyIDRe = regexp.MustCompile(`^[0-9A-Fa-f]{16}$`)
	// serialRe matches a numeric card serial number.
	serialRe = regexp.MustCompile(`^\d+$`)
)

// ValidateFingerprint checks that fp looks like a valid GPG fingerprint (40 hex chars).
func ValidateFingerprint(fp string) error {
	if !fingerprintRe.MatchString(fp) {
		return fmt.Errorf("invalid fingerprint format (expected 40 hex chars): %q", fp)
	}
	return nil
}

// ValidateKeyID checks that id looks like a valid GPG key ID (16 hex chars).
func ValidateKeyID(id string) error {
	if !keyIDRe.MatchString(id) {
		return fmt.Errorf("invalid key ID format (expected 16 hex chars): %q", id)
	}
	return nil
}

// ValidateSerial checks that serial looks like a valid card serial number (numeric).
func ValidateSerial(serial string) error {
	if !serialRe.MatchString(serial) {
		return fmt.Errorf("invalid card serial format (expected numeric): %q", serial)
	}
	return nil
}

// truncate returns at most maxLen characters from s, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// passphrasePipe creates an OS pipe, writes the configured passphrase to it,
// and returns the read end (to be passed to the child as an ExtraFile) along
// with the gpg flags needed to consume it. The caller must close the returned
// file when the child has exited.
//
// Returns (nil, nil, nil) if no passphrase is configured.
func (c *Client) passphrasePipe() (readEnd *os.File, args []string, err error) {
	if c.passphrase == "" {
		return nil, nil, nil
	}

	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create passphrase pipe: %w", err)
	}

	if _, err := w.WriteString(c.passphrase + "\n"); err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil, nil, fmt.Errorf("write passphrase pipe: %w", err)
	}
	if err := w.Close(); err != nil {
		_ = r.Close()
		return nil, nil, fmt.Errorf("close passphrase pipe: %w", err)
	}

	// The first entry in ExtraFiles becomes fd 3 in the child.
	return r, []string{"--pinentry-mode", "loopback", "--passphrase-fd", "3"}, nil
}

// exec runs the gpg binary with the given arguments and returns stdout.
func (c *Client) exec(ctx context.Context, args ...string) ([]byte, error) {
	pipeR, passArgs, err := c.passphrasePipe()
	if err != nil {
		return nil, err
	}
	if pipeR != nil {
		defer func() { _ = pipeR.Close() }()
	}

	fullArgs := append([]string{"--homedir", c.homeDir, "--batch", "--no-tty"}, passArgs...)
	fullArgs = append(fullArgs, args...)

	c.logger.DebugContext(ctx, "gpg exec",
		slog.String("binary", c.binary),
		slog.String("args", strings.Join(fullArgs, " ")),
	)

	cmd := exec.CommandContext(ctx, c.binary, fullArgs...) //nolint:gosec // binary path from user config
	if pipeR != nil {
		cmd.ExtraFiles = []*os.File{pipeR}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg %s: %w\nstderr: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return stdout.Bytes(), nil
}
