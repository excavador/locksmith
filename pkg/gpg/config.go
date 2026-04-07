package gpg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	// Config holds GPG-specific configuration stored inside GNUPGHOME/gpgsmith.yaml.
	Config struct {
		MasterFP       string          `yaml:"master_fp"`
		SubkeyAlgo     string          `yaml:"subkey_algo"`
		SubkeyExpiry   string          `yaml:"subkey_expiry"`
		PublishTargets []PublishTarget `yaml:"publish_targets,omitempty"`
	}

	// PublishTarget describes where to publish public keys.
	PublishTarget struct {
		Type string `yaml:"type"` // "keyserver" or "github"
		URL  string `yaml:"url,omitempty"`
	}
)

const (
	configFilename = "gpgsmith.yaml"

	// TargetTypeKeyserver is the publish target type for keyservers.
	TargetTypeKeyserver = "keyserver"
	// TargetTypeGitHub is the publish target type for GitHub.
	TargetTypeGitHub = "github"
)

// LoadConfig reads the GPG config from GNUPGHOME/gpgsmith.yaml.
func (c *Client) LoadConfig() (*Config, error) {
	path := filepath.Join(c.homeDir, configFilename)

	data, err := os.ReadFile(path) //nolint:gosec // path built from homeDir + constant
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("gpg config: %s not found (run auto-discover first)", path)
		}
		return nil, fmt.Errorf("gpg config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("gpg config: parse %s: %w", path, err)
	}

	return &cfg, nil
}

// SaveConfig writes the GPG config to GNUPGHOME/gpgsmith.yaml.
func (c *Client) SaveConfig(cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("gpg config: marshal: %w", err)
	}

	path := filepath.Join(c.homeDir, configFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("gpg config: write %s: %w", path, err)
	}

	return nil
}

// AutoDiscoverConfig detects the master key fingerprint and populates a default config.
func (c *Client) AutoDiscoverConfig(ctx context.Context) (*Config, error) {
	keys, err := c.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("auto-discover config: %w", err)
	}

	// Find the master key (Certify capability).
	var masterFP string
	for i := range keys {
		if strings.Contains(keys[i].Usage, "C") {
			masterFP = keys[i].Fingerprint
			break
		}
	}
	if masterFP == "" {
		return nil, fmt.Errorf("auto-discover config: no master key (certify capability) found")
	}

	cfg := &Config{
		MasterFP:     masterFP,
		SubkeyAlgo:   "rsa4096",
		SubkeyExpiry: "2y",
		PublishTargets: []PublishTarget{
			{Type: TargetTypeKeyserver, URL: "hkps://keys.openpgp.org"},
			{Type: TargetTypeKeyserver, URL: "hkps://keyserver.ubuntu.com"},
			{Type: TargetTypeGitHub},
		},
	}

	return cfg, nil
}
