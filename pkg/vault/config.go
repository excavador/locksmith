// Package vault provides encrypted, append-only snapshot storage using age encryption.
package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type (
	// Config holds machine-local vault configuration stored at
	// ~/.config/locksmith/config.yaml.
	//
	// Two forms are supported:
	//
	//  1. Legacy single-vault form (still works forever):
	//
	//        vault_dir: ~/Dropbox/Private/vault
	//        identity: ~/.config/locksmith/age.key
	//        gpg_binary: gpg
	//
	//  2. Multi-vault registry form:
	//
	//        vaults:
	//          - name: personal
	//            path: ~/Dropbox/Private/vault
	//            identity: ~/.config/locksmith/personal.age
	//          - name: work
	//            path: ~/work/vault
	//        default: personal
	//
	// Both forms may coexist; the legacy single-vault entry is treated as a
	// synthetic registry entry named "default". Use Resolve() to look up a
	// vault by name with the correct precedence.
	Config struct {
		// Legacy single-vault fields. Still honored for backward compatibility.
		VaultDir  string `yaml:"vault_dir,omitempty"`
		Identity  string `yaml:"identity,omitempty"`
		GPGBinary string `yaml:"gpg_binary,omitempty"`

		// Multi-vault registry. Each entry can override identity and gpg_binary.
		Vaults  []Entry `yaml:"vaults,omitempty"`
		Default string  `yaml:"default,omitempty"`
	}

	// Entry is a single named entry in the vault registry.
	Entry struct {
		Name      string `yaml:"name"`
		Path      string `yaml:"path"`
		Identity  string `yaml:"identity,omitempty"`
		GPGBinary string `yaml:"gpg_binary,omitempty"`

		// TrustedMasterFP is the GPG master key fingerprint that this vault
		// is expected to contain (40 hex chars). Populated on first use
		// (TOFU): the kernel reads gpgsmith.yaml from the decrypted vault on
		// the first OpenSession and records what it found. On subsequent
		// opens the kernel verifies the embedded master_fp matches this
		// value and refuses with a loud error on mismatch — defending
		// against snapshot substitution attacks. Empty until first use.
		TrustedMasterFP string `yaml:"trusted_master_fp,omitempty"`
	}
)

const (
	// LegacyDefaultName is the synthetic name assigned to the legacy
	// single-vault entry when only vault_dir: is set.
	LegacyDefaultName = "default"
)

// DefaultConfigDir returns the default configuration directory for locksmith.
func DefaultConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	return filepath.Join(configDir, "locksmith"), nil
}

// DefaultConfigPath returns the default path to the vault config file.
func DefaultConfigPath() (string, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// LoadConfig reads the vault configuration from the given path.
// If path is empty, it uses the default config path.
//
// All path-like fields (vault_dir, identity, vaults[].path, vaults[].identity)
// have a leading "~/" expanded to the user's home directory.
func LoadConfig(path string) (*Config, error) {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return nil, fmt.Errorf("config path: %w", err)
		}
	}

	data, err := os.ReadFile(path) //nolint:gosec // path from user config or default
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.VaultDir = expandHome(cfg.VaultDir)
	cfg.Identity = expandHome(cfg.Identity)
	for i := range cfg.Vaults {
		cfg.Vaults[i].Path = expandHome(cfg.Vaults[i].Path)
		cfg.Vaults[i].Identity = expandHome(cfg.Vaults[i].Identity)
	}

	return &cfg, nil
}

// SaveConfig writes the vault configuration to the given path.
// If path is empty, it uses the default config path.
func SaveConfig(path string, cfg *Config) error {
	if path == "" {
		var err error
		path, err = DefaultConfigPath()
		if err != nil {
			return fmt.Errorf("config path: %w", err)
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}

	return nil
}

// ToConfig returns an ephemeral single-vault Config equivalent to this entry.
// Handy for passing the resolved entry to the existing Vault constructors,
// which still take a *Config.
func (e *Entry) ToConfig() *Config {
	return &Config{
		VaultDir:  e.Path,
		Identity:  e.Identity,
		GPGBinary: e.GPGBinary,
	}
}

// Resolve looks up a vault by name and returns its effective entry. The
// resolution rules are:
//
//   - If name is "" and Default is set, look up Default.
//   - If name is "" and Default is empty, fall back to LegacyDefaultName.
//   - If a matching entry exists in Vaults, return it (per-entry fields win).
//   - Otherwise, if a legacy single-vault config (VaultDir set) is present
//     and the requested name is "" or LegacyDefaultName, synthesize a
//     LegacyDefaultName entry from the top-level fields.
//   - Otherwise return an error.
//
// Top-level Identity and GPGBinary act as defaults that fill in any per-entry
// fields left blank.
func (c *Config) Resolve(name string) (*Entry, error) {
	wanted := name
	if wanted == "" {
		wanted = c.Default
	}
	if wanted == "" {
		wanted = LegacyDefaultName
	}

	// First, look in the explicit registry.
	for i := range c.Vaults {
		if c.Vaults[i].Name == wanted {
			entry := c.Vaults[i]
			// Top-level fields fill in any blanks.
			if entry.Identity == "" {
				entry.Identity = c.Identity
			}
			if entry.GPGBinary == "" {
				entry.GPGBinary = c.GPGBinary
			}
			return &entry, nil
		}
	}

	// Fall back to the legacy single-vault form, but only when the caller is
	// asking for the default (or asking by the synthetic legacy name).
	if c.VaultDir != "" && (wanted == LegacyDefaultName || (name == "" && c.Default == "")) {
		return &Entry{
			Name:      LegacyDefaultName,
			Path:      c.VaultDir,
			Identity:  c.Identity,
			GPGBinary: c.GPGBinary,
		}, nil
	}

	if name == "" {
		return nil, fmt.Errorf("no vaults configured")
	}
	return nil, fmt.Errorf("unknown vault %q", name)
}

// VaultNames returns the names of all known vaults, including the synthetic
// legacy entry when only VaultDir is set. Useful for the web UI's chooser
// screen and for shell completion.
func (c *Config) VaultNames() []string {
	seen := make(map[string]bool, len(c.Vaults)+1)
	names := make([]string, 0, len(c.Vaults)+1)
	for i := range c.Vaults {
		if c.Vaults[i].Name == "" || seen[c.Vaults[i].Name] {
			continue
		}
		seen[c.Vaults[i].Name] = true
		names = append(names, c.Vaults[i].Name)
	}
	if c.VaultDir != "" && !seen[LegacyDefaultName] {
		names = append(names, LegacyDefaultName)
	}
	return names
}

// AddVault appends a new entry to the registry. Returns an error if a vault
// with the same name already exists. Path is required, identity is optional.
// If this is the first registry entry, it also becomes the default.
func (c *Config) AddVault(entry Entry) error {
	if entry.Name == "" {
		return fmt.Errorf("vault name is required")
	}
	if entry.Path == "" {
		return fmt.Errorf("vault path is required")
	}
	for i := range c.Vaults {
		if c.Vaults[i].Name == entry.Name {
			return fmt.Errorf("vault %q already exists", entry.Name)
		}
	}
	// Reject collision with the synthetic legacy entry.
	if entry.Name == LegacyDefaultName && c.VaultDir != "" {
		return fmt.Errorf("vault %q collides with the legacy vault_dir entry; remove vault_dir first", entry.Name)
	}
	c.Vaults = append(c.Vaults, entry)
	if c.Default == "" && c.VaultDir == "" {
		c.Default = entry.Name
	}
	return nil
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if path == "" {
		return ""
	}
	if path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[1:])
}
