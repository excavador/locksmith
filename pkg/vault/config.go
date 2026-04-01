// Package vault provides encrypted, append-only snapshot storage using age encryption.
package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type (
	// Config holds machine-local vault configuration stored at ~/.config/locksmith/config.yaml.
	Config struct {
		VaultDir  string `yaml:"vault_dir"`
		Identity  string `yaml:"identity,omitempty"`
		GPGBinary string `yaml:"gpg_binary,omitempty"`
	}
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
