package gpg

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type (
	// ServerEntry represents a publish target (keyserver or GitHub) in the registry.
	ServerEntry struct {
		Alias   string `yaml:"alias"`
		Type    string `yaml:"type"` // "keyserver" or "github"
		URL     string `yaml:"url,omitempty"`
		Enabled bool   `yaml:"enabled"`
	}

	// ServerRegistry holds all known publish targets.
	ServerRegistry struct {
		Servers []ServerEntry `yaml:"servers"`
	}
)

const (
	serversFilename = "gpgsmith-servers.yaml"
)

// DefaultServers returns the built-in server list.
func DefaultServers() []ServerEntry {
	return []ServerEntry{
		{Alias: "openpgp", Type: TargetTypeKeyserver, URL: "hkps://keys.openpgp.org", Enabled: true},
		{Alias: "ubuntu", Type: TargetTypeKeyserver, URL: "hkps://keyserver.ubuntu.com", Enabled: true},
		{Alias: "github", Type: TargetTypeGitHub, Enabled: false},
		{Alias: "mailvelope", Type: TargetTypeKeyserver, URL: "hkps://keys.mailvelope.com", Enabled: false},
		{Alias: "mit", Type: TargetTypeKeyserver, URL: "hkps://pgp.mit.edu", Enabled: false},
		{Alias: "gnupg", Type: TargetTypeKeyserver, URL: "hkps://keys.gnupg.net", Enabled: false},
	}
}

// LoadServerRegistry reads the server registry from GNUPGHOME/gpgsmith-servers.yaml.
// If the file does not exist, it migrates from publish_targets in the config
// or initializes with defaults.
func (c *Client) LoadServerRegistry() (*ServerRegistry, error) {
	path := filepath.Join(c.homeDir, serversFilename)

	data, err := os.ReadFile(path) //nolint:gosec // path built from homeDir + constant
	if err != nil {
		if os.IsNotExist(err) {
			return c.initServerRegistry()
		}
		return nil, fmt.Errorf("load server registry: read %s: %w", path, err)
	}

	var reg ServerRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("load server registry: parse %s: %w", path, err)
	}

	return &reg, nil
}

// SaveServerRegistry writes the server registry to GNUPGHOME/gpgsmith-servers.yaml.
func (c *Client) SaveServerRegistry(reg *ServerRegistry) error {
	data, err := yaml.Marshal(reg)
	if err != nil {
		return fmt.Errorf("save server registry: marshal: %w", err)
	}

	path := filepath.Join(c.homeDir, serversFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("save server registry: write %s: %w", path, err)
	}

	return nil
}

// initServerRegistry creates a new registry by migrating from config or using defaults.
func (c *Client) initServerRegistry() (*ServerRegistry, error) {
	// Try to migrate from existing publish_targets in config.
	cfg, cfgErr := c.LoadConfig()
	if cfgErr == nil && len(cfg.PublishTargets) > 0 {
		reg := migrateFromConfig(cfg.PublishTargets)

		// Remove publish_targets from config now that they're migrated.
		cfg.PublishTargets = nil
		if saveErr := c.SaveConfig(cfg); saveErr != nil {
			return nil, fmt.Errorf("init server registry: clear old config targets: %w", saveErr)
		}

		if err := c.SaveServerRegistry(reg); err != nil {
			return nil, fmt.Errorf("init server registry: %w", err)
		}
		return reg, nil
	}

	// No config to migrate from — use defaults.
	reg := &ServerRegistry{Servers: DefaultServers()}
	if err := c.SaveServerRegistry(reg); err != nil {
		return nil, fmt.Errorf("init server registry: %w", err)
	}
	return reg, nil
}

// migrateFromConfig converts old publish_targets to a server registry,
// merging with defaults to include any well-known servers not in the config.
func migrateFromConfig(targets []PublishTarget) *ServerRegistry {
	defaults := DefaultServers()

	// Index defaults by URL (keyservers) and type (github).
	defaultByURL := make(map[string]*ServerEntry, len(defaults))
	var defaultGitHub *ServerEntry
	for i := range defaults {
		if defaults[i].Type == TargetTypeGitHub {
			defaultGitHub = &defaults[i]
		} else {
			defaultByURL[defaults[i].URL] = &defaults[i]
		}
	}

	var servers []ServerEntry
	seen := make(map[string]bool)

	for _, t := range targets {
		if t.Type == TargetTypeGitHub {
			if defaultGitHub != nil {
				entry := *defaultGitHub
				entry.Enabled = true // was configured, so enable it
				servers = append(servers, entry)
				seen["github"] = true
			}
			continue
		}
		if t.URL == "" {
			continue
		}
		seen[t.URL] = true
		if def, ok := defaultByURL[t.URL]; ok {
			entry := *def
			entry.Enabled = true // was configured, so enable it
			servers = append(servers, entry)
		} else {
			servers = append(servers, ServerEntry{
				Alias:   aliasFromURL(t.URL),
				Type:    t.Type,
				URL:     t.URL,
				Enabled: true,
			})
		}
	}

	// Add remaining defaults that weren't in config (disabled, since user didn't configure them).
	for i := range defaults {
		key := defaults[i].URL
		if defaults[i].Type == TargetTypeGitHub {
			key = "github"
		}
		if !seen[key] {
			entry := defaults[i]
			entry.Enabled = false
			servers = append(servers, entry)
		}
	}

	return &ServerRegistry{Servers: servers}
}

// aliasFromURL generates an alias from a keyserver URL by extracting the hostname
// and using the first label before the first dot.
func aliasFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	host := u.Hostname()
	if idx := strings.IndexByte(host, '.'); idx > 0 {
		return host[:idx]
	}
	return host
}

// FindByAlias returns a pointer to the server entry with the given alias, or nil.
func (reg *ServerRegistry) FindByAlias(alias string) *ServerEntry {
	for i := range reg.Servers {
		if reg.Servers[i].Alias == alias {
			return &reg.Servers[i]
		}
	}
	return nil
}

// EnabledServers returns all servers with Enabled == true.
func (reg *ServerRegistry) EnabledServers() []ServerEntry {
	var out []ServerEntry
	for i := range reg.Servers {
		if reg.Servers[i].Enabled {
			out = append(out, reg.Servers[i])
		}
	}
	return out
}

// ToPublishTargets converts server entries to PublishTarget slice for use with Publish().
func ToPublishTargets(entries []ServerEntry) []PublishTarget {
	targets := make([]PublishTarget, 0, len(entries))
	for i := range entries {
		targets = append(targets, PublishTarget{
			Type: entries[i].Type,
			URL:  entries[i].URL,
		})
	}
	return targets
}

// AllServerURLs returns all unique keyserver URLs from the registry.
func (reg *ServerRegistry) AllServerURLs() []string {
	var urls []string
	for i := range reg.Servers {
		if reg.Servers[i].Type == TargetTypeKeyserver && reg.Servers[i].URL != "" {
			urls = append(urls, reg.Servers[i].URL)
		}
	}
	return urls
}

// ValidateServerAlias checks that an alias is non-empty and contains only
// lowercase letters, digits, and hyphens.
func ValidateServerAlias(alias string) error {
	if alias == "" {
		return fmt.Errorf("alias cannot be empty")
	}
	for _, r := range alias {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("alias %q contains invalid character %q (use lowercase letters, digits, hyphens)", alias, string(r))
		}
	}
	return nil
}
