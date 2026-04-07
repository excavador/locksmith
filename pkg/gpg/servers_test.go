package gpg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerRegistrySaveLoad(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	reg := &ServerRegistry{
		Servers: []ServerEntry{
			{Alias: "openpgp", Type: "keyserver", URL: "hkps://keys.openpgp.org", Enabled: true},
			{Alias: "github", Type: "github", Enabled: false},
		},
	}

	if err := client.SaveServerRegistry(reg); err != nil {
		t.Fatalf("SaveServerRegistry() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "gpgsmith-servers.yaml")); err != nil {
		t.Fatalf("servers file not created: %v", err)
	}

	loaded, err := client.LoadServerRegistry()
	if err != nil {
		t.Fatalf("LoadServerRegistry() error: %v", err)
	}

	if len(loaded.Servers) != 2 {
		t.Fatalf("Servers len = %d, want 2", len(loaded.Servers))
	}
	if loaded.Servers[0].Alias != "openpgp" {
		t.Errorf("Alias = %q, want %q", loaded.Servers[0].Alias, "openpgp")
	}
	if !loaded.Servers[0].Enabled {
		t.Error("expected openpgp to be enabled")
	}
}

func TestLoadServerRegistryDefaults(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		t.Fatalf("LoadServerRegistry() error: %v", err)
	}

	defaults := DefaultServers()
	if len(reg.Servers) != len(defaults) {
		t.Fatalf("Servers len = %d, want %d", len(reg.Servers), len(defaults))
	}

	// File should have been created.
	if _, err := os.Stat(filepath.Join(dir, "gpgsmith-servers.yaml")); err != nil {
		t.Fatalf("servers file not auto-created: %v", err)
	}
}

func TestLoadServerRegistryMigration(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	// Write a config with publish_targets.
	cfg := &Config{
		MasterFP:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		SubkeyAlgo:   "rsa4096",
		SubkeyExpiry: "2y",
		PublishTargets: []PublishTarget{
			{Type: "keyserver", URL: "hkps://keys.openpgp.org"},
			{Type: "keyserver", URL: "hkps://custom.example.com"},
			{Type: "github"},
		},
	}
	if err := client.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error: %v", err)
	}

	reg, err := client.LoadServerRegistry()
	if err != nil {
		t.Fatalf("LoadServerRegistry() error: %v", err)
	}

	// Should include: migrated targets (enabled) + remaining defaults (disabled).
	openpgp := reg.FindByAlias("openpgp")
	if openpgp == nil {
		t.Fatal("missing openpgp after migration")
	}
	if !openpgp.Enabled {
		t.Error("openpgp should be enabled (was in config)")
	}

	github := reg.FindByAlias("github")
	if github == nil {
		t.Fatal("missing github after migration")
	}
	if !github.Enabled {
		t.Error("github should be enabled (was in config)")
	}

	// Custom server should be migrated with auto-generated alias.
	custom := reg.FindByAlias("custom")
	if custom == nil {
		t.Fatal("missing custom server after migration")
	}
	if custom.URL != "hkps://custom.example.com" {
		t.Errorf("custom URL = %q, want %q", custom.URL, "hkps://custom.example.com")
	}
	if !custom.Enabled {
		t.Error("custom should be enabled (was in config)")
	}

	// Ubuntu should be present but disabled (not in config).
	ubuntu := reg.FindByAlias("ubuntu")
	if ubuntu == nil {
		t.Fatal("missing ubuntu default after migration")
	}
	if ubuntu.Enabled {
		t.Error("ubuntu should be disabled (not in config)")
	}

	// Config should have publish_targets cleared.
	reloadedCfg, err := client.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}
	if len(reloadedCfg.PublishTargets) != 0 {
		t.Errorf("publish_targets should be cleared after migration, got %d", len(reloadedCfg.PublishTargets))
	}
}

func TestFindByAlias(t *testing.T) {
	reg := &ServerRegistry{
		Servers: []ServerEntry{
			{Alias: "openpgp", Type: "keyserver", URL: "hkps://keys.openpgp.org", Enabled: true},
			{Alias: "github", Type: "github", Enabled: false},
		},
	}

	found := reg.FindByAlias("openpgp")
	if found == nil {
		t.Fatal("FindByAlias(\"openpgp\") returned nil")
	}
	if found.URL != "hkps://keys.openpgp.org" {
		t.Errorf("URL = %q, want %q", found.URL, "hkps://keys.openpgp.org")
	}

	found = reg.FindByAlias("github")
	if found == nil {
		t.Fatal("FindByAlias(\"github\") returned nil")
	}

	if reg.FindByAlias("nonexistent") != nil {
		t.Error("FindByAlias(\"nonexistent\") should return nil")
	}
}

func TestEnabledServers(t *testing.T) {
	reg := &ServerRegistry{
		Servers: []ServerEntry{
			{Alias: "openpgp", Type: "keyserver", Enabled: true},
			{Alias: "ubuntu", Type: "keyserver", Enabled: true},
			{Alias: "github", Type: "github", Enabled: false},
			{Alias: "mit", Type: "keyserver", Enabled: false},
		},
	}

	enabled := reg.EnabledServers()
	if len(enabled) != 2 {
		t.Fatalf("EnabledServers len = %d, want 2", len(enabled))
	}
	if enabled[0].Alias != "openpgp" {
		t.Errorf("enabled[0].Alias = %q, want %q", enabled[0].Alias, "openpgp")
	}
	if enabled[1].Alias != "ubuntu" {
		t.Errorf("enabled[1].Alias = %q, want %q", enabled[1].Alias, "ubuntu")
	}
}

func TestToPublishTargets(t *testing.T) {
	entries := []ServerEntry{
		{Alias: "openpgp", Type: "keyserver", URL: "hkps://keys.openpgp.org"},
		{Alias: "github", Type: "github"},
	}

	targets := ToPublishTargets(entries)
	if len(targets) != 2 {
		t.Fatalf("targets len = %d, want 2", len(targets))
	}
	if targets[0].Type != "keyserver" || targets[0].URL != "hkps://keys.openpgp.org" {
		t.Errorf("targets[0] = %+v", targets[0])
	}
	if targets[1].Type != "github" {
		t.Errorf("targets[1].Type = %q, want %q", targets[1].Type, "github")
	}
}

func TestAllServerURLs(t *testing.T) {
	reg := &ServerRegistry{
		Servers: []ServerEntry{
			{Alias: "openpgp", Type: "keyserver", URL: "hkps://keys.openpgp.org", Enabled: true},
			{Alias: "github", Type: "github", Enabled: true},
			{Alias: "mit", Type: "keyserver", URL: "hkps://pgp.mit.edu", Enabled: false},
		},
	}

	urls := reg.AllServerURLs()
	if len(urls) != 2 {
		t.Fatalf("AllServerURLs len = %d, want 2", len(urls))
	}
}

func TestValidateServerAlias(t *testing.T) {
	tests := []struct {
		alias string
		valid bool
	}{
		{"openpgp", true},
		{"my-server", true},
		{"server1", true},
		{"", false},
		{"UPPER", false},
		{"has space", false},
		{"has_underscore", false},
	}

	for _, tt := range tests {
		err := ValidateServerAlias(tt.alias)
		if tt.valid && err != nil {
			t.Errorf("ValidateServerAlias(%q) unexpected error: %v", tt.alias, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateServerAlias(%q) expected error, got nil", tt.alias)
		}
	}
}

func TestAliasFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"hkps://keys.openpgp.org", "keys"},
		{"hkps://keyserver.ubuntu.com", "keyserver"},
		{"hkps://pgp.mit.edu", "pgp"},
		{"hkps://localhost", "localhost"},
	}

	for _, tt := range tests {
		got := aliasFromURL(tt.url)
		if got != tt.want {
			t.Errorf("aliasFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}
