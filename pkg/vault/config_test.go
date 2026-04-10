package vault

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestResolveLegacyOnly verifies the legacy single-vault form still works.
func TestResolveLegacyOnly(t *testing.T) {
	cfg := &Config{
		VaultDir:  "/tmp/legacy-vault",
		Identity:  "/tmp/legacy.age",
		GPGBinary: "gpg2",
	}

	cases := []struct{ name, want string }{
		{"", LegacyDefaultName},
		{LegacyDefaultName, LegacyDefaultName},
	}
	for _, tc := range cases {
		entry, err := cfg.Resolve(tc.name)
		if err != nil {
			t.Fatalf("Resolve(%q) error: %v", tc.name, err)
		}
		if entry.Name != tc.want {
			t.Errorf("Resolve(%q).Name = %q, want %q", tc.name, entry.Name, tc.want)
		}
		if entry.Path != "/tmp/legacy-vault" {
			t.Errorf("Resolve(%q).Path = %q", tc.name, entry.Path)
		}
		if entry.Identity != "/tmp/legacy.age" {
			t.Errorf("Resolve(%q).Identity = %q", tc.name, entry.Identity)
		}
		if entry.GPGBinary != "gpg2" {
			t.Errorf("Resolve(%q).GPGBinary = %q", tc.name, entry.GPGBinary)
		}
	}

	if _, err := cfg.Resolve("nonexistent"); err == nil {
		t.Error("Resolve(nonexistent) should fail")
	}
}

// TestResolveRegistryOnly verifies the new vaults: form works on its own.
func TestResolveRegistryOnly(t *testing.T) {
	cfg := &Config{
		Vaults: []Entry{
			{Name: "personal", Path: "/p", Identity: "/p.age"},
			{Name: "work", Path: "/w"},
		},
		Default: "personal",
	}

	tests := []struct {
		query   string
		want    Entry
		wantErr bool
	}{
		{"", Entry{Name: "personal", Path: "/p", Identity: "/p.age"}, false},
		{"personal", Entry{Name: "personal", Path: "/p", Identity: "/p.age"}, false},
		{"work", Entry{Name: "work", Path: "/w"}, false},
		{"missing", Entry{}, true},
	}
	for _, tc := range tests {
		got, err := cfg.Resolve(tc.query)
		if tc.wantErr {
			if err == nil {
				t.Errorf("Resolve(%q) expected error, got %+v", tc.query, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Resolve(%q) error: %v", tc.query, err)
		}
		if !reflect.DeepEqual(*got, tc.want) {
			t.Errorf("Resolve(%q) = %+v, want %+v", tc.query, *got, tc.want)
		}
	}
}

// TestResolveTopLevelDefaults verifies that top-level Identity / GPGBinary
// fill in any per-entry blanks.
func TestResolveTopLevelDefaults(t *testing.T) {
	cfg := &Config{
		Identity:  "/default.age",
		GPGBinary: "gpg",
		Vaults: []Entry{
			{Name: "personal", Path: "/p"},                         // inherits both
			{Name: "work", Path: "/w", Identity: "/work-only.age"}, // overrides identity only
		},
	}

	personal, err := cfg.Resolve("personal")
	if err != nil {
		t.Fatalf("Resolve(personal): %v", err)
	}
	if personal.Identity != "/default.age" {
		t.Errorf("personal inherited Identity = %q, want /default.age", personal.Identity)
	}
	if personal.GPGBinary != "gpg" {
		t.Errorf("personal inherited GPGBinary = %q, want gpg", personal.GPGBinary)
	}

	work, err := cfg.Resolve("work")
	if err != nil {
		t.Fatalf("Resolve(work): %v", err)
	}
	if work.Identity != "/work-only.age" {
		t.Errorf("work overridden Identity = %q, want /work-only.age", work.Identity)
	}
	if work.GPGBinary != "gpg" {
		t.Errorf("work inherited GPGBinary = %q, want gpg", work.GPGBinary)
	}
}

// TestResolveBothFormsCoexist verifies that legacy + registry can coexist.
// The registry entries are explicit and should win on name collision.
func TestResolveBothFormsCoexist(t *testing.T) {
	cfg := &Config{
		VaultDir: "/tmp/legacy",
		Vaults: []Entry{
			{Name: "work", Path: "/w"},
		},
		Default: "work",
	}

	// Default points at work — should NOT fall through to legacy.
	entry, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve(): %v", err)
	}
	if entry.Name != "work" {
		t.Errorf("Resolve() = %q, want work (default override)", entry.Name)
	}

	// Explicit legacy lookup still works.
	legacy, err := cfg.Resolve(LegacyDefaultName)
	if err != nil {
		t.Fatalf("Resolve(default): %v", err)
	}
	if legacy.Path != "/tmp/legacy" {
		t.Errorf("Resolve(default).Path = %q, want /tmp/legacy", legacy.Path)
	}
}

// TestResolveBothFormsNoDefault verifies fallback when both forms are present
// but Default is empty: an empty query falls back to the legacy entry.
func TestResolveBothFormsNoDefault(t *testing.T) {
	cfg := &Config{
		VaultDir: "/tmp/legacy",
		Vaults: []Entry{
			{Name: "work", Path: "/w"},
		},
	}

	entry, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve(): %v", err)
	}
	if entry.Name != LegacyDefaultName {
		t.Errorf("Resolve() = %q, want %q", entry.Name, LegacyDefaultName)
	}
	if entry.Path != "/tmp/legacy" {
		t.Errorf("Resolve().Path = %q, want /tmp/legacy", entry.Path)
	}
}

// TestResolveEmptyConfig verifies a totally empty config returns an error.
func TestResolveEmptyConfig(t *testing.T) {
	cfg := &Config{}
	if _, err := cfg.Resolve(""); err == nil {
		t.Error("Resolve() on empty config should fail")
	}
	if _, err := cfg.Resolve("anything"); err == nil {
		t.Error("Resolve(anything) on empty config should fail")
	}
}

// TestVaultNames verifies the listing helper.
func TestVaultNames(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			name: "legacy only",
			cfg:  Config{VaultDir: "/tmp/legacy"},
			want: []string{LegacyDefaultName},
		},
		{
			name: "registry only",
			cfg: Config{
				Vaults: []Entry{
					{Name: "personal", Path: "/p"},
					{Name: "work", Path: "/w"},
				},
			},
			want: []string{"personal", "work"},
		},
		{
			name: "both",
			cfg: Config{
				VaultDir: "/tmp/legacy",
				Vaults: []Entry{
					{Name: "work", Path: "/w"},
				},
			},
			want: []string{"work", LegacyDefaultName},
		},
		{
			name: "empty",
			cfg:  Config{},
			want: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.VaultNames()
			gotCopy := append([]string{}, got...)
			wantCopy := append([]string{}, tc.want...)
			sort.Strings(gotCopy)
			sort.Strings(wantCopy)
			if !reflect.DeepEqual(gotCopy, wantCopy) {
				t.Errorf("VaultNames() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAddVault verifies the registry-add helper.
func TestAddVault(t *testing.T) {
	cfg := &Config{}

	// First add becomes default.
	if err := cfg.AddVault(Entry{Name: "personal", Path: "/p"}); err != nil {
		t.Fatalf("AddVault(personal): %v", err)
	}
	if cfg.Default != "personal" {
		t.Errorf("Default = %q, want personal", cfg.Default)
	}

	// Second add does not change the default.
	if err := cfg.AddVault(Entry{Name: "work", Path: "/w"}); err != nil {
		t.Fatalf("AddVault(work): %v", err)
	}
	if cfg.Default != "personal" {
		t.Errorf("Default = %q, want personal (unchanged)", cfg.Default)
	}

	// Duplicate name fails.
	if err := cfg.AddVault(Entry{Name: "personal", Path: "/x"}); err == nil {
		t.Error("AddVault duplicate name should fail")
	}

	// Missing fields fail.
	if err := cfg.AddVault(Entry{Path: "/x"}); err == nil {
		t.Error("AddVault missing name should fail")
	}
	if err := cfg.AddVault(Entry{Name: "x"}); err == nil {
		t.Error("AddVault missing path should fail")
	}
}

// TestAddVaultLegacyCollision verifies the synthetic-name collision guard.
func TestAddVaultLegacyCollision(t *testing.T) {
	cfg := &Config{VaultDir: "/tmp/legacy"}
	err := cfg.AddVault(Entry{Name: LegacyDefaultName, Path: "/x"})
	if err == nil {
		t.Errorf("expected collision error when adding %q with legacy vault_dir set", LegacyDefaultName)
	}
}

// TestLoadConfigLegacyForm verifies a YAML file written in the legacy form
// loads cleanly and resolves correctly.
func TestLoadConfigLegacyForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yamlBody := []byte("vault_dir: /tmp/old-vault\nidentity: /tmp/key.age\ngpg_binary: gpg2\n")
	if err := os.WriteFile(path, yamlBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.VaultDir != "/tmp/old-vault" {
		t.Errorf("VaultDir = %q", cfg.VaultDir)
	}
	if len(cfg.Vaults) != 0 {
		t.Errorf("Vaults should be empty for legacy form, got %d", len(cfg.Vaults))
	}

	entry, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if entry.Path != "/tmp/old-vault" {
		t.Errorf("entry.Path = %q", entry.Path)
	}
}

// TestLoadConfigRegistryForm verifies a YAML file written in the new form
// loads cleanly and resolves correctly.
func TestLoadConfigRegistryForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yamlBody := []byte(`vaults:
  - name: personal
    path: /tmp/personal-vault
    identity: /tmp/personal.age
  - name: work
    path: /tmp/work-vault
default: personal
`)
	if err := os.WriteFile(path, yamlBody, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Vaults) != 2 {
		t.Fatalf("Vaults len = %d, want 2", len(cfg.Vaults))
	}

	entry, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if entry.Name != "personal" || entry.Path != "/tmp/personal-vault" {
		t.Errorf("default entry = %+v", entry)
	}
}

// TestSaveLoadRoundtripRegistryForm verifies new-form configs roundtrip cleanly.
func TestSaveLoadRoundtripRegistryForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	original := &Config{
		Vaults: []Entry{
			{Name: "personal", Path: "/p", Identity: "/p.age"},
			{Name: "work", Path: "/w"},
		},
		Default: "personal",
	}
	if err := SaveConfig(path, original); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !reflect.DeepEqual(loaded.Vaults, original.Vaults) {
		t.Errorf("Vaults roundtrip mismatch: %+v vs %+v", loaded.Vaults, original.Vaults)
	}
	if loaded.Default != original.Default {
		t.Errorf("Default roundtrip mismatch: %q vs %q", loaded.Default, original.Default)
	}
}
