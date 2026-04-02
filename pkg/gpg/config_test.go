package gpg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigSaveLoad(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		MasterFP:     "6E1FD854CD2D225DDAED8EB7822B3952F976544E",
		SubkeyAlgo:   "ed25519",
		SubkeyExpiry: "1y",
		PublishTargets: []PublishTarget{
			{Type: "keyserver", URL: "hkps://keys.openpgp.org"},
			{Type: "github"},
		},
	}

	if err := client.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig() error: %v", err)
	}

	// Verify file exists.
	if _, err := os.Stat(filepath.Join(dir, "gpgsmith.yaml")); err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	loaded, err := client.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error: %v", err)
	}

	if loaded.MasterFP != cfg.MasterFP {
		t.Errorf("MasterFP = %q, want %q", loaded.MasterFP, cfg.MasterFP)
	}
	if loaded.SubkeyAlgo != cfg.SubkeyAlgo {
		t.Errorf("SubkeyAlgo = %q, want %q", loaded.SubkeyAlgo, cfg.SubkeyAlgo)
	}
	if loaded.SubkeyExpiry != cfg.SubkeyExpiry {
		t.Errorf("SubkeyExpiry = %q, want %q", loaded.SubkeyExpiry, cfg.SubkeyExpiry)
	}
	if len(loaded.PublishTargets) != 2 {
		t.Fatalf("PublishTargets len = %d, want 2", len(loaded.PublishTargets))
	}
	if loaded.PublishTargets[0].Type != "keyserver" {
		t.Errorf("PublishTargets[0].Type = %q, want %q", loaded.PublishTargets[0].Type, "keyserver")
	}
	if loaded.PublishTargets[0].URL != "hkps://keys.openpgp.org" {
		t.Errorf("PublishTargets[0].URL = %q, want %q", loaded.PublishTargets[0].URL, "hkps://keys.openpgp.org")
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.LoadConfig()
	if err == nil {
		t.Fatal("LoadConfig() should fail when config file does not exist")
	}
}
