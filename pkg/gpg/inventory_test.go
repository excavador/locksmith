package gpg

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInventorySaveLoad(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	inv := &Inventory{
		YubiKeys: []YubiKeyEntry{
			{
				Serial:       "12345678",
				Label:        "green",
				Model:        "YubiKey 5 NFC",
				Description:  "on keychain",
				Provisioning: "same-keys",
				Subkeys: []SubKeyRef{
					{KeyID: "886F425C412784FD", Usage: "sign", Created: time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)},
				},
				ProvisionedAt: time.Date(2025, 12, 31, 14, 30, 0, 0, time.UTC),
				Status:        "active",
			},
		},
	}

	if err := client.SaveInventory(inv); err != nil {
		t.Fatalf("SaveInventory() error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "gpgsmith-inventory.yaml")); err != nil {
		t.Fatalf("inventory file not created: %v", err)
	}

	loaded, err := client.LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error: %v", err)
	}

	if len(loaded.YubiKeys) != 1 {
		t.Fatalf("YubiKeys len = %d, want 1", len(loaded.YubiKeys))
	}
	yk := loaded.YubiKeys[0]
	if yk.Serial != "12345678" {
		t.Errorf("Serial = %q, want %q", yk.Serial, "12345678")
	}
	if yk.Label != "green" {
		t.Errorf("Label = %q, want %q", yk.Label, "green")
	}
	if yk.Status != "active" {
		t.Errorf("Status = %q, want %q", yk.Status, "active")
	}
	if len(yk.Subkeys) != 1 {
		t.Fatalf("Subkeys len = %d, want 1", len(yk.Subkeys))
	}
}

func TestLoadInventoryEmpty(t *testing.T) {
	dir := t.TempDir()
	client, err := New(Options{HomeDir: dir})
	if err != nil {
		t.Fatal(err)
	}

	inv, err := client.LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error: %v", err)
	}
	if len(inv.YubiKeys) != 0 {
		t.Errorf("expected 0 YubiKeys, got %d", len(inv.YubiKeys))
	}
}

func TestFindByLabel(t *testing.T) {
	inv := &Inventory{
		YubiKeys: []YubiKeyEntry{
			{Serial: "11111111", Label: "green", Status: "active"},
			{Serial: "22222222", Label: "spare", Status: "active"},
		},
	}

	// Find by label.
	found := inv.FindByLabel("green")
	if found == nil {
		t.Fatal("FindByLabel(\"green\") returned nil")
	}
	if found.Serial != "11111111" {
		t.Errorf("Serial = %q, want %q", found.Serial, "11111111")
	}

	// Find by serial.
	found = inv.FindByLabel("22222222")
	if found == nil {
		t.Fatal("FindByLabel(\"22222222\") returned nil")
	}
	if found.Label != "spare" {
		t.Errorf("Label = %q, want %q", found.Label, "spare")
	}

	// Serial takes priority over label.
	inv.YubiKeys = append(inv.YubiKeys, YubiKeyEntry{Serial: "green", Label: "conflict", Status: "active"})
	found = inv.FindByLabel("green")
	if found == nil {
		t.Fatal("FindByLabel(\"green\") returned nil with serial conflict")
	}
	// Should match the entry with serial "green", not label "green".
	if found.Label != "conflict" {
		t.Errorf("serial should take priority: Label = %q, want %q", found.Label, "conflict")
	}

	// Not found.
	if inv.FindByLabel("nonexistent") != nil {
		t.Error("FindByLabel(\"nonexistent\") should return nil")
	}
}
