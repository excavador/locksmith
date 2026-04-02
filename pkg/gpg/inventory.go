package gpg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type (
	// YubiKeyEntry represents a provisioned YubiKey in the inventory.
	YubiKeyEntry struct {
		Serial        string      `yaml:"serial"`
		Label         string      `yaml:"label"`
		Model         string      `yaml:"model"`
		Description   string      `yaml:"description,omitempty"`
		Provisioning  string      `yaml:"provisioning"` // "same-keys" or "unique-keys"
		Subkeys       []SubKeyRef `yaml:"subkeys,omitempty"`
		ProvisionedAt time.Time   `yaml:"provisioned_at"`
		Status        string      `yaml:"status"` // "active" or "revoked"
	}

	// SubKeyRef is a reference to a subkey stored on a YubiKey.
	SubKeyRef struct {
		KeyID   string    `yaml:"keyid"`
		Usage   string    `yaml:"usage"` // "sign", "encrypt", "auth"
		Created time.Time `yaml:"created"`
		Expires time.Time `yaml:"expires,omitempty"`
	}

	// Inventory holds all known YubiKeys.
	Inventory struct {
		YubiKeys []YubiKeyEntry `yaml:"yubikeys"`
	}
)

const (
	inventoryFilename = "gpgsmith-inventory.yaml"
)

// LoadInventory reads the YubiKey inventory from GNUPGHOME/gpgsmith-inventory.yaml.
func (c *Client) LoadInventory() (*Inventory, error) {
	path := filepath.Join(c.homeDir, inventoryFilename)

	data, err := os.ReadFile(path) //nolint:gosec // path built from homeDir + constant
	if err != nil {
		if os.IsNotExist(err) {
			return &Inventory{}, nil
		}
		return nil, fmt.Errorf("load inventory: read %s: %w", path, err)
	}

	var inv Inventory
	if err := yaml.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("load inventory: parse %s: %w", path, err)
	}

	return &inv, nil
}

// SaveInventory writes the YubiKey inventory to GNUPGHOME/gpgsmith-inventory.yaml.
func (c *Client) SaveInventory(inv *Inventory) error {
	data, err := yaml.Marshal(inv)
	if err != nil {
		return fmt.Errorf("save inventory: marshal: %w", err)
	}

	path := filepath.Join(c.homeDir, inventoryFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("save inventory: write %s: %w", path, err)
	}

	return nil
}

// DiscoverCard detects a connected YubiKey and returns an inventory entry.
// The entry is not automatically added to the inventory.
func (c *Client) DiscoverCard(ctx context.Context) (*YubiKeyEntry, error) {
	info, err := c.CardStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover card: %w", err)
	}

	if err := ValidateSerial(info.Serial); err != nil {
		return nil, fmt.Errorf("discover card: %w", err)
	}

	entry := &YubiKeyEntry{
		Serial:        info.Serial,
		Model:         info.Model,
		ProvisionedAt: time.Now().UTC(),
		Status:        "active",
	}

	// Match card fingerprints against keyring to populate subkey refs.
	keys, err := c.ListKeys(ctx)
	if err != nil {
		return entry, nil
	}

	for _, cardFP := range info.KeyIDs {
		for i := range keys {
			if keys[i].Fingerprint == cardFP {
				ref := SubKeyRef{
					KeyID:   keys[i].KeyID,
					Usage:   UsageLabel(keys[i].Usage),
					Created: keys[i].Created,
				}
				if !keys[i].Expires.IsZero() {
					ref.Expires = keys[i].Expires
				}
				entry.Subkeys = append(entry.Subkeys, ref)
				break
			}
		}
	}

	return entry, nil
}

// UsageLabel converts a usage code to a human-readable label.
func UsageLabel(usage string) string {
	switch strings.ToLower(usage) {
	case "s":
		return "sign"
	case "e":
		return "encrypt"
	case "a":
		return "auth"
	default:
		return usage
	}
}

// FindByLabel returns the YubiKey entry matching the given label or serial.
func (inv *Inventory) FindByLabel(labelOrSerial string) *YubiKeyEntry {
	// Try serial first, then label.
	for i := range inv.YubiKeys {
		if inv.YubiKeys[i].Serial == labelOrSerial {
			return &inv.YubiKeys[i]
		}
	}
	for i := range inv.YubiKeys {
		if inv.YubiKeys[i].Label == labelOrSerial {
			return &inv.YubiKeys[i]
		}
	}
	return nil
}
