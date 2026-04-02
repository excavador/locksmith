package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendAndLoad(t *testing.T) {
	dir := t.TempDir()

	entry1 := Entry{
		Timestamp: time.Date(2026, 1, 1, 14, 0, 0, 0, time.UTC),
		Action:    "generate-subkeys",
		Details:   "S/E/A rsa4096 expires 2027-12-31",
		Metadata: map[string]string{
			"subkeys": "0x886F,0x7958,0x5711",
		},
	}

	if err := Append(dir, entry1); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	entries, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Action != "generate-subkeys" {
		t.Errorf("action = %q, want %q", entries[0].Action, "generate-subkeys")
	}
	if entries[0].Details != "S/E/A rsa4096 expires 2027-12-31" {
		t.Errorf("details = %q, want %q", entries[0].Details, "S/E/A rsa4096 expires 2027-12-31")
	}
	if entries[0].Metadata["subkeys"] != "0x886F,0x7958,0x5711" {
		t.Errorf("metadata[subkeys] = %q, want %q", entries[0].Metadata["subkeys"], "0x886F,0x7958,0x5711")
	}

	// Append a second entry
	entry2 := Entry{
		Timestamp: time.Date(2026, 1, 1, 14, 30, 0, 0, time.UTC),
		Action:    "to-card",
		Details:   "moved subkeys to YubiKey",
		Metadata: map[string]string{
			"serial": "12345678",
			"mode":   "same-keys",
		},
	}

	if err := Append(dir, entry2); err != nil {
		t.Fatalf("Append() second entry error: %v", err)
	}

	entries, err = Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[1].Action != "to-card" {
		t.Errorf("second entry action = %q, want %q", entries[1].Action, "to-card")
	}
}

func TestLoadEmptyDir(t *testing.T) {
	dir := t.TempDir()

	entries, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(entries))
	}
}

func TestAppendAutoTimestamp(t *testing.T) {
	dir := t.TempDir()

	before := time.Now().UTC()
	entry := Entry{
		Action:  "test-action",
		Details: "auto timestamp",
	}
	if err := Append(dir, entry); err != nil {
		t.Fatalf("Append() error: %v", err)
	}
	after := time.Now().UTC()

	entries, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	ts := entries[0].Timestamp
	if ts.Before(before) || ts.After(after) {
		t.Errorf("auto timestamp %v not between %v and %v", ts, before, after)
	}
}

func TestAppendNoMetadata(t *testing.T) {
	dir := t.TempDir()

	entry := Entry{
		Timestamp: time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC),
		Action:    "revoke-card",
		Details:   "YubiKey lost",
	}
	if err := Append(dir, entry); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	entries, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Metadata != nil {
		t.Errorf("expected nil metadata, got %v", entries[0].Metadata)
	}
}

func TestSequentialAppendPreservesAll(t *testing.T) {
	// Append is designed for single-threaded CLI use (one user inside an
	// encrypted vault session). This test verifies that sequential appends
	// preserve all entries and maintain a valid YAML file.
	dir := t.TempDir()

	const n = 20
	for i := range n {
		entry := Entry{
			Action:  fmt.Sprintf("action-%d", i),
			Details: fmt.Sprintf("sequential entry %d", i),
		}
		if err := Append(dir, entry); err != nil {
			t.Fatalf("Append(%d) error: %v", i, err)
		}
	}

	entries, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(entries) != n {
		t.Errorf("expected %d entries, got %d", n, len(entries))
	}

	// Verify ordering is preserved.
	for i, e := range entries {
		want := fmt.Sprintf("action-%d", i)
		if e.Action != want {
			t.Errorf("entry %d action = %q, want %q", i, e.Action, want)
		}
	}
}

func TestLoadCorruptedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gpgsmith-audit.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml: {{{"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() should fail with corrupted YAML")
	}
}

func TestAuditFileFormat(t *testing.T) {
	dir := t.TempDir()

	entry := Entry{
		Timestamp: time.Date(2026, 4, 1, 15, 0, 0, 0, time.UTC),
		Action:    "generate-subkeys",
		Details:   "test",
	}
	if err := Append(dir, entry); err != nil {
		t.Fatalf("Append() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "gpgsmith-audit.yaml"))
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Fatal("audit file is empty")
	}
	// Should be valid YAML with entries key
	if content[:8] != "entries:" {
		t.Errorf("audit file should start with 'entries:', got %q", content[:8])
	}
}
