// Package audit provides shared, append-only audit logging stored as YAML.
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type (
	// Entry represents a single audit log entry.
	Entry struct {
		Timestamp time.Time         `yaml:"timestamp"`
		Action    string            `yaml:"action"`
		Details   string            `yaml:"details"`
		Metadata  map[string]string `yaml:"metadata,omitempty"`
	}

	// auditFile is the on-disk YAML structure.
	auditFile struct {
		Entries []Entry `yaml:"entries"`
	}
)

const (
	auditFilename = "gpgsmith-audit.yaml"
)

// Append adds an entry to the audit log in the given directory.
// If the audit file does not exist, it is created.
func Append(dir string, entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	entries, err := Load(dir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("audit append: load existing: %w", err)
	}

	entries = append(entries, entry)

	af := auditFile{Entries: entries}
	data, err := yaml.Marshal(&af)
	if err != nil {
		return fmt.Errorf("audit append: marshal: %w", err)
	}

	path := filepath.Join(dir, auditFilename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("audit append: write %s: %w", path, err)
	}

	return nil
}

// Load reads all audit entries from the given directory.
// Returns an empty slice (not an error) if the audit file does not exist.
func Load(dir string) ([]Entry, error) {
	path := filepath.Join(dir, auditFilename)

	data, err := os.ReadFile(path) //nolint:gosec // path built from known dir + constant filename
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit load: read %s: %w", path, err)
	}

	var af auditFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return nil, fmt.Errorf("audit load: parse %s: %w", path, err)
	}

	return af.Entries, nil
}
