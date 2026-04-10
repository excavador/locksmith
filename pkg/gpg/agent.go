package gpg

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteAgentConfig writes gpg.conf and gpg-agent.conf into homeDir to enable
// loopback pinentry mode. This bypasses pinentry entirely so the application
// can supply passphrases via --passphrase-fd, which works in any environment
// (TTY, non-TTY, container, CI). It also tunes gpg-agent's passphrase cache
// for typical interactive session lengths.
//
// Existing files are overwritten. Permissions are set to 0600.
func WriteAgentConfig(homeDir string) error {
	if homeDir == "" {
		return fmt.Errorf("write agent config: homeDir is required")
	}

	gpgConf := "pinentry-mode loopback\n"
	gpgAgentConf := "allow-loopback-pinentry\n" +
		"default-cache-ttl 3600\n" +
		"max-cache-ttl 28800\n"

	if err := os.WriteFile(filepath.Join(homeDir, "gpg.conf"), []byte(gpgConf), 0o600); err != nil {
		return fmt.Errorf("write gpg.conf: %w", err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, "gpg-agent.conf"), []byte(gpgAgentConf), 0o600); err != nil {
		return fmt.Errorf("write gpg-agent.conf: %w", err)
	}

	return nil
}
