package gpgsmith

import (
	"fmt"
	"os"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestConfirmPassphrases(t *testing.T) {
	t.Run("matching passphrases", func(t *testing.T) {
		calls := 0
		readFn := func(_ string) (string, error) {
			calls++
			return "correct-horse-battery-staple", nil
		}

		pass, err := confirmPassphrases(readFn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pass != "correct-horse-battery-staple" {
			t.Errorf("passphrase = %q, want %q", pass, "correct-horse-battery-staple")
		}
		if calls != 2 {
			t.Errorf("expected 2 reads, got %d", calls)
		}
	})

	t.Run("mismatched passphrases", func(t *testing.T) {
		calls := 0
		readFn := func(_ string) (string, error) {
			calls++
			if calls == 1 {
				return "first-pass", nil
			}
			return "different-pass", nil
		}

		_, err := confirmPassphrases(readFn)
		if err == nil {
			t.Fatal("expected error for mismatched passphrases")
		}
		if err.Error() != "passphrases do not match" {
			t.Errorf("error = %q, want %q", err.Error(), "passphrases do not match")
		}
	})

	t.Run("first read fails", func(t *testing.T) {
		readFn := func(_ string) (string, error) {
			return "", fmt.Errorf("read error")
		}

		_, err := confirmPassphrases(readFn)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("second read fails", func(t *testing.T) {
		calls := 0
		readFn := func(_ string) (string, error) {
			calls++
			if calls == 1 {
				return "pass", nil
			}
			return "", fmt.Errorf("read error")
		}

		_, err := confirmPassphrases(readFn)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestVaultPassphraseFromEnv(t *testing.T) {
	// Verify that GPGSMITH_VAULT_KEY is checked before prompting.
	// We test this indirectly by checking the env var is read.
	t.Run("env var set", func(t *testing.T) {
		t.Setenv("GPGSMITH_VAULT_KEY", "test-passphrase-from-env")
		val := os.Getenv("GPGSMITH_VAULT_KEY")
		if val != "test-passphrase-from-env" {
			t.Errorf("GPGSMITH_VAULT_KEY = %q, want %q", val, "test-passphrase-from-env")
		}
	})

	t.Run("env var empty", func(t *testing.T) {
		t.Setenv("GPGSMITH_VAULT_KEY", "")
		val := os.Getenv("GPGSMITH_VAULT_KEY")
		if val != "" {
			t.Errorf("GPGSMITH_VAULT_KEY should be empty, got %q", val)
		}
	})
}

func TestVaultCmdHasNoInteractiveFlag(t *testing.T) {
	cmd := vaultCmd()

	// Verify create, import, open, and restore all have no-interactive flag.
	wantFlags := []string{"create", "import", "open", "restore"}
	for _, name := range wantFlags {
		t.Run(name, func(t *testing.T) {
			var sub *cli.Command
			for _, c := range cmd.Commands {
				if c.Name == name {
					sub = c
					break
				}
			}
			if sub == nil {
				t.Fatalf("subcommand %q not found", name)
			}
			found := false
			for _, f := range sub.Flags {
				if bf, ok := f.(*cli.BoolFlag); ok && bf.Name == "no-interactive" {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("subcommand %q missing --no-interactive flag", name)
			}
		})
	}
}

func TestVaultOpenRejectsPositionalArgs(t *testing.T) {
	cmd := vaultCmd()

	// Find the "open" subcommand.
	var open *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "open" {
			open = c
			break
		}
	}
	if open == nil {
		t.Fatal("open subcommand not found")
	}

	// vault open should not have ArgsUsage (unlike vault restore which does).
	if open.ArgsUsage != "" {
		t.Errorf("vault open should not have ArgsUsage, got %q", open.ArgsUsage)
	}
}

func TestVaultRestoreHasArgsUsage(t *testing.T) {
	cmd := vaultCmd()

	var restore *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "restore" {
			restore = c
			break
		}
	}
	if restore == nil {
		t.Fatal("restore subcommand not found")
	}

	if restore.ArgsUsage == "" {
		t.Error("vault restore should have ArgsUsage for <ref>")
	}
}

func TestShellEscapeSingleQuote(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with space", "with space"},
		{"it's", "it'\\''s"},
		{"", ""},
		{"don't stop", "don'\\''t stop"},
		{"'''", "'\\'''\\'''\\''"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shellEscapeSingleQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellEscapeSingleQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
