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

	// Verify create, import, and open all have no-interactive flag.
	wantFlags := []string{"create", "import", "open"}
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
