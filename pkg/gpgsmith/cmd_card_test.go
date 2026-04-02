package gpgsmith

import (
	"os"
	"testing"

	"github.com/urfave/cli/v3"
)

func TestCardDiscoverCmdExists(t *testing.T) {
	cmd := cardCmd()

	var discover *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "discover" {
			discover = c
			break
		}
	}
	if discover == nil {
		t.Fatal("discover subcommand not found")
	}
	if discover.Action == nil {
		t.Error("discover subcommand has no action")
	}
}

func TestPromptLineFrom(t *testing.T) {
	t.Run("reads line", func(t *testing.T) {
		f := writeTempFile(t, "my-yubikey\n")
		defer f.Close()

		got, err := promptLineFrom("Label: ", f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "my-yubikey" {
			t.Errorf("got %q, want %q", got, "my-yubikey")
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		f := writeTempFile(t, "  spaced  \n")
		defer f.Close()

		got, err := promptLineFrom("Label: ", f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "spaced" {
			t.Errorf("got %q, want %q", got, "spaced")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		f := writeTempFile(t, "\n")
		defer f.Close()

		got, err := promptLineFrom("Label: ", f)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})

	t.Run("no input EOF", func(t *testing.T) {
		f := writeTempFile(t, "")
		defer f.Close()

		_, err := promptLineFrom("Label: ", f)
		if err == nil {
			t.Fatal("expected error for EOF")
		}
	})
}

func writeTempFile(t *testing.T, content string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "input-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}
