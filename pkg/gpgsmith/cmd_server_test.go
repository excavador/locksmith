package gpgsmith

import (
	"testing"

	"github.com/urfave/cli/v3"
)

func TestServerCmdSubcommands(t *testing.T) {
	cmd := serverCmd()

	want := []string{"publish", "lookup", "list", "add", "remove", "enable", "disable"}
	got := make(map[string]bool)
	for _, c := range cmd.Commands {
		got[c.Name] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing subcommand %q", name)
		}
	}
}

func TestServerPublishCmdExists(t *testing.T) {
	cmd := serverCmd()

	var publish *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "publish" {
			publish = c
			break
		}
	}
	if publish == nil {
		t.Fatal("publish subcommand not found")
	}
	if publish.Action == nil {
		t.Error("publish subcommand has no action")
	}
	if publish.ArgsUsage != "[alias...]" {
		t.Errorf("publish ArgsUsage = %q, want %q", publish.ArgsUsage, "[alias...]")
	}
}

func TestServerAddCmdExists(t *testing.T) {
	cmd := serverCmd()

	var add *cli.Command
	for _, c := range cmd.Commands {
		if c.Name == "add" {
			add = c
			break
		}
	}
	if add == nil {
		t.Fatal("add subcommand not found")
	}
	if add.Action == nil {
		t.Error("add subcommand has no action")
	}
	if add.ArgsUsage != "<alias> <url>" {
		t.Errorf("add ArgsUsage = %q, want %q", add.ArgsUsage, "<alias> <url>")
	}
}
