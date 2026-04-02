package gpgsmith

import (
	"os"
	"strings"
	"testing"
)

func TestNewSessionRCBash(t *testing.T) {
	rc := newSessionRC("/bin/bash")
	defer rc.cleanup()

	if len(rc.args) != 2 {
		t.Fatalf("expected 2 args, got %d: %v", len(rc.args), rc.args)
	}
	if rc.args[0] != "--rcfile" {
		t.Errorf("args[0] = %q, want %q", rc.args[0], "--rcfile")
	}

	// The rcfile should exist and contain the prompt override.
	data, err := os.ReadFile(rc.args[1])
	if err != nil {
		t.Fatalf("read rcfile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "(gpgsmith)") {
		t.Errorf("rcfile missing (gpgsmith) prompt indicator: %q", content)
	}
	if !strings.Contains(content, ".bashrc") {
		t.Errorf("rcfile should source .bashrc: %q", content)
	}

	// No extra env vars for bash.
	if len(rc.envs) != 0 {
		t.Errorf("expected 0 envs, got %d: %v", len(rc.envs), rc.envs)
	}
}

func TestNewSessionRCZsh(t *testing.T) {
	rc := newSessionRC("/bin/zsh")
	defer rc.cleanup()

	// Zsh uses ZDOTDIR env, not shell args.
	if len(rc.args) != 0 {
		t.Errorf("expected 0 args for zsh, got %d: %v", len(rc.args), rc.args)
	}
	if len(rc.envs) != 1 {
		t.Fatalf("expected 1 env for zsh, got %d: %v", len(rc.envs), rc.envs)
	}
	if !strings.HasPrefix(rc.envs[0], "ZDOTDIR=") {
		t.Errorf("env should start with ZDOTDIR=, got %q", rc.envs[0])
	}

	// The ZDOTDIR should contain a .zshrc with the prompt.
	zdotdir := strings.TrimPrefix(rc.envs[0], "ZDOTDIR=")
	data, err := os.ReadFile(zdotdir + "/.zshrc")
	if err != nil {
		t.Fatalf("read .zshrc: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "(gpgsmith)") {
		t.Errorf(".zshrc missing (gpgsmith) prompt indicator: %q", content)
	}
}

func TestNewSessionRCUnknown(t *testing.T) {
	rc := newSessionRC("/bin/sh")
	defer rc.cleanup()

	if len(rc.args) != 0 {
		t.Errorf("expected 0 args for unknown shell, got %d", len(rc.args))
	}
	if len(rc.envs) != 0 {
		t.Errorf("expected 0 envs for unknown shell, got %d", len(rc.envs))
	}
}

func TestNewSessionRCCleanup(t *testing.T) {
	rc := newSessionRC("/bin/bash")

	// Capture the temp file path before cleanup.
	if len(rc.args) < 2 {
		t.Fatal("expected rcfile path in args")
	}
	path := rc.args[1]

	// File should exist before cleanup.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("rcfile should exist before cleanup: %v", err)
	}

	rc.cleanup()

	// File should be removed after cleanup.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("rcfile should be removed after cleanup, got err: %v", err)
	}
}
