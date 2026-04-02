package gpgsmith

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type (
	// sessionRC holds the temporary rc file/dir paths for a shell session.
	sessionRC struct {
		// args are extra shell arguments (e.g., --rcfile for bash).
		args []string
		// envs are extra environment variables (e.g., ZDOTDIR for zsh).
		envs []string
		// cleanup removes temporary files.
		cleanup func()
	}
)

// isTerminal returns true if stdin is connected to a terminal.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// promptLine prints a prompt to stderr and reads a line from stdin.
func promptLine(prompt string) (string, error) {
	return promptLineFrom(prompt, os.Stdin)
}

// promptLineFrom reads a line from the given reader after printing a prompt.
func promptLineFrom(prompt string, r *os.File) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no input")
	}

	return strings.TrimSpace(scanner.Text()), nil
}

// newSessionRC creates shell-specific configuration to prepend "(gpgsmith) "
// to the prompt after the user's rc file loads.
func newSessionRC(shell string) *sessionRC {
	base := filepath.Base(shell)
	switch base {
	case "bash":
		return bashSessionRC()
	case "zsh":
		return zshSessionRC()
	default:
		return &sessionRC{cleanup: func() {}}
	}
}

func bashSessionRC() *sessionRC {
	content := "if [ -f ~/.bashrc ]; then . ~/.bashrc; fi\nPS1=\"(gpgsmith) $PS1\"\n"
	f, err := os.CreateTemp("", "gpgsmith-rc-*")
	if err != nil {
		return &sessionRC{cleanup: func() {}}
	}

	_, writeErr := f.WriteString(content)
	closeErr := f.Close()

	if writeErr != nil || closeErr != nil {
		_ = os.Remove(f.Name())
		return &sessionRC{cleanup: func() {}}
	}

	name := f.Name()
	return &sessionRC{
		args:    []string{"--rcfile", name},
		cleanup: func() { _ = os.Remove(name) },
	}
}

func zshSessionRC() *sessionRC {
	home := os.Getenv("HOME")
	dir, err := os.MkdirTemp("", "gpgsmith-zdotdir-*")
	if err != nil {
		return &sessionRC{cleanup: func() {}}
	}

	escaped := shellEscapeSingleQuote(home)
	content := fmt.Sprintf("if [ -f '%s/.zshrc' ]; then . '%s/.zshrc'; fi\nPS1=\"(gpgsmith) $PS1\"\n", escaped, escaped)
	if err := os.WriteFile(filepath.Join(dir, ".zshrc"), []byte(content), 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return &sessionRC{cleanup: func() {}}
	}

	return &sessionRC{
		envs:    []string{"ZDOTDIR=" + dir},
		cleanup: func() { _ = os.RemoveAll(dir) },
	}
}

// shellEscapeSingleQuote escapes a string for safe use inside single quotes.
// Single quotes in the input are replaced with '\" (end quote, escaped quote, start quote).
func shellEscapeSingleQuote(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}
