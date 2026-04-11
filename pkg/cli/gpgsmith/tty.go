package gpgsmith

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// promptLine prints a prompt to stderr and reads a line from stdin.
func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no input")
	}

	return strings.TrimSpace(scanner.Text()), nil
}

// readPassphrase prints a prompt and reads a passphrase from stdin with
// local echo disabled. Returns an error if the passphrase is empty.
func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd()) //nolint:gosec // stdin fd is always within int range
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return "", fmt.Errorf("passphrase cannot be empty")
	}
	return string(pass), nil
}

// readPassphraseWithConfirm prompts the user twice and returns the
// passphrase if both inputs match.
func readPassphraseWithConfirm() (string, error) {
	pass, err := readPassphrase("Vault passphrase: ")
	if err != nil {
		return "", err
	}
	confirm, err := readPassphrase("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}
