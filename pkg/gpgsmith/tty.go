package gpgsmith

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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
