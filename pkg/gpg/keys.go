package gpg

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type (
	// SubKey represents a GPG key or subkey parsed from --with-colons output.
	SubKey struct {
		KeyID       string
		Fingerprint string
		Algorithm   string
		Usage       string // S, E, A, C (may be combined like "SC")
		Created     time.Time
		Expires     time.Time
		CardSerial  string
	}

	// CardInfo holds information from gpg --card-status.
	CardInfo struct {
		Serial     string
		Model      string
		ReaderName string   // raw Reader field from card-status
		KeyIDs     []string // key grip or key IDs on the card
	}
)

// ListKeys returns all keys and subkeys in the keyring.
func (c *Client) ListKeys(ctx context.Context) ([]SubKey, error) {
	out, err := c.exec(ctx, "--with-colons", "--fixed-list-mode", "--list-keys")
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	return parseColonsOutput(string(out))
}

// ListSecretKeys returns all secret keys and subkeys in the keyring.
func (c *Client) ListSecretKeys(ctx context.Context) ([]SubKey, error) {
	out, err := c.exec(ctx, "--with-colons", "--fixed-list-mode", "--list-secret-keys")
	if err != nil {
		return nil, fmt.Errorf("list secret keys: %w", err)
	}

	return parseColonsOutput(string(out))
}

// CardStatus queries the connected smart card and returns its info.
func (c *Client) CardStatus(ctx context.Context) (*CardInfo, error) {
	out, err := c.exec(ctx, "--card-status", "--with-colons")
	if err != nil {
		return nil, fmt.Errorf("card status: %w", err)
	}

	return parseCardStatus(string(out))
}

// parseColonsOutput parses gpg --with-colons output into SubKey records.
// See https://github.com/gpg/gnupg/blob/master/doc/DETAILS for field definitions.
//
// Record types we care about:
//
//	pub/sec — primary key
//	sub/ssb — subkey
//	fpr     — fingerprint (follows pub/sub record)
//
// Colon fields (0-indexed):
//
//	0:  record type
//	1:  validity
//	2:  key length
//	3:  algorithm number
//	4:  key ID (long)
//	5:  creation date (seconds since epoch)
//	6:  expiration date (seconds since epoch, empty = no expiry)
//	8:  trust info / serial number
//	9:  fingerprint (in fpr records)
//	11: capabilities (in pub/sub records)
//	14: card serial (in ssb records, if key is on card)
func parseColonsOutput(output string) ([]SubKey, error) {
	var keys []SubKey
	var current *SubKey

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")

		recType := fields[0]
		switch recType {
		case "pub", "sec", "sub", "ssb":
			if len(fields) < 12 {
				continue
			}
			k := SubKey{
				KeyID:     fields[4],
				Algorithm: algoName(fields[3]),
				Usage:     parseUsage(recType, fields[11]),
			}
			if fields[5] != "" {
				k.Created = parseEpoch(fields[5])
			}
			if fields[6] != "" {
				k.Expires = parseEpoch(fields[6])
			}
			if len(fields) > 14 && fields[14] != "" {
				k.CardSerial = fields[14]
			}
			keys = append(keys, k)
			current = &keys[len(keys)-1]

		case "fpr":
			if current != nil && len(fields) > 9 {
				current.Fingerprint = fields[9]
			}
		}
	}

	return keys, nil
}

// parseCardStatus extracts card info from gpg --card-status --with-colons output.
func parseCardStatus(output string) (*CardInfo, error) {
	info := &CardInfo{}

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")

		switch {
		case fields[0] == "Reader" && len(fields) > 1:
			info.ReaderName = fields[1]
		case fields[0] == "serial" && len(fields) > 1:
			info.Serial = fields[1]
		case fields[0] == "cardtype" && len(fields) > 1:
			info.Model = fields[1]
		case fields[0] == "fpr" && len(fields) > 1:
			// Card fingerprints for S/E/A slots
			for _, f := range fields[1:] {
				if f != "" {
					info.KeyIDs = append(info.KeyIDs, f)
				}
			}
		}
	}

	// Fall back to extracting model from the Reader name if cardtype is not set.
	if info.Model == "" && info.ReaderName != "" {
		info.Model = extractModelFromReader(info.ReaderName)
	}

	if info.Serial == "" {
		return nil, fmt.Errorf("card status: no card detected or no serial found")
	}

	return info, nil
}

// parseUsage extracts the relevant usage letters from the capabilities field.
// For primary keys (pub/sec), we extract only the lowercase letters which represent
// the key's own capabilities. For subkeys (sub/ssb), we use the full field as-is
// since it only contains the subkey's own capabilities.
func parseUsage(recType, caps string) string {
	switch recType {
	case "pub", "sec":
		// Primary keys: extract lowercase letters only (key's own capabilities).
		var b strings.Builder
		for _, r := range caps {
			if r >= 'a' && r <= 'z' {
				b.WriteRune(r)
			}
		}
		return strings.ToUpper(b.String())
	default:
		return caps
	}
}

// extractModelFromReader extracts a card model name from the Reader field.
// Reader lines look like "Yubico YubiKey OTP FIDO CCID 00 00".
// We strip trailing interface descriptors (OTP, FIDO, CCID) and slot numbers.
func extractModelFromReader(reader string) string {
	reader = strings.TrimSpace(reader)

	// Remove trailing slot numbers like "00 00".
	reader = strings.TrimRight(reader, "0123456789 ")

	// Remove known interface descriptors.
	for _, suffix := range []string{"CCID", "FIDO", "OTP", "U2F"} {
		reader = strings.TrimSuffix(reader, suffix)
		reader = strings.TrimRight(reader, " ")
	}

	return strings.TrimSpace(reader)
}

// parseEpoch converts a Unix epoch string to time.Time.
func parseEpoch(s string) time.Time {
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// algoName maps GPG algorithm numbers to human-readable names.
func algoName(num string) string {
	switch num {
	case "1":
		return "rsa"
	case "17":
		return "dsa"
	case "18":
		return "ecdh"
	case "19":
		return "ecdsa"
	case "22":
		return "ed25519"
	case "25":
		return "x25519"
	default:
		return "algo-" + num
	}
}
