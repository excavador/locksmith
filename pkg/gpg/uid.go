package gpg

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

type (
	// UID represents a user ID attached to a master key.
	UID struct {
		Index    int    // 1-based index in the order returned by gpg
		Validity string // validity field: "u" = ultimate, "r" = revoked, "e" = expired
		Created  time.Time
		Revoked  time.Time // zero unless the UID has been revoked
		Hash     string    // 40-char hex hash of the UID (gpg internal identifier)
		UID      string    // "Name (comment) <email>"
	}
)

// ListUIDs returns all user IDs on the master key identified by masterFP,
// in the order gpg reports them. Revoked UIDs are included.
//
// Uses --list-sigs (not --list-keys) so that revoked UIDs still have an
// associated creation date: gpg's colon output strips field 5 from a
// revoked uid record, but the original self-signature line that follows
// it still carries the date the UID was added. The companion rev: line
// (if present) carries the revocation date.
func (c *Client) ListUIDs(ctx context.Context, masterFP string) ([]UID, error) {
	if err := ValidateFingerprint(masterFP); err != nil {
		return nil, fmt.Errorf("list uids: %w", err)
	}

	out, err := c.exec(ctx, "--with-colons", "--fixed-list-mode", "--list-sigs", masterFP)
	if err != nil {
		return nil, fmt.Errorf("list uids: %w", err)
	}

	return parseUIDs(string(out)), nil
}

// parseUIDs extracts uid records from gpg --with-colons --list-sigs output.
//
// uid record fields (0-indexed):
//
//	0: "uid"
//	1: validity
//	5: creation date (epoch seconds; empty for revoked UIDs)
//	6: expiration date (epoch seconds, may be empty)
//	7: uid hash (40 hex chars)
//	9: User ID string ("Name <email>")
//
// For revoked UIDs, the creation date is recovered from the trailing
// self-signature record (sig:, field 5), and the revocation date is taken
// from the companion rev: record (rev:, field 5). Records belonging to a
// uid are bounded by the next uid:/pub:/sub:/sec:/ssb: record.
func parseUIDs(output string) []UID {
	var uids []UID
	var current *UID

	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")

		switch fields[0] {
		case recUID:
			if len(fields) < 10 { //nolint:mnd // uid records have at least 10 fields
				continue
			}
			u := UID{
				Index:    len(uids) + 1,
				Validity: fields[1],
				Hash:     fields[7],
				UID:      fields[9],
			}
			if fields[5] != "" {
				u.Created = parseEpoch(fields[5])
			}
			uids = append(uids, u)
			current = &uids[len(uids)-1]

		case recSig:
			// Self-sig date — fills in Created when the uid record itself
			// did not carry one (typical for revoked UIDs).
			if current != nil && current.Created.IsZero() && len(fields) > 5 && fields[5] != "" {
				current.Created = parseEpoch(fields[5])
			}

		case recRev:
			// Revocation signature date.
			if current != nil && current.Revoked.IsZero() && len(fields) > 5 && fields[5] != "" {
				current.Revoked = parseEpoch(fields[5])
			}

		case recPub, recSub, recSec, recSsb:
			// Moved past the uid block — stop attaching sig/rev to it.
			current = nil
		}
	}

	return uids
}

// AddUID attaches a new user ID to the master key.
// The uid argument must be in the form "Name <email>" or "Name (comment) <email>".
func (c *Client) AddUID(ctx context.Context, masterFP string, uid string) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("add uid: %w", err)
	}
	if uid == "" {
		return fmt.Errorf("add uid: uid is required")
	}

	if _, err := c.exec(ctx, "--quick-add-uid", masterFP, uid); err != nil {
		return fmt.Errorf("add uid: %w", err)
	}

	c.logger.InfoContext(ctx, "added uid",
		slog.String("uid", uid),
	)
	return nil
}

// RevokeUID revokes a user ID on the master key. The uid argument must
// match the existing UID exactly (use ListUIDs to look it up).
func (c *Client) RevokeUID(ctx context.Context, masterFP string, uid string) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("revoke uid: %w", err)
	}
	if uid == "" {
		return fmt.Errorf("revoke uid: uid is required")
	}

	if _, err := c.exec(ctx, "--quick-revoke-uid", masterFP, uid); err != nil {
		return fmt.Errorf("revoke uid: %w", err)
	}

	c.logger.InfoContext(ctx, "revoked uid",
		slog.String("uid", uid),
	)
	return nil
}

// SetPrimaryUID promotes a user ID to primary on the master key. The uid
// argument must match the existing UID exactly.
func (c *Client) SetPrimaryUID(ctx context.Context, masterFP string, uid string) error {
	if err := ValidateFingerprint(masterFP); err != nil {
		return fmt.Errorf("set primary uid: %w", err)
	}
	if uid == "" {
		return fmt.Errorf("set primary uid: uid is required")
	}

	if _, err := c.exec(ctx, "--quick-set-primary-uid", masterFP, uid); err != nil {
		return fmt.Errorf("set primary uid: %w", err)
	}

	c.logger.InfoContext(ctx, "set primary uid",
		slog.String("uid", uid),
	)
	return nil
}
