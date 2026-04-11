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
//	5: creation date (epoch seconds; empty for revoked UIDs; LATEST self-sig
//	   date for active UIDs after a primary toggle, NOT the original
//	   creation date)
//	6: expiration date (epoch seconds, may be empty)
//	7: uid hash (40 hex chars)
//	9: User ID string ("Name <email>")
//
// Field 5 of the uid record reflects the LATEST self-signature, which gpg
// refreshes whenever the UID is touched (e.g. --quick-set-primary-uid
// rewrites the binding signature with today's timestamp). Naively trusting
// field 5 makes a UID created in 2022 look like it was created today right
// after a primary-toggle.
//
// To recover the actual creation date, we walk all sig: records that follow
// each uid: record and pick the EARLIEST one — that's the original binding
// signature from when the UID was first added. The earliest sig is also
// what we want for revoked UIDs (where field 5 is empty entirely).
//
// The revocation date comes from the companion rev: record (rev:, field 5).
// Records belonging to a uid are bounded by the next
// uid:/pub:/sub:/sec:/ssb: record.
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
			// Note: we deliberately do NOT trust field 5 of the uid record
			// here. It reflects the latest self-signature, which gpg
			// refreshes on operations like --quick-set-primary-uid. The
			// earliest sig: record below is the authoritative origin date.
			uids = append(uids, u)
			current = &uids[len(uids)-1]

		case recSig:
			// Self-sig date. Track the EARLIEST one as the original
			// creation timestamp; later sig records on the same UID
			// represent re-signings (e.g. primary toggles, expiration
			// extensions, key updates) which we don't want to surface.
			if current != nil && len(fields) > 5 && fields[5] != "" {
				sigAt := parseEpoch(fields[5])
				if current.Created.IsZero() || sigAt.Before(current.Created) {
					current.Created = sigAt
				}
			}

		case recRev:
			// Revocation signature date. Use the earliest revocation, in
			// the (very unusual) case that there's more than one.
			if current != nil && len(fields) > 5 && fields[5] != "" {
				revAt := parseEpoch(fields[5])
				if current.Revoked.IsZero() || revAt.Before(current.Revoked) {
					current.Revoked = revAt
				}
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
