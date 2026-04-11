package gpg

import (
	"os"
	"testing"
)

func TestParseUIDs(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-keys-multiuid.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	uids := parseUIDs(string(data))

	if len(uids) != 3 {
		t.Fatalf("expected 3 uids, got %d", len(uids))
	}

	tests := []struct {
		idx      int
		uid      string
		validity string
		hash     string
	}{
		{1, "Test User <test@example.com>", "u", "ABC123"},
		{2, "Test User <work@example.com>", "u", "DEF456"},
		{3, "Old Name <old@example.com>", "r", "GHI789"},
	}

	for i, want := range tests {
		got := uids[i]
		if got.Index != want.idx {
			t.Errorf("uid[%d].Index = %d, want %d", i, got.Index, want.idx)
		}
		if got.UID != want.uid {
			t.Errorf("uid[%d].UID = %q, want %q", i, got.UID, want.uid)
		}
		if got.Validity != want.validity {
			t.Errorf("uid[%d].Validity = %q, want %q", i, got.Validity, want.validity)
		}
		if got.Hash != want.hash {
			t.Errorf("uid[%d].Hash = %q, want %q", i, got.Hash, want.hash)
		}
	}

	// Spot-check creation date is parsed.
	if uids[0].Created.IsZero() {
		t.Error("uid[0].Created should not be zero")
	}
}

// TestParseUIDsPrimaryTogglePrefersOriginalDate verifies that after a
// `--quick-set-primary-uid` operation (which adds a fresh self-signature
// with today's timestamp), the parser still reports the ORIGINAL creation
// date — not the date of the most recent re-signing. This was a real bug
// surfaced during v0.4.0 manual testing: setting an old UID as primary
// caused its CREATED column to jump from 2022 to today.
//
// Field 5 of the uid record reflects the latest self-signature, so the
// parser must always walk sig: records and pick the earliest one.
func TestParseUIDsPrimaryTogglePrefersOriginalDate(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-sigs-primary-toggle.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	uids := parseUIDs(string(data))

	if len(uids) != 2 {
		t.Fatalf("expected 2 uids, got %d", len(uids))
	}

	promoted := uids[0]
	original := uids[1]

	if promoted.UID != "Promoted Primary <primary@example.com>" {
		t.Errorf("promoted.UID = %q", promoted.UID)
	}
	// The promoted UID has TWO sig records: the original from 1659571200
	// (2022-08-04) and a fresh re-sign from 1775826361 (2026-04-10).
	// Field 5 of the uid record holds the latest (1775826361). The parser
	// must prefer the earliest sig (1659571200).
	if promoted.Created.Unix() != 1659571200 {
		t.Errorf("promoted.Created = %d, want 1659571200 (the original sig date, not the latest re-sign)",
			promoted.Created.Unix())
	}

	if original.Created.Unix() != 1659571200 {
		t.Errorf("original.Created = %d, want 1659571200", original.Created.Unix())
	}
}

// TestParseUIDsRevokedRecoversDates verifies the parser can recover the
// creation date from the trailing self-sig record and the revocation date
// from the rev record, even when gpg's colon output omits the creation
// date from a revoked uid line.
func TestParseUIDsRevokedRecoversDates(t *testing.T) {
	data, err := os.ReadFile("../../testdata/list-sigs-revoked-uid.txt")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	uids := parseUIDs(string(data))

	if len(uids) != 2 {
		t.Fatalf("expected 2 uids, got %d", len(uids))
	}

	active := uids[0]
	revoked := uids[1]

	if active.Validity != "u" {
		t.Errorf("active.Validity = %q, want %q", active.Validity, "u")
	}
	if active.UID != "T <t@e.com>" {
		t.Errorf("active.UID = %q", active.UID)
	}
	if active.Created.IsZero() {
		t.Error("active.Created should not be zero")
	}
	if !active.Revoked.IsZero() {
		t.Errorf("active.Revoked should be zero, got %v", active.Revoked)
	}

	if revoked.Validity != "r" {
		t.Errorf("revoked.Validity = %q, want %q", revoked.Validity, "r")
	}
	if revoked.UID != "X <x@e.com>" {
		t.Errorf("revoked.UID = %q", revoked.UID)
	}
	// Creation date must be recovered from the trailing sig record.
	if revoked.Created.IsZero() {
		t.Error("revoked.Created should be recovered from sig record, got zero")
	}
	if revoked.Created.Unix() != 1775826359 {
		t.Errorf("revoked.Created = %d, want 1775826359", revoked.Created.Unix())
	}
	// Revocation date must come from the rev record.
	if revoked.Revoked.IsZero() {
		t.Error("revoked.Revoked should be set from rev record, got zero")
	}
	if revoked.Revoked.Unix() != 1775826361 {
		t.Errorf("revoked.Revoked = %d, want 1775826361", revoked.Revoked.Unix())
	}
}
