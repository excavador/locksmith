package gpgsmith

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestSessionFilenamesFor(t *testing.T) {
	state, info := SessionFilenamesFor("20260410T143012Z_setup.tar.age", "laptop.local")
	wantState := "20260410T143012Z_setup.tar.age.session-laptop.local"
	wantInfo := "20260410T143012Z_setup.tar.age.session-laptop.local.info"
	if state != wantState {
		t.Errorf("state = %q, want %q", state, wantState)
	}
	if info != wantInfo {
		t.Errorf("info = %q, want %q", info, wantInfo)
	}
}

func TestParseSessionFilename(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		canonical string
		host      string
		ok        bool
	}{
		{
			name:      "bare name",
			input:     "20260410T143012Z_setup.tar.age.session-laptop.local",
			canonical: "20260410T143012Z_setup.tar.age",
			host:      "laptop.local",
			ok:        true,
		},
		{
			name:      "full path",
			input:     "/dropbox/vault/20260410T143012Z_setup.tar.age.session-desktop",
			canonical: "20260410T143012Z_setup.tar.age",
			host:      "desktop",
			ok:        true,
		},
		{
			name:      "host with dots and digits",
			input:     "20260101T000000Z_initial.tar.age.session-host42.example.com",
			canonical: "20260101T000000Z_initial.tar.age",
			host:      "host42.example.com",
			ok:        true,
		},
		{
			name:  "no infix",
			input: "20260410T143012Z_setup.tar.age",
			ok:    false,
		},
		{
			name:  "empty hostname",
			input: "20260410T143012Z_setup.tar.age.session-",
			ok:    false,
		},
		{
			name:  "no canonical",
			input: ".session-laptop",
			ok:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canonical, host, ok := ParseSessionFilename(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if canonical != tc.canonical {
				t.Errorf("canonical = %q, want %q", canonical, tc.canonical)
			}
			if host != tc.host {
				t.Errorf("host = %q, want %q", host, tc.host)
			}
		})
	}
}

func TestWriteAndReadEphemeralInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.info")

	original := &EphemeralInfo{
		Hostname:      "laptop.local",
		Source:        LockSourceCLI,
		StartedAt:     time.Date(2026, 4, 10, 14, 0, 0, 0, time.UTC),
		LastHeartbeat: time.Date(2026, 4, 10, 14, 32, 0, 0, time.UTC),
		Generation:    7,
		Status:        EphemeralStatusActive,
	}

	if err := WriteEphemeralInfo(path, original); err != nil {
		t.Fatalf("WriteEphemeralInfo: %v", err)
	}

	// Mode should be 0600 (private).
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := stat.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode = %o, want 0o600", mode)
	}

	loaded, err := ReadEphemeralInfo(path)
	if err != nil {
		t.Fatalf("ReadEphemeralInfo: %v", err)
	}

	if loaded.Hostname != original.Hostname {
		t.Errorf("Hostname mismatch: %q vs %q", loaded.Hostname, original.Hostname)
	}
	if loaded.Source != original.Source {
		t.Errorf("Source mismatch: %q vs %q", loaded.Source, original.Source)
	}
	if !loaded.StartedAt.Equal(original.StartedAt) {
		t.Errorf("StartedAt mismatch: %v vs %v", loaded.StartedAt, original.StartedAt)
	}
	if !loaded.LastHeartbeat.Equal(original.LastHeartbeat) {
		t.Errorf("LastHeartbeat mismatch: %v vs %v", loaded.LastHeartbeat, original.LastHeartbeat)
	}
	if loaded.Generation != original.Generation {
		t.Errorf("Generation mismatch: %d vs %d", loaded.Generation, original.Generation)
	}
	if loaded.Status != original.Status {
		t.Errorf("Status mismatch: %q vs %q", loaded.Status, original.Status)
	}
}

func TestWriteEphemeralInfoAtomic(t *testing.T) {
	// Verify the temp file does not leak after a successful write.
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.info")

	if err := WriteEphemeralInfo(path, &EphemeralInfo{Hostname: "h"}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "atomic.info" {
			t.Errorf("leaked tmp file: %s", entry.Name())
		}
	}
}

func TestEphemeralInfoIsStale(t *testing.T) {
	now := time.Date(2026, 4, 10, 14, 32, 0, 0, time.UTC)
	cases := []struct {
		name      string
		heartbeat time.Time
		stale     bool
	}{
		{"fresh", now.Add(-10 * time.Second), false},
		{"borderline-fresh", now.Add(-89 * time.Second), false},
		{"borderline-stale", now.Add(-91 * time.Second), true},
		{"clearly stale", now.Add(-10 * time.Minute), true},
		{"future heartbeat (clock skew)", now.Add(10 * time.Second), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := &EphemeralInfo{LastHeartbeat: tc.heartbeat}
			if got := info.IsStale(now); got != tc.stale {
				t.Errorf("IsStale = %v, want %v", got, tc.stale)
			}
		})
	}
}

func TestListEphemeralsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := ListEphemerals(dir)
	if err != nil {
		t.Fatalf("ListEphemerals: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 ephemerals, got %d", len(got))
	}
}

func TestListEphemeralsMultipleHosts(t *testing.T) {
	dir := t.TempDir()

	// Drop a fake canonical and two ephemerals from different hosts.
	canonical := "20260410T143012Z_setup.tar.age"
	if err := os.WriteFile(filepath.Join(dir, canonical), []byte("fake encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, host := range []string{"laptop", "desktop"} {
		statePath, infoPath := SessionFilenamesFor(canonical, host)
		if err := os.WriteFile(filepath.Join(dir, statePath), []byte("fake state"), 0o600); err != nil {
			t.Fatal(err)
		}
		info := &EphemeralInfo{
			Hostname:      host,
			Source:        LockSourceCLI,
			StartedAt:     time.Now().Add(-10 * time.Minute).UTC(),
			LastHeartbeat: time.Now().UTC(),
			Generation:    1,
			Status:        EphemeralStatusActive,
		}
		if err := WriteEphemeralInfo(filepath.Join(dir, infoPath), info); err != nil {
			t.Fatal(err)
		}
	}

	got, err := ListEphemerals(dir)
	if err != nil {
		t.Fatalf("ListEphemerals: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 ephemerals, got %d", len(got))
	}

	// Sorted by hostname.
	hosts := []string{got[0].Info.Hostname, got[1].Info.Hostname}
	want := []string{"desktop", "laptop"}
	sort.Strings(want)
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}

	for i := range got {
		if got[i].CanonicalBase != canonical {
			t.Errorf("got[%d].CanonicalBase = %q", i, got[i].CanonicalBase)
		}
		if got[i].SessionPath == "" {
			t.Errorf("got[%d].SessionPath empty (state file should have been found)", i)
		}
	}
}

func TestListEphemeralsSkipsJunk(t *testing.T) {
	dir := t.TempDir()

	// A truly garbage .info file.
	if err := os.WriteFile(filepath.Join(dir, "garbage.info"), []byte("not yaml at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A .info that doesn't follow the .session-<host> pattern.
	if err := os.WriteFile(filepath.Join(dir, "random.info"), []byte("hostname: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real ephemeral.
	canonical := "20260410T143012Z_real.tar.age"
	_, infoPath := SessionFilenamesFor(canonical, "h")
	if err := WriteEphemeralInfo(filepath.Join(dir, infoPath), &EphemeralInfo{
		Hostname:      "h",
		LastHeartbeat: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	got, err := ListEphemerals(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 valid ephemeral, got %d", len(got))
	}
	if got[0].Info.Hostname != "h" {
		t.Errorf("hostname = %q, want h", got[0].Info.Hostname)
	}
}

func TestFindEphemeralFor(t *testing.T) {
	dir := t.TempDir()
	canonical := "20260410T143012Z_setup.tar.age"

	for _, host := range []string{"a", "b", "c"} {
		_, infoPath := SessionFilenamesFor(canonical, host)
		if err := WriteEphemeralInfo(filepath.Join(dir, infoPath), &EphemeralInfo{
			Hostname:      host,
			LastHeartbeat: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := FindEphemeralFor(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("FindEphemeralFor returned nil for existing host")
	}
	if got.Info.Hostname != "b" {
		t.Errorf("hostname = %q, want b", got.Info.Hostname)
	}

	missing, err := FindEphemeralFor(dir, "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if missing != nil {
		t.Errorf("expected nil for nonexistent host, got %+v", missing)
	}
}

func TestEphemeralIsDivergent(t *testing.T) {
	cases := []struct {
		name           string
		canonicalBase  string
		canonicalNames []string
		divergent      bool
	}{
		{
			name:           "no other canonicals",
			canonicalBase:  "20260410T143012Z_setup.tar.age",
			canonicalNames: []string{"20260410T143012Z_setup.tar.age"},
			divergent:      false,
		},
		{
			name:          "older canonicals exist",
			canonicalBase: "20260410T143012Z_setup.tar.age",
			canonicalNames: []string{
				"20260101T000000Z_initial.tar.age",
				"20260410T143012Z_setup.tar.age",
			},
			divergent: false,
		},
		{
			name:          "newer canonical exists",
			canonicalBase: "20260410T143012Z_setup.tar.age",
			canonicalNames: []string{
				"20260410T143012Z_setup.tar.age",
				"20260415T120000Z_more-work.tar.age",
			},
			divergent: true,
		},
		{
			name:           "ephemeral references missing canonical, newer present",
			canonicalBase:  "20260410T143012Z_old.tar.age",
			canonicalNames: []string{"20260415T120000Z_new.tar.age"},
			divergent:      true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &Ephemeral{CanonicalBase: tc.canonicalBase}
			if got := e.IsDivergent(tc.canonicalNames); got != tc.divergent {
				t.Errorf("IsDivergent = %v, want %v", got, tc.divergent)
			}
		})
	}
}

func TestDeleteEphemeralFiles(t *testing.T) {
	dir := t.TempDir()
	canonical := "20260410T143012Z_setup.tar.age"
	statePath, infoPath := SessionFilenamesFor(canonical, "h")
	stateFull := filepath.Join(dir, statePath)
	infoFull := filepath.Join(dir, infoPath)

	if err := os.WriteFile(stateFull, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoFull, []byte("info"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := DeleteEphemeralFiles(stateFull, infoFull); err != nil {
		t.Fatalf("DeleteEphemeralFiles: %v", err)
	}

	for _, p := range []string{stateFull, infoFull} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s should be deleted", p)
		}
	}

	// Idempotent: deleting again is fine.
	if err := DeleteEphemeralFiles(stateFull, infoFull); err != nil {
		t.Errorf("second DeleteEphemeralFiles should be no-op, got: %v", err)
	}
}
