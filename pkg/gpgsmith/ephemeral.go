package gpgsmith

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Naming convention for in-progress sessions stored alongside the canonical
// snapshots in the vault directory:
//
//	<canonical>.tar.age                        — canonical snapshot (immutable)
//	<canonical>.tar.age.session-<hostname>     — encrypted in-progress workdir
//	<canonical>.tar.age.session-<hostname>.info — plaintext liveness sidecar
//
// The base canonical filename is preserved in the suffix so the relationship
// is immediately visible: every .session-<host> file is parented to a known
// snapshot, and divergence is detected by comparing that parent to the latest
// canonical in the same directory.
//
// The hostname-suffix lets multiple machines (in a Dropbox/Syncthing-synced
// vault directory) coexist without colliding on filenames. Each machine has
// at most one in-progress session per vault, named after its own hostname.

const (
	sessionInfix = ".session-"
	infoSuffix   = ".info"

	// HeartbeatInterval is how often a running daemon refreshes the .info
	// liveness timestamp on disk.
	HeartbeatInterval = 30 * time.Second

	// StaleHeartbeatThreshold is how long ago the last heartbeat must be
	// before another process treats the session as stale (presumed crashed
	// or otherwise dead). Generously larger than HeartbeatInterval to
	// tolerate sync delay and load spikes.
	StaleHeartbeatThreshold = 90 * time.Second

	// EphemeralStatusActive marks a session whose daemon is presumed to be
	// running and heartbeating.
	EphemeralStatusActive EphemeralStatus = "active"

	// EphemeralStatusIdleSealed marks a session that was auto-sealed by the
	// idle timer; the encrypted state file is on disk and the in-memory
	// daemon state has been dropped.
	EphemeralStatusIdleSealed EphemeralStatus = "idle-sealed"
)

type (
	// EphemeralStatus is the lifecycle state recorded in a .info sidecar.
	EphemeralStatus string

	// EphemeralInfo is the plaintext content of a .session-<host>.info file.
	// It is updated on every heartbeat tick and read by other processes
	// (other gpgsmith invocations on the same or different hosts) without
	// needing the vault passphrase.
	EphemeralInfo struct {
		Hostname      string          `yaml:"hostname"`
		Source        LockSource      `yaml:"source"`
		StartedAt     time.Time       `yaml:"started_at"`
		LastHeartbeat time.Time       `yaml:"last_heartbeat"`
		Generation    uint64          `yaml:"generation"`
		Status        EphemeralStatus `yaml:"status"`
	}

	// Ephemeral describes an in-progress session file pair (.session-host and
	// its .info sidecar) discovered in a vault directory. It does NOT
	// include any decrypted state — only the on-disk filenames and the
	// plaintext .info contents.
	Ephemeral struct {
		// VaultDir is the absolute path of the vault directory holding the
		// session files.
		VaultDir string

		// CanonicalBase is the filename of the canonical snapshot this
		// session was opened from (e.g. "20260410T143012Z_setup.tar.age").
		CanonicalBase string

		// SessionPath is the full path to the encrypted state file
		// (<vaultdir>/<canonical>.session-<host>). May be empty if the
		// session was opened but never wrote any state to disk yet
		// (the .info exists alone).
		SessionPath string

		// InfoPath is the full path to the .info sidecar.
		InfoPath string

		// Info is the parsed .info contents.
		Info EphemeralInfo
	}
)

// SessionFilenamesFor returns the (state, info) filenames for a session held
// by the given hostname against the given canonical snapshot base filename.
// hostname must be the bare host name (no dots stripped, no munging beyond
// what os.Hostname returns).
func SessionFilenamesFor(canonicalBase, hostname string) (statePath, infoPath string) {
	state := canonicalBase + sessionInfix + hostname
	return state, state + infoSuffix
}

// ParseSessionFilename extracts the canonical base and hostname from a
// .session-<hostname> filename. Returns ok=false if the name does not match
// the expected pattern. Accepts both bare names and full paths; the
// directory portion is ignored.
func ParseSessionFilename(name string) (canonicalBase, hostname string, ok bool) {
	base := filepath.Base(name)
	idx := strings.LastIndex(base, sessionInfix)
	if idx <= 0 {
		return "", "", false
	}
	canonicalBase = base[:idx]
	hostname = base[idx+len(sessionInfix):]
	if canonicalBase == "" || hostname == "" {
		return "", "", false
	}
	return canonicalBase, hostname, true
}

// WriteEphemeralInfo serializes info to YAML and writes it atomically to
// path. The write goes to a temp file followed by rename so observers never
// see a half-written file.
func WriteEphemeralInfo(path string, info *EphemeralInfo) error {
	data, err := yaml.Marshal(info)
	if err != nil {
		return fmt.Errorf("ephemeral info: marshal: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gpgsmith-info-")
	if err != nil {
		return fmt.Errorf("ephemeral info: create tmp: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("ephemeral info: write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("ephemeral info: chmod tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName) //nolint:gosec // tmpName from os.CreateTemp in caller-supplied dir
		return fmt.Errorf("ephemeral info: close tmp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil { //nolint:gosec // both paths from caller-supplied vault dir
		_ = os.Remove(tmpName) //nolint:gosec // tmpName from os.CreateTemp in caller-supplied dir
		return fmt.Errorf("ephemeral info: rename: %w", err)
	}
	return nil
}

// ReadEphemeralInfo reads and parses a .info sidecar file.
func ReadEphemeralInfo(path string) (*EphemeralInfo, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path supplied by caller from a constrained directory listing
	if err != nil {
		return nil, fmt.Errorf("ephemeral info: read %s: %w", path, err)
	}
	var info EphemeralInfo
	if err := yaml.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("ephemeral info: parse %s: %w", path, err)
	}
	return &info, nil
}

// IsStale reports whether the last heartbeat is older than the threshold.
// Used to detect crashed daemons whose .info file remains on disk.
func (e *EphemeralInfo) IsStale(now time.Time) bool {
	return now.Sub(e.LastHeartbeat) > StaleHeartbeatThreshold
}

// IsIdleSealed reports whether the ephemeral was put to rest by the idle
// timer (as opposed to actively crashed or actively running).
func (e *EphemeralInfo) IsIdleSealed() bool {
	return e.Status == EphemeralStatusIdleSealed
}

// ListEphemerals scans vaultDir for all .session-<hostname>.info files and
// returns the parsed Ephemeral records. Files whose .info cannot be parsed
// are silently skipped (they're treated as junk; the caller can decide what
// to do with them). The returned slice is sorted by hostname for stable
// output.
func ListEphemerals(vaultDir string) ([]Ephemeral, error) {
	entries, err := os.ReadDir(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("ephemeral list: read dir %s: %w", vaultDir, err)
	}

	var out []Ephemeral
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, infoSuffix) {
			continue
		}
		// Strip the .info suffix to get the .session-<host> filename, then
		// parse that for canonical+hostname.
		stateBase := strings.TrimSuffix(name, infoSuffix)
		canonical, hostname, ok := ParseSessionFilename(stateBase)
		if !ok {
			continue
		}

		infoPath := filepath.Join(vaultDir, name)
		info, err := ReadEphemeralInfo(infoPath)
		if err != nil {
			continue
		}

		statePath := filepath.Join(vaultDir, stateBase)
		// The state file may legitimately be absent if the daemon hasn't
		// flushed yet (very early in the session). That's not an error,
		// but record an empty path so callers know not to read it.
		if _, statErr := os.Stat(statePath); statErr != nil {
			statePath = ""
		}

		_ = hostname // currently used only via Info.Hostname
		out = append(out, Ephemeral{
			VaultDir:      vaultDir,
			CanonicalBase: canonical,
			SessionPath:   statePath,
			InfoPath:      infoPath,
			Info:          *info,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Info.Hostname < out[j].Info.Hostname
	})
	return out, nil
}

// FindEphemeralFor returns the Ephemeral matching the given hostname in
// vaultDir, or nil if none exists.
func FindEphemeralFor(vaultDir, hostname string) (*Ephemeral, error) {
	all, err := ListEphemerals(vaultDir)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Info.Hostname == hostname {
			return &all[i], nil
		}
	}
	return nil, nil
}

// IsDivergent reports whether the canonical the ephemeral was based on is
// older than the latest canonical present in the same vault directory.
// Returns true when newer canonicals exist (the user has changes from
// elsewhere that the ephemeral does not include).
//
// canonicalNames is the list of canonical snapshot filenames currently in
// the vault dir, in arbitrary order. This is supplied by the caller (rather
// than read here) so the function is testable in isolation.
func (e *Ephemeral) IsDivergent(canonicalNames []string) bool {
	for _, name := range canonicalNames {
		if name > e.CanonicalBase {
			return true
		}
	}
	return false
}

// DeleteEphemeralFiles removes the .session-<host> and .info file pair.
// Either or both may be absent; missing files are not errors.
func DeleteEphemeralFiles(statePath, infoPath string) error {
	if statePath != "" {
		if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("ephemeral delete state: %w", err)
		}
	}
	if infoPath != "" {
		if err := os.Remove(infoPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("ephemeral delete info: %w", err)
		}
	}
	return nil
}
