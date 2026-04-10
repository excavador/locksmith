package wire

// This file holds proto↔kernel type converters. Every translation between
// pkg/gen/gpgsmith/v1 messages and pkg/{vault,gpg,audit,gpgsmith} types
// lives here. Handlers in handlers_*.go are kept thin: receive proto in,
// call into Backend with kernel types, return proto out. Tests for the
// converters live in mapping_test.go.

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/excavador/locksmith/pkg/audit"
	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
)

// ===== timestamp helpers =====

func toProtoTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// ===== LockSource =====

func toProtoLockSource(s gpgsmith.LockSource) v1.LockSource {
	switch s {
	case gpgsmith.LockSourceCLI:
		return v1.LockSource_LOCK_SOURCE_CLI
	case gpgsmith.LockSourceUI:
		return v1.LockSource_LOCK_SOURCE_UI
	case gpgsmith.LockSourceTUI:
		return v1.LockSource_LOCK_SOURCE_TUI
	default:
		return v1.LockSource_LOCK_SOURCE_UNSPECIFIED
	}
}

func fromProtoLockSource(p v1.LockSource) gpgsmith.LockSource {
	switch p {
	case v1.LockSource_LOCK_SOURCE_CLI:
		return gpgsmith.LockSourceCLI
	case v1.LockSource_LOCK_SOURCE_UI:
		return gpgsmith.LockSourceUI
	case v1.LockSource_LOCK_SOURCE_TUI:
		return gpgsmith.LockSourceTUI
	default:
		return gpgsmith.LockSourceCLI
	}
}

// ===== SubKey =====

func toProtoSubKey(k gpg.SubKey) *v1.SubKey {
	return &v1.SubKey{
		KeyId:       k.KeyID,
		Fingerprint: k.Fingerprint,
		Algorithm:   k.Algorithm,
		Usage:       k.Usage,
		Created:     toProtoTime(k.Created),
		Expires:     toProtoTime(k.Expires),
		CardSerial:  k.CardSerial,
		Validity:    k.Validity,
	}
}

func toProtoSubKeys(ks []gpg.SubKey) []*v1.SubKey {
	out := make([]*v1.SubKey, 0, len(ks))
	for i := range ks {
		out = append(out, toProtoSubKey(ks[i]))
	}
	return out
}

// ===== UID / Identity =====

func toProtoIdentity(u gpg.UID) *v1.Identity {
	status := ""
	switch u.Validity {
	case "u":
		status = "ultimate"
	case "r":
		status = "revoked"
	case "e":
		status = "expired"
	case "f":
		status = "full"
	case "m":
		status = "marginal"
	case "n":
		status = "never"
	default:
		status = u.Validity
	}
	return &v1.Identity{
		Index:    int32(u.Index), //nolint:gosec // gpg uid index is small positive int
		Validity: u.Validity,
		Status:   status,
		Created:  toProtoTime(u.Created),
		Revoked:  toProtoTime(u.Revoked),
		Hash:     u.Hash,
		Uid:      u.UID,
	}
}

func toProtoIdentities(us []gpg.UID) []*v1.Identity {
	out := make([]*v1.Identity, 0, len(us))
	for i := range us {
		out = append(out, toProtoIdentity(us[i]))
	}
	return out
}

// ===== Snapshot =====

func toProtoSnapshot(s vault.Snapshot) *v1.Snapshot {
	return &v1.Snapshot{
		Path:      s.Path,
		Filename:  filenameOf(s.Path),
		Timestamp: toProtoTime(s.Timestamp),
		Message:   s.Message,
	}
}

func toProtoSnapshots(ss []vault.Snapshot) []*v1.Snapshot {
	out := make([]*v1.Snapshot, 0, len(ss))
	for i := range ss {
		out = append(out, toProtoSnapshot(ss[i]))
	}
	return out
}

// filenameOf returns the basename of a path. Avoids importing filepath
// just for one call site.
func filenameOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}

// ===== CardInfo / YubiKeyEntry =====

func toProtoCardInfo(e gpg.YubiKeyEntry) *v1.CardInfo {
	return &v1.CardInfo{
		Serial:        e.Serial,
		Label:         e.Label,
		Model:         e.Model,
		Description:   e.Description,
		Provisioning:  e.Provisioning,
		Status:        e.Status,
		ProvisionedAt: toProtoTime(e.ProvisionedAt),
		Subkeys:       toProtoSubKeyRefs(e.Subkeys),
	}
}

func toProtoCardInfos(es []gpg.YubiKeyEntry) []*v1.CardInfo {
	out := make([]*v1.CardInfo, 0, len(es))
	for i := range es {
		out = append(out, toProtoCardInfo(es[i]))
	}
	return out
}

func toProtoSubKeyRef(r gpg.SubKeyRef) *v1.SubKeyRef {
	return &v1.SubKeyRef{
		KeyId:   r.KeyID,
		Usage:   r.Usage,
		Created: toProtoTime(r.Created),
		Expires: toProtoTime(r.Expires),
	}
}

func toProtoSubKeyRefs(rs []gpg.SubKeyRef) []*v1.SubKeyRef {
	out := make([]*v1.SubKeyRef, 0, len(rs))
	for i := range rs {
		out = append(out, toProtoSubKeyRef(rs[i]))
	}
	return out
}

// ===== PublishServer / ServerEntry =====

func toProtoPublishServer(s gpg.ServerEntry) *v1.PublishServer {
	return &v1.PublishServer{
		Alias:   s.Alias,
		Type:    s.Type,
		Url:     s.URL,
		Enabled: s.Enabled,
	}
}

func toProtoPublishServers(ss []gpg.ServerEntry) []*v1.PublishServer {
	out := make([]*v1.PublishServer, 0, len(ss))
	for i := range ss {
		out = append(out, toProtoPublishServer(ss[i]))
	}
	return out
}

// ===== AuditEntry =====

func toProtoAuditEntry(e audit.Entry) *v1.AuditEntry {
	return &v1.AuditEntry{
		Timestamp: toProtoTime(e.Timestamp),
		Action:    e.Action,
		Details:   e.Details,
		Metadata:  e.Metadata,
	}
}

func toProtoAuditEntries(es []audit.Entry) []*v1.AuditEntry {
	out := make([]*v1.AuditEntry, 0, len(es))
	for i := range es {
		out = append(out, toProtoAuditEntry(es[i]))
	}
	return out
}

// ===== VaultRegistryEntry =====

func toProtoVaultEntry(e vault.Entry) *v1.VaultRegistryEntry {
	return &v1.VaultRegistryEntry{
		Name:            e.Name,
		Path:            e.Path,
		IdentityFile:    e.Identity,
		GpgBinary:       e.GPGBinary,
		TrustedMasterFp: e.TrustedMasterFP,
	}
}

func toProtoVaultEntries(es []vault.Entry) []*v1.VaultRegistryEntry {
	out := make([]*v1.VaultRegistryEntry, 0, len(es))
	for i := range es {
		out = append(out, toProtoVaultEntry(es[i]))
	}
	return out
}

// ===== SessionInfo =====

func toProtoSessionInfo(s SessionInfo) *v1.SessionInfo {
	return &v1.SessionInfo{
		VaultName:      s.VaultName,
		VaultPath:      s.VaultPath,
		Source:         toProtoLockSource(s.Source),
		Hostname:       s.Hostname,
		StartedAt:      toProtoTime(s.StartedAt),
		LastActiveAt:   toProtoTime(s.LastActiveAt),
		SourceSnapshot: s.SourceSnapshot,
		MasterFp:       s.MasterFP,
		Generation:     s.Generation,
		Status:         s.Status,
	}
}

func toProtoSessionInfos(ss []SessionInfo) []*v1.SessionInfo {
	out := make([]*v1.SessionInfo, 0, len(ss))
	for i := range ss {
		out = append(out, toProtoSessionInfo(ss[i]))
	}
	return out
}

// ===== ResumeOption =====

func toProtoResumeOption(r ResumeOption) *v1.ResumeOption {
	return &v1.ResumeOption{
		CanonicalBase: r.CanonicalBase,
		Hostname:      r.Hostname,
		Source:        toProtoLockSource(r.Source),
		StartedAt:     toProtoTime(r.StartedAt),
		LastHeartbeat: toProtoTime(r.LastHeartbeat),
		Status:        r.Status,
		Divergent:     r.Divergent,
	}
}

func toProtoResumeOptions(rs []ResumeOption) []*v1.ResumeOption {
	out := make([]*v1.ResumeOption, 0, len(rs))
	for i := range rs {
		out = append(out, toProtoResumeOption(rs[i]))
	}
	return out
}

// ===== PublishResult / LookupResult =====

func toProtoPublishResults(prs []PublishResult) []*v1.PublishResult {
	out := make([]*v1.PublishResult, 0, len(prs))
	for i := range prs {
		out = append(out, &v1.PublishResult{
			Alias:   prs[i].Alias,
			Success: prs[i].Success,
			Error:   prs[i].Error,
		})
	}
	return out
}

func toProtoLookupResults(lrs []LookupResult) []*v1.LookupResult {
	out := make([]*v1.LookupResult, 0, len(lrs))
	for i := range lrs {
		out = append(out, &v1.LookupResult{
			Url:    lrs[i].URL,
			Status: lrs[i].Status,
		})
	}
	return out
}

// ===== Event =====

func toProtoEventKind(k EventKind) v1.EventKind {
	switch k {
	case EventKindJobStarted:
		return v1.EventKind_EVENT_KIND_JOB_STARTED
	case EventKindJobProgress:
		return v1.EventKind_EVENT_KIND_JOB_PROGRESS
	case EventKindJobPrompt:
		return v1.EventKind_EVENT_KIND_JOB_PROMPT
	case EventKindJobCompleted:
		return v1.EventKind_EVENT_KIND_JOB_COMPLETED
	case EventKindJobFailed:
		return v1.EventKind_EVENT_KIND_JOB_FAILED
	case EventKindStateChanged:
		return v1.EventKind_EVENT_KIND_STATE_CHANGED
	case EventKindSessionEnded:
		return v1.EventKind_EVENT_KIND_SESSION_ENDED
	default:
		return v1.EventKind_EVENT_KIND_UNSPECIFIED
	}
}

func toProtoEvent(e Event) *v1.Event {
	return &v1.Event{
		Timestamp: toProtoTime(e.At),
		VaultName: e.VaultName,
		JobId:     e.JobID,
		Kind:      toProtoEventKind(e.Kind),
		Message:   e.Message,
		Data:      e.Data,
	}
}
