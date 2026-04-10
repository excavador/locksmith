package wire

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/excavador/locksmith/pkg/audit"
	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
	"github.com/excavador/locksmith/pkg/gpg"
	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
)

type (
	// fakeBackend is a minimal Backend implementation that returns canned
	// data for the methods exercised by the round-trip tests. Each method
	// records the most recent invocation so tests can assert what the
	// handler called.
	//
	// Methods that are not exercised in any test return errUnimplemented
	// to surface accidental coverage gaps.
	fakeBackend struct {
		statusReturn DaemonStatus

		listIdentitiesCalls  int
		listIdentitiesArg    string
		listIdentitiesReturn []gpg.UID
		listIdentitiesErr    error

		addIdentityCalls int
		addIdentityVault string
		addIdentityUID   string

		subscribeEvents chan Event
	}
)

var (
	errUnimplemented = errors.New("fakeBackend: method not implemented for this test")
)

func (f *fakeBackend) DaemonStatus(_ context.Context) (DaemonStatus, error) {
	return f.statusReturn, nil
}
func (f *fakeBackend) DaemonShutdown(context.Context, int) error           { return errUnimplemented }
func (f *fakeBackend) ListSessions(context.Context) ([]SessionInfo, error) { return nil, nil }

func (f *fakeBackend) ListVaults(context.Context) ([]vault.Entry, string, error) {
	return nil, "", errUnimplemented
}
func (f *fakeBackend) StatusVaults(context.Context) ([]SessionInfo, []ResumeOption, error) {
	return nil, nil, errUnimplemented
}
func (f *fakeBackend) OpenVault(context.Context, string, string, gpgsmith.LockSource) (OpenResult, error) {
	return OpenResult{}, errUnimplemented
}
func (f *fakeBackend) ResumeVault(context.Context, string, string, gpgsmith.LockSource, bool) (SessionInfo, error) {
	return SessionInfo{}, errUnimplemented
}
func (f *fakeBackend) SealVault(context.Context, string, string) (vault.Snapshot, error) {
	return vault.Snapshot{}, errUnimplemented
}
func (f *fakeBackend) DiscardVault(context.Context, string) error { return errUnimplemented }
func (f *fakeBackend) Snapshots(context.Context, string) ([]vault.Snapshot, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) ImportVault(context.Context, string, string, string) (vault.Snapshot, error) {
	return vault.Snapshot{}, errUnimplemented
}
func (f *fakeBackend) ExportVault(context.Context, string, string, string) (string, error) {
	return "", errUnimplemented
}
func (f *fakeBackend) TrustVault(context.Context, string, string) error { return errUnimplemented }

func (f *fakeBackend) CreateMasterKey(context.Context, string, CreateKeyOpts) (string, []gpg.SubKey, error) {
	return "", nil, errUnimplemented
}
func (f *fakeBackend) GenerateSubkeys(context.Context, string) ([]gpg.SubKey, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) ListKeys(context.Context, string) ([]gpg.SubKey, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) RevokeSubkey(context.Context, string, string) error { return errUnimplemented }
func (f *fakeBackend) ExportKey(context.Context, string) (string, error) {
	return "", errUnimplemented
}
func (f *fakeBackend) SSHPubKey(context.Context, string) (string, error) {
	return "", errUnimplemented
}
func (f *fakeBackend) KeyStatus(context.Context, string) ([]gpg.SubKey, *gpg.CardInfo, error) {
	return nil, nil, errUnimplemented
}

func (f *fakeBackend) ListIdentities(_ context.Context, vaultName string) ([]gpg.UID, error) {
	f.listIdentitiesCalls++
	f.listIdentitiesArg = vaultName
	return f.listIdentitiesReturn, f.listIdentitiesErr
}
func (f *fakeBackend) AddIdentity(_ context.Context, vaultName, uid string) error {
	f.addIdentityCalls++
	f.addIdentityVault = vaultName
	f.addIdentityUID = uid
	return nil
}
func (f *fakeBackend) RevokeIdentity(context.Context, string, string) error { return errUnimplemented }
func (f *fakeBackend) PrimaryIdentity(context.Context, string, string) error {
	return errUnimplemented
}

func (f *fakeBackend) ProvisionCard(context.Context, string, ProvisionCardOpts) (gpg.YubiKeyEntry, string, error) {
	return gpg.YubiKeyEntry{}, "", errUnimplemented
}
func (f *fakeBackend) RotateCard(context.Context, string, string) (gpg.YubiKeyEntry, error) {
	return gpg.YubiKeyEntry{}, errUnimplemented
}
func (f *fakeBackend) RevokeCard(context.Context, string, string) error { return errUnimplemented }
func (f *fakeBackend) CardInventory(context.Context, string) ([]gpg.YubiKeyEntry, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) DiscoverCard(context.Context, string, string, string) (gpg.YubiKeyEntry, bool, error) {
	return gpg.YubiKeyEntry{}, false, errUnimplemented
}

func (f *fakeBackend) ListPublishServers(context.Context, string) ([]gpg.ServerEntry, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) AddPublishServer(context.Context, string, string, string) error {
	return errUnimplemented
}
func (f *fakeBackend) RemovePublishServer(context.Context, string, string) error {
	return errUnimplemented
}
func (f *fakeBackend) EnablePublishServer(context.Context, string, string) error {
	return errUnimplemented
}
func (f *fakeBackend) DisablePublishServer(context.Context, string, string) error {
	return errUnimplemented
}
func (f *fakeBackend) Publish(context.Context, string, []string) ([]PublishResult, error) {
	return nil, errUnimplemented
}
func (f *fakeBackend) LookupPublished(context.Context, string) ([]LookupResult, error) {
	return nil, errUnimplemented
}

func (f *fakeBackend) ShowAudit(context.Context, string, int) ([]audit.Entry, error) {
	return nil, errUnimplemented
}

func (f *fakeBackend) SubscribeEvents(_ context.Context, _ string) (<-chan Event, error) {
	if f.subscribeEvents != nil {
		return f.subscribeEvents, nil
	}
	return nil, errUnimplemented
}

// startTestServer mounts the wire Server on an httptest.Server and returns
// a Client wired to it plus a teardown function.
func startTestServer(t *testing.T, b Backend) (*Client, func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(NewServer(b).Handler())
	// Connect needs HTTP/2 for client streaming over h2c, but unary calls
	// work fine over plain HTTP/1.1. The httptest.Server defaults to
	// HTTP/1.1 which is enough for everything we test here.
	srv.Start()

	client := NewHTTPClient(srv.Client(), srv.URL)
	teardown := func() {
		client.Close()
		srv.Close()
	}
	return client, teardown
}

func TestRoundTripDaemonStatus(t *testing.T) {
	now := time.Date(2026, 4, 10, 14, 32, 0, 0, time.UTC)
	backend := &fakeBackend{
		statusReturn: DaemonStatus{
			PID:            12345,
			Version:        "v0.4.0-test",
			Commit:         "abc1234",
			SocketPath:     "/run/user/1000/gpgsmith.sock",
			StartedAt:      now,
			ActiveSessions: 2,
		},
	}
	client, teardown := startTestServer(t, backend)
	defer teardown()

	resp, err := client.Daemon.Status(context.Background(), connect.NewRequest(&v1.StatusRequest{}))
	if err != nil {
		t.Fatalf("Daemon.Status: %v", err)
	}
	if resp.Msg.Pid != 12345 {
		t.Errorf("Pid = %d, want 12345", resp.Msg.Pid)
	}
	if resp.Msg.Version != "v0.4.0-test" {
		t.Errorf("Version = %q", resp.Msg.Version)
	}
	if resp.Msg.SocketPath != "/run/user/1000/gpgsmith.sock" {
		t.Errorf("SocketPath = %q", resp.Msg.SocketPath)
	}
	if resp.Msg.ActiveSessions != 2 {
		t.Errorf("ActiveSessions = %d", resp.Msg.ActiveSessions)
	}
	if !resp.Msg.StartedAt.AsTime().Equal(now) {
		t.Errorf("StartedAt = %v, want %v", resp.Msg.StartedAt.AsTime(), now)
	}
}

func TestRoundTripIdentityList(t *testing.T) {
	created := time.Date(2026, 4, 10, 14, 0, 0, 0, time.UTC)
	revoked := time.Date(2026, 4, 10, 14, 32, 0, 0, time.UTC)
	backend := &fakeBackend{
		listIdentitiesReturn: []gpg.UID{
			{Index: 1, Validity: "u", Created: created, UID: "Active <a@example.com>"},
			{Index: 2, Validity: "r", Created: created, Revoked: revoked, UID: "Old <o@example.com>"},
		},
	}
	client, teardown := startTestServer(t, backend)
	defer teardown()

	resp, err := client.Identity.List(context.Background(), connect.NewRequest(&v1.ListIdentitiesRequest{
		VaultName: "personal",
	}))
	if err != nil {
		t.Fatalf("Identity.List: %v", err)
	}

	if backend.listIdentitiesCalls != 1 {
		t.Errorf("ListIdentities called %d times, want 1", backend.listIdentitiesCalls)
	}
	if backend.listIdentitiesArg != "personal" {
		t.Errorf("vault arg = %q, want personal", backend.listIdentitiesArg)
	}

	got := resp.Msg.Identities
	if len(got) != 2 {
		t.Fatalf("got %d identities, want 2", len(got))
	}

	if got[0].Index != 1 || got[0].Status != "ultimate" {
		t.Errorf("identity[0] = %+v", got[0])
	}
	if got[1].Index != 2 || got[1].Status != "revoked" {
		t.Errorf("identity[1] = %+v", got[1])
	}
	if !got[1].Revoked.AsTime().Equal(revoked) {
		t.Errorf("identity[1].Revoked = %v, want %v", got[1].Revoked.AsTime(), revoked)
	}
}

func TestRoundTripIdentityAdd(t *testing.T) {
	backend := &fakeBackend{}
	client, teardown := startTestServer(t, backend)
	defer teardown()

	_, err := client.Identity.Add(context.Background(), connect.NewRequest(&v1.AddIdentityRequest{
		VaultName: "work",
		Uid:       "New User <new@example.com>",
	}))
	if err != nil {
		t.Fatalf("Identity.Add: %v", err)
	}
	if backend.addIdentityCalls != 1 {
		t.Errorf("AddIdentity called %d times, want 1", backend.addIdentityCalls)
	}
	if backend.addIdentityVault != "work" {
		t.Errorf("vault = %q, want work", backend.addIdentityVault)
	}
	if backend.addIdentityUID != "New User <new@example.com>" {
		t.Errorf("uid = %q", backend.addIdentityUID)
	}
}

func TestRoundTripBackendError(t *testing.T) {
	backend := &fakeBackend{
		listIdentitiesErr: errors.New("vault not open"),
	}
	client, teardown := startTestServer(t, backend)
	defer teardown()

	_, err := client.Identity.List(context.Background(), connect.NewRequest(&v1.ListIdentitiesRequest{
		VaultName: "missing",
	}))
	if err == nil {
		t.Fatal("expected error from backend")
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("expected *connect.Error, got %T: %v", err, err)
	}
	if connectErr.Code() != connect.CodeInternal {
		t.Errorf("code = %v, want %v", connectErr.Code(), connect.CodeInternal)
	}
}

func TestUnixSocketClientConstruction(t *testing.T) {
	// Smoke test: NewUnixSocketClient should produce a non-nil client
	// without dialing the socket eagerly. Calls would fail if the socket
	// doesn't exist, but construction must succeed.
	client := NewUnixSocketClient("/nonexistent/path/that/does/not/exist")
	if client == nil {
		t.Fatal("NewUnixSocketClient returned nil")
	}
	if client.Daemon == nil || client.Vault == nil || client.Identity == nil {
		t.Error("sub-clients are nil")
	}
	client.Close()
}

// Compile-time check: the various unimplemented services declared in the
// proto must be picked up by the http.ServeMux. We don't exercise them in
// tests but a typo in the path would cause silent registration failure.
// This test just ensures the Server constructor doesn't panic.
func TestServerHandlerConstruction(t *testing.T) {
	srv := NewServer(&fakeBackend{})
	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

// Verify the http.Handler returned actually responds to a known Connect
// path with a 200 (or 400 for an invalid request, depending on transport).
// Mostly a smoke test that the routing works at all.
func TestHandlerRespondsToKnownPath(t *testing.T) {
	srv := httptest.NewServer(NewServer(&fakeBackend{}).Handler())
	defer srv.Close()

	// POST to a real Connect path with empty body — should not 404.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/gpgsmith.v1.DaemonService/Status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("status 404 for known Connect path: routing is broken")
	}
}
