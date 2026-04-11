package gpgsmith

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	v1 "github.com/excavador/locksmith/pkg/gen/gpgsmith/v1"
)

type (
	// fakeClient is a hand-rolled DaemonClient used by tests. Every
	// method records the session token it was called with so the test
	// can assert the web UI stamps the right per-tab token.
	fakeClient struct {
		vaults []*v1.VaultRegistryEntry

		openToken        string // token returned by VaultOpen
		openResumeOption *v1.ResumeOption
		openErr          error
		discardToken     string // last token passed to Discard
		discardCalls     int
		resumeToken      string
		resumeErr        error
		resumeLastAction v1.ResumeRequest_Action
		resumeLastPass   string
		resumeLastVault  string

		keyListToken string
		keyListErr   error
	}
)

func (f *fakeClient) VaultList(_ context.Context) (*v1.ListResponse, error) {
	return &v1.ListResponse{Vaults: f.vaults, DefaultVault: ""}, nil
}

func (f *fakeClient) VaultStatus(_ context.Context) (*v1.StatusVaultResponse, error) {
	return &v1.StatusVaultResponse{}, nil
}

func (f *fakeClient) VaultOpen(_ context.Context, _, _ string) (*v1.OpenResponse, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &v1.OpenResponse{Token: f.openToken, ResumeAvailable: f.openResumeOption}, nil
}

func (f *fakeClient) VaultResume(_ context.Context, vaultName, passphrase string, resume bool) (*v1.ResumeResponse, error) {
	f.resumeLastVault = vaultName
	f.resumeLastPass = passphrase
	if resume {
		f.resumeLastAction = v1.ResumeRequest_ACTION_RESUME
	} else {
		f.resumeLastAction = v1.ResumeRequest_ACTION_DISCARD
	}
	if f.resumeErr != nil {
		return nil, f.resumeErr
	}
	return &v1.ResumeResponse{Token: f.resumeToken}, nil
}

func (f *fakeClient) VaultDiscard(_ context.Context, token string) error {
	f.discardToken = token
	f.discardCalls++
	return nil
}

func (f *fakeClient) KeyList(_ context.Context, token string) (*v1.ListKeysResponse, error) {
	f.keyListToken = token
	if f.keyListErr != nil {
		return nil, f.keyListErr
	}
	return &v1.ListKeysResponse{}, nil
}

func (f *fakeClient) KeyStatus(_ context.Context, _ string) (*v1.KeyStatusResponse, error) {
	return &v1.KeyStatusResponse{}, nil
}

func (f *fakeClient) IdentityList(_ context.Context, _ string) (*v1.ListIdentitiesResponse, error) {
	return &v1.ListIdentitiesResponse{}, nil
}

func (f *fakeClient) CardInventory(_ context.Context, _ string) (*v1.InventoryResponse, error) {
	return &v1.InventoryResponse{}, nil
}

func (f *fakeClient) ServerList(_ context.Context, _ string) (*v1.ListServersResponse, error) {
	return &v1.ListServersResponse{}, nil
}

func (f *fakeClient) ServerLookup(_ context.Context, _ string) (*v1.LookupResponse, error) {
	return &v1.LookupResponse{}, nil
}

func (f *fakeClient) AuditShow(_ context.Context, _ string, _ int32) (*v1.ShowResponse, error) {
	return &v1.ShowResponse{}, nil
}

// newTestServer spins up a Server with a fake backend and returns both
// the server (so tests can reach into tabs/state) and an httptest
// server serving its Handler().
func newTestServer(t *testing.T, client *fakeClient) (*Server, *httptest.Server) {
	t.Helper()
	srv, err := NewServer(Config{Client: client})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// noRedirectClient returns an http.Client that does NOT follow
// redirects, so tests can inspect Location/Set-Cookie on the first
// hop.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestDashboard_NoCookie_Returns401(t *testing.T) {
	_, ts := newTestServer(t, &fakeClient{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestDashboard_WrongStartupToken_Returns401(t *testing.T) {
	_, ts := newTestServer(t, &fakeClient{})
	client := noRedirectClient()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/?t=WRONGTOKEN", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestDashboard_CorrectStartupToken_SetsCookieAndRedirects(t *testing.T) {
	srv, ts := newTestServer(t, &fakeClient{})
	client := noRedirectClient()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/?t="+srv.StartupToken(), nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("want Location /, got %q", loc)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == cookieName {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatalf("expected cookie %q to be set", cookieName)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie not HttpOnly+SameSite=Strict: %+v", cookie)
	}
}

func TestDashboard_WithCookie_Returns200(t *testing.T) {
	srv, ts := newTestServer(t, &fakeClient{
		vaults: []*v1.VaultRegistryEntry{{Name: "work", Path: "/tmp/work"}},
	})
	cookie := seedCookie(t, srv)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "work") {
		t.Fatalf("body missing vault name: %s", body)
	}
}

func TestVaultOpen_StoresTokenInTab(t *testing.T) {
	fake := &fakeClient{
		vaults:    []*v1.VaultRegistryEntry{{Name: "work"}},
		openToken: "token-abc",
	}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)

	form := url.Values{}
	form.Set("passphrase", "hunter2")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/vault/work/open", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	client := noRedirectClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST open: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}

	tab := srv.tabs.get(cookie.Value)
	if tab == nil {
		t.Fatal("tab lost")
	}
	if tab.daemonToken != "token-abc" {
		t.Fatalf("want daemonToken=token-abc, got %q", tab.daemonToken)
	}
	if tab.vaultName != "work" {
		t.Fatalf("want vaultName=work, got %q", tab.vaultName)
	}
}

// TestVaultOpen_ResumeAvailable_RedirectsToResumePrompt verifies that
// when the daemon reports a recoverable ephemeral, the web UI redirects
// to the per-tab resume prompt page and stashes the passphrase on the
// tab for the follow-up VaultResume call.
func TestVaultOpen_ResumeAvailable_RedirectsToResumePrompt(t *testing.T) {
	fake := &fakeClient{
		vaults:           []*v1.VaultRegistryEntry{{Name: "work"}},
		openResumeOption: &v1.ResumeOption{CanonicalBase: "snap.tar.age", Status: "idle-sealed"},
	}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)

	form := url.Values{}
	form.Set("passphrase", "hunter2")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/vault/work/open", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("POST open: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/vault/work/resume" {
		t.Errorf("Location = %q, want /vault/work/resume", got)
	}
	tab := srv.tabs.get(cookie.Value)
	if tab == nil || tab.pendingResume == nil {
		t.Fatal("pending resume not stashed on tab")
	}
	if tab.pendingResume.vaultName != "work" {
		t.Errorf("pendingResume.vaultName = %q", tab.pendingResume.vaultName)
	}
	if tab.pendingResume.passphrase != "hunter2" {
		t.Errorf("pendingResume.passphrase = %q", tab.pendingResume.passphrase)
	}
	if tab.daemonToken != "" {
		t.Errorf("daemonToken = %q, want empty (no bind until resume decision)", tab.daemonToken)
	}
}

// TestVaultResume_POSTCallsDaemonAndBinds verifies the POST /resume flow:
// "resume" action forwards to the daemon, receives a token, and binds it
// to the tab (clearing pendingResume).
func TestVaultResume_POSTCallsDaemonAndBinds(t *testing.T) {
	fake := &fakeClient{resumeToken: "resumed-token"}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)

	// Stash a pending resume (simulates what handleVaultOpen did).
	srv.tabs.stashPendingResume(cookie.Value, "work", "hunter2")

	form := url.Values{}
	form.Set("action", "resume")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/vault/work/resume", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("POST resume: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/" {
		t.Errorf("Location = %q, want /", got)
	}
	if fake.resumeLastAction != v1.ResumeRequest_ACTION_RESUME {
		t.Errorf("daemon resume action = %v, want RESUME", fake.resumeLastAction)
	}
	if fake.resumeLastVault != "work" || fake.resumeLastPass != "hunter2" {
		t.Errorf("daemon resume call = (%q, %q)", fake.resumeLastVault, fake.resumeLastPass)
	}
	tab := srv.tabs.get(cookie.Value)
	if tab.daemonToken != "resumed-token" {
		t.Errorf("tab.daemonToken = %q, want resumed-token", tab.daemonToken)
	}
	if tab.pendingResume != nil {
		t.Error("pendingResume should be cleared after resume")
	}
}

func TestKeys_WithoutBoundVault_Returns400(t *testing.T) {
	srv, ts := newTestServer(t, &fakeClient{})
	cookie := seedCookie(t, srv)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/vault/work/keys", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", resp.StatusCode)
	}
}

func TestKeys_WrongVaultName_Returns404(t *testing.T) {
	fake := &fakeClient{openToken: "t1"}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	// Manually bind the tab to "work".
	srv.tabs.bind(cookie.Value, "t1", "work")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/vault/other/keys", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestKeys_PassesSessionToken(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "session-xyz", "work")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/vault/work/keys", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if fake.keyListToken != "session-xyz" {
		t.Fatalf("want session-xyz, got %q", fake.keyListToken)
	}
}

func TestVaultDiscard_ClearsTabAndCallsDaemon(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "session-xyz", "work")

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+"/vault/work/discard", nil)
	req.AddCookie(cookie)
	client := noRedirectClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", resp.StatusCode)
	}
	if fake.discardCalls != 1 || fake.discardToken != "session-xyz" {
		t.Fatalf("want 1 discard call with token session-xyz, got calls=%d token=%q",
			fake.discardCalls, fake.discardToken)
	}
	tab := srv.tabs.get(cookie.Value)
	if tab == nil || tab.daemonToken != "" {
		t.Fatalf("tab token not cleared: %+v", tab)
	}
}

// seedCookie performs the startup-token handshake and returns the
// issued cookie so subsequent requests can skip reauth.
func seedCookie(t *testing.T, srv *Server) *http.Cookie {
	t.Helper()
	// Directly create a tab to avoid threading an httptest client for
	// every test that needs an authenticated session. This mirrors
	// what authMiddleware does on a successful startup-token hit.
	token := newRandomToken()
	srv.tabs.create(token)
	return &http.Cookie{Name: cookieName, Value: token}
}
