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

		openToken    string // token returned by VaultOpen
		openErr      error
		discardToken string // last token passed to Discard
		discardCalls int

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
	return &v1.OpenResponse{Token: f.openToken}, nil
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
