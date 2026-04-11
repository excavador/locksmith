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

		// Group A mutation stubs.
		sealToken   string
		sealMessage string
		sealResp    *v1.SealResponse
		sealErr     error

		trustVault string
		trustFp    string
		trustErr   error

		keyRevokeToken string
		keyRevokeID    string
		keyRevokeErr   error

		idAddToken     string
		idAddUID       string
		idAddErr       error
		idRevokeToken  string
		idRevokeUID    string
		idRevokeErr    error
		idPrimaryToken string
		idPrimaryUID   string
		idPrimaryErr   error

		srvAddToken     string
		srvAddAlias     string
		srvAddURL       string
		srvAddErr       error
		srvRemoveToken  string
		srvRemoveAlias  string
		srvRemoveErr    error
		srvEnableToken  string
		srvEnableAlias  string
		srvEnableErr    error
		srvDisableToken string
		srvDisableAlias string
		srvDisableErr   error
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

func (f *fakeClient) VaultSeal(_ context.Context, token, message string) (*v1.SealResponse, error) {
	f.sealToken = token
	f.sealMessage = message
	if f.sealErr != nil {
		return nil, f.sealErr
	}
	if f.sealResp != nil {
		return f.sealResp, nil
	}
	return &v1.SealResponse{}, nil
}

func (f *fakeClient) VaultTrust(_ context.Context, vaultName, fingerprint string) error {
	f.trustVault = vaultName
	f.trustFp = fingerprint
	return f.trustErr
}

func (f *fakeClient) KeyRevoke(_ context.Context, token, keyID string) error {
	f.keyRevokeToken = token
	f.keyRevokeID = keyID
	return f.keyRevokeErr
}

func (f *fakeClient) IdentityAdd(_ context.Context, token, uid string) error {
	f.idAddToken = token
	f.idAddUID = uid
	return f.idAddErr
}

func (f *fakeClient) IdentityRevoke(_ context.Context, token, uid string) error {
	f.idRevokeToken = token
	f.idRevokeUID = uid
	return f.idRevokeErr
}

func (f *fakeClient) IdentityPrimary(_ context.Context, token, uid string) error {
	f.idPrimaryToken = token
	f.idPrimaryUID = uid
	return f.idPrimaryErr
}

func (f *fakeClient) ServerAdd(_ context.Context, token, alias, url string) error {
	f.srvAddToken = token
	f.srvAddAlias = alias
	f.srvAddURL = url
	return f.srvAddErr
}

func (f *fakeClient) ServerRemove(_ context.Context, token, alias string) error {
	f.srvRemoveToken = token
	f.srvRemoveAlias = alias
	return f.srvRemoveErr
}

func (f *fakeClient) ServerEnable(_ context.Context, token, alias string) error {
	f.srvEnableToken = token
	f.srvEnableAlias = alias
	return f.srvEnableErr
}

func (f *fakeClient) ServerDisable(_ context.Context, token, alias string) error {
	f.srvDisableToken = token
	f.srvDisableAlias = alias
	return f.srvDisableErr
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

// -----------------------------------------------------------------------------
// Group A mutation handler tests (v0.6.0).
// -----------------------------------------------------------------------------

func postForm(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string, form url.Values) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func getWithCookie(t *testing.T, ts *httptest.Server, cookie *http.Cookie, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+path, nil)
	req.AddCookie(cookie)
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func TestIdentityAdd_POST_CallsDaemonAndRedirects(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("uid", "Alice <a@example.com>")
	resp := postForm(t, ts, cookie, "/vault/work/identities/add", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if fake.idAddToken != "sess-1" {
		t.Errorf("token = %q, want sess-1", fake.idAddToken)
	}
	if fake.idAddUID != "Alice <a@example.com>" {
		t.Errorf("uid = %q", fake.idAddUID)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/vault/work/identities") {
		t.Errorf("location = %q", loc)
	}
}

func TestIdentityAdd_EmptyUID_FlashesError(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("uid", "   ")
	resp := postForm(t, ts, cookie, "/vault/work/identities/add", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if fake.idAddUID != "" {
		t.Errorf("daemon should NOT be called for empty uid; got %q", fake.idAddUID)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "err=") {
		t.Errorf("location %q missing err flash", loc)
	}
}

func TestIdentityRevoke_GET_ShowsConfirmPage(t *testing.T) {
	srv, ts := newTestServer(t, &fakeClient{})
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	resp := getWithCookie(t, ts, cookie, "/vault/work/identities/revoke?uid="+url.QueryEscape("Bob <b@example.com>"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "Confirm") {
		t.Errorf("confirm page missing 'Confirm': %s", html)
	}
	if !strings.Contains(html, "Bob") {
		t.Errorf("confirm page missing uid: %s", html)
	}
	if !strings.Contains(html, `action="/vault/work/identities/revoke"`) {
		t.Errorf("confirm form action missing")
	}
}

func TestIdentityRevoke_POST_CallsDaemonAndRedirects(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("uid", "Bob <b@example.com>")
	resp := postForm(t, ts, cookie, "/vault/work/identities/revoke", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.idRevokeUID != "Bob <b@example.com>" || fake.idRevokeToken != "sess-1" {
		t.Errorf("daemon call = (%q, %q)", fake.idRevokeToken, fake.idRevokeUID)
	}
}

func TestIdentityPrimary_POST_CallsDaemon(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("uid", "Carol <c@example.com>")
	resp := postForm(t, ts, cookie, "/vault/work/identities/primary", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.idPrimaryUID != "Carol <c@example.com>" {
		t.Errorf("primary uid = %q", fake.idPrimaryUID)
	}
}

func TestServerAdd_POST_CallsDaemon(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("alias", "ks1")
	form.Set("url", "hkps://keys.example.com")
	resp := postForm(t, ts, cookie, "/vault/work/servers/add", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.srvAddAlias != "ks1" || fake.srvAddURL != "hkps://keys.example.com" {
		t.Errorf("server add args = (%q, %q)", fake.srvAddAlias, fake.srvAddURL)
	}
}

func TestServerAdd_InvalidInput_FlashesError(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("alias", "")
	form.Set("url", "hkps://keys.example.com")
	resp := postForm(t, ts, cookie, "/vault/work/servers/add", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.srvAddAlias != "" {
		t.Errorf("daemon should NOT be called; alias = %q", fake.srvAddAlias)
	}
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Errorf("missing err flash: %q", resp.Header.Get("Location"))
	}
}

func TestServerEnable_POST_CallsDaemon(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("alias", "ks1")
	resp := postForm(t, ts, cookie, "/vault/work/servers/enable", form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.srvEnableAlias != "ks1" {
		t.Errorf("enable alias = %q", fake.srvEnableAlias)
	}
}

func TestServerDisable_POST_CallsDaemon(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("alias", "ks1")
	resp := postForm(t, ts, cookie, "/vault/work/servers/disable", form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.srvDisableAlias != "ks1" {
		t.Errorf("disable alias = %q", fake.srvDisableAlias)
	}
}

func TestServerRemove_ConfirmThenPOST(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	// GET confirm
	resp := getWithCookie(t, ts, cookie, "/vault/work/servers/remove?alias=ks1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ks1") {
		t.Errorf("confirm body missing alias")
	}

	// POST confirm
	form := url.Values{}
	form.Set("alias", "ks1")
	post := postForm(t, ts, cookie, "/vault/work/servers/remove", form)
	defer post.Body.Close()
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("post status = %d", post.StatusCode)
	}
	if fake.srvRemoveAlias != "ks1" {
		t.Errorf("remove alias = %q", fake.srvRemoveAlias)
	}
}

func TestKeyRevoke_ConfirmThenPOST(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	resp := getWithCookie(t, ts, cookie, "/vault/work/keys/revoke?key_id=ABCD1234")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "ABCD1234") {
		t.Errorf("confirm body missing key_id")
	}

	form := url.Values{}
	form.Set("key_id", "ABCD1234")
	post := postForm(t, ts, cookie, "/vault/work/keys/revoke", form)
	defer post.Body.Close()
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("post status = %d", post.StatusCode)
	}
	if fake.keyRevokeID != "ABCD1234" {
		t.Errorf("revoke id = %q", fake.keyRevokeID)
	}
}

func TestVaultSeal_POST_UnbindsAndFlashes(t *testing.T) {
	fake := &fakeClient{
		sealResp: &v1.SealResponse{Snapshot: &v1.Snapshot{Filename: "snap-42.tar.age"}},
	}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	srv.tabs.bind(cookie.Value, "sess-1", "work")

	form := url.Values{}
	form.Set("message", "end of day")
	resp := postForm(t, ts, cookie, "/vault/work/seal", form)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.sealMessage != "end of day" || fake.sealToken != "sess-1" {
		t.Errorf("seal args = (%q, %q)", fake.sealToken, fake.sealMessage)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "snap-42.tar.age") {
		t.Errorf("flash missing filename: %q", loc)
	}
	tab := srv.tabs.get(cookie.Value)
	if tab == nil || tab.daemonToken != "" {
		t.Errorf("tab should be unbound after seal: %+v", tab)
	}
}

func TestVaultTrust_ConfirmShowsBothFingerprints(t *testing.T) {
	fake := &fakeClient{
		vaults: []*v1.VaultRegistryEntry{{
			Name:            "work",
			TrustedMasterFp: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		}},
	}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)
	// Trust does NOT require a bound tab.

	newFp := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	resp := getWithCookie(t, ts, cookie, "/vault/work/trust/confirm?fingerprint="+newFp)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	if !strings.Contains(html, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Errorf("confirm page missing old fp: %s", html)
	}
	if !strings.Contains(html, newFp) {
		t.Errorf("confirm page missing new fp: %s", html)
	}
}

func TestVaultTrust_POSTCallsDaemon(t *testing.T) {
	fake := &fakeClient{
		vaults: []*v1.VaultRegistryEntry{{Name: "work"}},
	}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)

	form := url.Values{}
	form.Set("fingerprint", "aaaabbbbccccddddeeeeffff00001111aaaa2222")
	resp := postForm(t, ts, cookie, "/vault/work/trust", form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.trustVault != "work" {
		t.Errorf("trust vault = %q", fake.trustVault)
	}
	if fake.trustFp != strings.ToUpper("aaaabbbbccccddddeeeeffff00001111aaaa2222") {
		t.Errorf("trust fp = %q", fake.trustFp)
	}
}

func TestVaultTrust_BadFingerprint_Flashes(t *testing.T) {
	fake := &fakeClient{}
	srv, ts := newTestServer(t, fake)
	cookie := seedCookie(t, srv)

	form := url.Values{}
	form.Set("fingerprint", "not-hex")
	resp := postForm(t, ts, cookie, "/vault/work/trust", form)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if fake.trustVault != "" {
		t.Errorf("daemon should NOT be called; got %q", fake.trustVault)
	}
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Errorf("missing err flash")
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
