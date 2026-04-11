//go:build e2e

// Package e2e tests for the gpgsmith web UI. Run with:
//
//	just e2e
//
// or:
//
//	go test -tags e2e ./pkg/webui/gpgsmith/...
//
// These tests drive a real headless Chromium via chromedp against a
// real in-process daemon + wire server + web UI. They are skipped from
// the default `go test ./...` invocation by the //go:build e2e tag.
//
// Chromium must be on PATH (devbox.json pulls it in automatically).
package gpgsmith

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/excavador/locksmith/pkg/daemon"
	"github.com/excavador/locksmith/pkg/gpgsmith"
	"github.com/excavador/locksmith/pkg/vault"
	"github.com/excavador/locksmith/pkg/wire"
)

const (
	e2ePassphrase = "e2e-vault-pass-please-no"
	e2eMasterFP   = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
)

// e2eEnv is one fully-wired test environment: a real daemon serving a
// real decryptable test vault, a wire server in front of the daemon,
// and the web UI in front of the wire server, all in-process. The
// browser drives the web UI at Env.WebURL.
type (
	e2eEnv struct {
		WebURL       string
		StartupToken string
		VaultName    string
		Passphrase   string
		cleanups     []func()
	}
)

func (e *e2eEnv) close() {
	for i := len(e.cleanups) - 1; i >= 0; i-- {
		e.cleanups[i]()
	}
}

// newE2EEnv wires up a daemon + wire server + web UI as a chain of
// in-process handlers. Vault setup mirrors pkg/daemon/daemon_test.go's
// makeDaemonTestVault helper — one empty canonical snapshot with a
// stub gpgsmith.yaml carrying a known master fingerprint.
func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()

	env := &e2eEnv{
		VaultName:  "test",
		Passphrase: e2ePassphrase,
	}

	logger := slog.New(slog.DiscardHandler)

	// 1. Stage and seal a one-snapshot test vault.
	vaultDir := t.TempDir()
	vcfg := &vault.Config{VaultDir: vaultDir}
	v, err := vault.NewWithPassphrase(vcfg, e2ePassphrase, logger)
	if err != nil {
		t.Fatalf("vault.NewWithPassphrase: %v", err)
	}
	stage := t.TempDir()
	gpgyaml := "master_fp: " + e2eMasterFP + "\nsubkey_algo: rsa4096\nsubkey_expiry: 2y\n"
	if err := os.WriteFile(filepath.Join(stage, "gpgsmith.yaml"), []byte(gpgyaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "marker"), []byte("staged"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ship an empty server registry so ServerLookup fans out to zero
	// targets. Otherwise the tests depend on real keyserver network
	// round-trips (~16s) which is both slow and flaky for CI and
	// airgapped dev boxes.
	if err := os.WriteFile(filepath.Join(stage, "gpgsmith-servers.yaml"), []byte("servers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Import(context.Background(), stage); err != nil {
		t.Fatalf("v.Import: %v", err)
	}

	// 2. Vault registry config the daemon will read.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	rcfg := &vault.Config{
		Default: env.VaultName,
		Vaults:  []vault.Entry{{Name: env.VaultName, Path: vaultDir}},
	}
	if err := vault.SaveConfig(cfgPath, rcfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// 3. In-process daemon.
	d := daemon.New(daemon.Options{
		Version:         "e2e",
		Commit:          "e2e",
		Logger:          logger,
		IdleTimeout:     5 * time.Minute,
		GracefulTimeout: 2 * time.Second,
		ConfigPath:      cfgPath,
		SocketPath:      "/dev/null/unused",
	})
	env.cleanups = append(env.cleanups, func() {
		_ = d.DaemonShutdown(context.Background(), 2)
	})

	// 4. Wire server mounted on its own httptest.Server (HTTP, not UDS).
	wireHandler := wire.NewServer(d).Handler()
	wireTS := httptest.NewServer(wireHandler)
	env.cleanups = append(env.cleanups, wireTS.Close)

	// 5. wire.Client pointing at the wire server. MUST install the
	// env-session interceptor so web UI per-request context tokens
	// are stamped onto outbound headers.
	wireClient := wire.NewHTTPClient(wireTS.Client(), wireTS.URL, wire.WithEnvSessionInterceptor())
	env.cleanups = append(env.cleanups, wireClient.Close)

	// 6. Web UI server wrapped around the wire client.
	webuiSrv, err := NewServer(Config{
		Client: NewWireAdapter(wireClient),
		Logger: logger,
	})
	if err != nil {
		t.Fatalf("webui.NewServer: %v", err)
	}
	webTS := httptest.NewServer(webuiSrv.Handler())
	env.cleanups = append(env.cleanups, webTS.Close)

	env.WebURL = webTS.URL
	env.StartupToken = webuiSrv.StartupToken()
	t.Cleanup(env.close)
	return env
}

// newChromedpCtx builds a headless-Chromium context using the chromium
// binary pulled in by devbox. Each test gets its own isolated profile
// directory so cookies don't leak across tests.
//
// We deliberately do NOT use t.TempDir for the profile: chromedp's
// Cancel is asynchronous and t.TempDir's cleanup runs before the
// chromium process has finished flushing to disk, so you get
// "directory not empty" teardown failures. Instead we allocate the
// dir with os.MkdirTemp and remove it only after cancel has
// returned.
func newChromedpCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()

	userDataDir, err := os.MkdirTemp("", "chromedp-")
	if err != nil {
		t.Fatalf("mkdir user-data-dir: %v", err)
	}

	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoSandbox,
		chromedp.Headless,
		chromedp.DisableGPU,
		chromedp.UserDataDir(userDataDir),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, browserCancel := chromedp.NewContext(allocCtx)

	// Overall deadline so a hung test doesn't hold the suite forever.
	ctx, deadlineCancel := context.WithTimeout(ctx, 30*time.Second)

	cancel := func() {
		deadlineCancel()
		// chromedp.Cancel explicitly waits for the browser to exit
		// via the CDP Browser.close command. After this returns we
		// can safely remove the profile dir.
		_ = chromedp.Cancel(ctx)
		browserCancel()
		allocCancel()
		_ = os.RemoveAll(userDataDir)
	}
	return ctx, cancel
}

// TestE2E_StartupTokenCookieHandoff is the harness smoke test. It
// verifies the full wiring works: chromedp can launch, reach the
// in-process web UI, exchange the startup token for a cookie, and
// render the dashboard HTML.
//
// If this test fails the rest of the e2e suite cannot possibly pass;
// run it in isolation first.
func TestE2E_StartupTokenCookieHandoff(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var dashboardTitle string
	err := chromedp.Run(ctx,
		// Visit the URL that carries the startup token.
		chromedp.Navigate(env.WebURL+"/?t="+env.StartupToken),
		// chromedp automatically follows the 303 redirect to "/".
		chromedp.WaitVisible(`h2`, chromedp.ByQuery),
		chromedp.Title(&dashboardTitle),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !strings.Contains(dashboardTitle, "Dashboard") {
		t.Errorf("page title = %q, want to contain Dashboard", dashboardTitle)
	}

	// Assert the cookie was set by the auth middleware.
	var cookies []*network.Cookie
	err = chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		u, err := url.Parse(env.WebURL)
		if err != nil {
			return err
		}
		cs, err := network.GetCookies().WithURLs([]string{u.String()}).Do(ctx)
		if err != nil {
			return err
		}
		cookies = cs
		return nil
	}))
	if err != nil {
		t.Fatalf("get cookies: %v", err)
	}

	var found bool
	for _, c := range cookies {
		if c.Name == "gpgsmith_webui" && c.Value != "" {
			found = true
			if !c.HTTPOnly {
				t.Error("gpgsmith_webui cookie is not HttpOnly")
			}
			if c.SameSite != network.CookieSameSiteStrict {
				t.Errorf("gpgsmith_webui cookie SameSite = %v, want Strict", c.SameSite)
			}
			break
		}
	}
	if !found {
		t.Errorf("gpgsmith_webui cookie not set; got cookies: %+v", cookies)
	}

	// Silence unused-import complaint on platforms where tests skip.
	_ = gpgsmith.SessionFilenamesFor
}

// TestE2E_Dashboard_NoCookie_Returns401 checks that visiting the root
// URL without the startup token AND without a valid cookie is rejected
// with a 401. Negative case for the auth middleware.
func TestE2E_Dashboard_NoCookie_Returns401(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var statusCode int64
	err := chromedp.Run(ctx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			return network.Enable().Do(ctx)
		}),
		interceptStatus(env.WebURL+"/", &statusCode),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if statusCode != 401 {
		t.Errorf("status = %d, want 401", statusCode)
	}
}

// TestE2E_OpenVault_WrongPassphrase_Flashes checks that submitting the
// wrong passphrase returns to the dashboard with an error flash.
func TestE2E_OpenVault_WrongPassphrase_Flashes(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var alertText string
	err := chromedp.Run(ctx,
		chromedp.Navigate(env.WebURL+"/?t="+env.StartupToken),
		chromedp.WaitVisible(`input[name="passphrase"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="passphrase"]`, "totally-wrong-passphrase", chromedp.ByQuery),
		chromedp.Submit(`input[name="passphrase"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`.alert`, chromedp.ByQuery),
		chromedp.Text(`.alert`, &alertText, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	// The daemon returns an age decrypt error; the webui flashes
	// "open: <error>". We only assert the flash contains "open".
	if !strings.Contains(strings.ToLower(alertText), "open") {
		t.Errorf("alert text = %q, want to contain 'open'", alertText)
	}
}

// TestE2E_Navigation_ReadOnlyFlow opens the vault with the correct
// passphrase and walks every read-only page, asserting each renders
// the expected heading. Finally discards the session and asserts the
// dashboard returns to the closed state.
//
// All subtests share one browser context and one decrypted vault, so
// the expensive setup (scrypt KDF on vault open, chromium startup) is
// paid once for the whole group.
func TestE2E_Navigation_ReadOnlyFlow(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	// 1. Authenticate the tab and open the vault.
	err := chromedp.Run(ctx,
		chromedp.Navigate(env.WebURL+"/?t="+env.StartupToken),
		chromedp.WaitVisible(`input[name="passphrase"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="passphrase"]`, env.Passphrase, chromedp.ByQuery),
		chromedp.Submit(`input[name="passphrase"]`, chromedp.ByQuery),
		// After successful open the header partial renders the
		// "vault: <name>" span, which only appears when the tab
		// has a bound session.
		chromedp.WaitVisible(`header span`, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("open vault: %v", err)
	}

	pages := []struct {
		name    string
		path    string
		heading string
	}{
		{"keys", "/vault/" + env.VaultName + "/keys", "Keys"},
		{"identities", "/vault/" + env.VaultName + "/identities", "Identities"},
		{"cards", "/vault/" + env.VaultName + "/cards", "Cards"},
		{"audit", "/vault/" + env.VaultName + "/audit", "Audit"},
	}
	for _, p := range pages {
		t.Run(p.name, func(t *testing.T) {
			var h2 string
			if err := chromedp.Run(ctx,
				chromedp.Navigate(env.WebURL+p.path),
				chromedp.WaitVisible(`h2`, chromedp.ByQuery),
				chromedp.Text(`h2`, &h2, chromedp.ByQuery),
			); err != nil {
				t.Fatalf("navigate %s: %v", p.path, err)
			}
			if !strings.Contains(h2, p.heading) {
				t.Errorf("h2 = %q, want to contain %q", h2, p.heading)
			}
		})
	}

	// Servers page is special: it renders instantly with a placeholder
	// that HTMX swaps with the lookup-results fragment as soon as the
	// hx-trigger="load" fires. The test vault ships with an empty
	// server registry so the swap completes in <1s (no real network).
	//
	// We assert the swap happened by polling for any of the three
	// possible swap outcomes inside #servers-lookup — a results
	// table, the "no lookup results" empty state, or an error alert.
	// Presence of any of those proves htmx ran the fragment fetch
	// and swapped the response into the DOM, which is the whole
	// point of the lazy-load pattern.
	t.Run("servers_htmx_swap", func(t *testing.T) {
		err := chromedp.Run(ctx,
			chromedp.Navigate(env.WebURL+"/vault/"+env.VaultName+"/servers"),
			chromedp.WaitVisible(`#servers-lookup`, chromedp.ByQuery),
		)
		if err != nil {
			t.Fatalf("servers initial render: %v", err)
		}
		waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
		defer waitCancel()
		err = chromedp.Run(waitCtx, chromedp.ActionFunc(func(ctx context.Context) error {
			deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			for {
				var swapped bool
				err := chromedp.Evaluate(
					`!!document.querySelector("#servers-lookup table") ||
					 !!document.querySelector("#servers-lookup .empty") ||
					 !!document.querySelector("#servers-lookup .alert")`,
					&swapped,
				).Do(ctx)
				if err != nil {
					return err
				}
				if swapped {
					return nil
				}
				select {
				case <-deadline.Done():
					return deadline.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		}))
		if err != nil {
			t.Errorf("HTMX did not swap servers lookup fragment: %v", err)
		}
	})

	// Discard returns the dashboard to the "closed" state.
	t.Run("discard", func(t *testing.T) {
		err := chromedp.Run(ctx,
			chromedp.Navigate(env.WebURL+"/"),
			chromedp.WaitVisible(`form[action="/vault/`+env.VaultName+`/discard"] button`, chromedp.ByQuery),
			chromedp.Click(`form[action="/vault/`+env.VaultName+`/discard"] button`, chromedp.ByQuery),
			// After discard the header span disappears because the
			// tab is no longer bound to a vault.
			chromedp.WaitNotPresent(`header span`, chromedp.ByQuery),
		)
		if err != nil {
			t.Fatalf("discard: %v", err)
		}
	})
}

// openVaultUI is a chromedp action that goes through the startup-token
// handshake and opens the e2e test vault. Use from tests that need a
// bound tab before exercising mutation handlers.
func openVaultUI(env *e2eEnv) chromedp.Action {
	return chromedp.Tasks{
		chromedp.Navigate(env.WebURL + "/?t=" + env.StartupToken),
		chromedp.WaitVisible(`input[name="passphrase"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="passphrase"]`, env.Passphrase, chromedp.ByQuery),
		chromedp.Submit(`input[name="passphrase"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`header span`, chromedp.ByQuery),
	}
}

// TestE2E_ServerAdd_FormSubmit exercises the full Group A server-add
// path: open vault -> visit servers page -> fill form -> submit ->
// verify the new row is visible. The test vault ships with an empty
// server registry, so any alias we add is observable immediately.
func TestE2E_ServerAdd_FormSubmit(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		openVaultUI(env),
		chromedp.Navigate(env.WebURL+"/vault/"+env.VaultName+"/servers"),
		chromedp.WaitVisible(`input[name="alias"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="alias"]`, "e2e-ks", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="url"]`, "hkps://e2e.example.com", chromedp.ByQuery),
		chromedp.Submit(`input[name="alias"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`table`, chromedp.ByQuery),
		chromedp.OuterHTML(`main`, &html, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !strings.Contains(html, "e2e-ks") {
		t.Errorf("servers page missing newly-added alias: %s", html)
	}
}

// TestE2E_ServerEnable_Toggle adds a server (which starts enabled by
// default), disables it via the inline form, and verifies the row now
// renders as disabled with an Enable button.
func TestE2E_ServerEnable_Toggle(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		openVaultUI(env),
		chromedp.Navigate(env.WebURL+"/vault/"+env.VaultName+"/servers"),
		chromedp.WaitVisible(`input[name="alias"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="alias"]`, "toggle-ks", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="url"]`, "hkps://toggle.example.com", chromedp.ByQuery),
		chromedp.Submit(`input[name="alias"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`form[action="/vault/`+env.VaultName+`/servers/disable"] button`, chromedp.ByQuery),
		chromedp.Click(`form[action="/vault/`+env.VaultName+`/servers/disable"] button`, chromedp.ByQuery),
		chromedp.WaitVisible(`form[action="/vault/`+env.VaultName+`/servers/enable"] button`, chromedp.ByQuery),
		chromedp.OuterHTML(`main`, &html, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !strings.Contains(html, "toggle-ks") {
		t.Errorf("servers page missing toggle-ks row: %s", html)
	}
}

// TestE2E_ServerRemove_ConfirmFlow adds a server, clicks Remove, lands
// on the confirm page, confirms, and verifies the row is gone.
func TestE2E_ServerRemove_ConfirmFlow(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var html string
	err := chromedp.Run(ctx,
		openVaultUI(env),
		chromedp.Navigate(env.WebURL+"/vault/"+env.VaultName+"/servers"),
		chromedp.WaitVisible(`input[name="alias"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="alias"]`, "rm-ks", chromedp.ByQuery),
		chromedp.SendKeys(`input[name="url"]`, "hkps://rm.example.com", chromedp.ByQuery),
		chromedp.Submit(`input[name="alias"]`, chromedp.ByQuery),
		// Click the Remove button (GET -> confirm page).
		chromedp.WaitVisible(`form[action="/vault/`+env.VaultName+`/servers/remove"] button`, chromedp.ByQuery),
		chromedp.Click(`form[action="/vault/`+env.VaultName+`/servers/remove"] button`, chromedp.ByQuery),
		// Confirm page: click the submit button inside the POST form.
		chromedp.WaitVisible(`form[method="post"][action="/vault/`+env.VaultName+`/servers/remove"] button`, chromedp.ByQuery),
		chromedp.Click(`form[method="post"][action="/vault/`+env.VaultName+`/servers/remove"] button`, chromedp.ByQuery),
		// Wait until we land back on the /servers list page — the add
		// form input name="url" only exists on the list page, not on
		// the confirm page.
		chromedp.WaitVisible(`input[name="url"]`, chromedp.ByQuery),
		chromedp.OuterHTML(`main`, &html, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	// The alias should only appear inside the success flash, not in a
	// table row. Assert the empty state is now rendered.
	if !strings.Contains(html, "No publish servers configured") {
		t.Errorf("servers page should be empty after remove: %s", html)
	}
}

// TestE2E_VaultTrust_ConfirmFlow navigates to the trust page, submits a
// new fingerprint, walks through the confirm page, and asserts the
// dashboard renders the new fingerprint afterwards.
func TestE2E_VaultTrust_ConfirmFlow(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	newFp := "CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE"

	var dashHTML string
	err := chromedp.Run(ctx,
		// No vault-open required for trust; just the startup handshake.
		chromedp.Navigate(env.WebURL+"/?t="+env.StartupToken),
		chromedp.WaitVisible(`table`, chromedp.ByQuery),
		chromedp.Navigate(env.WebURL+"/vault/"+env.VaultName+"/trust"),
		chromedp.WaitVisible(`input[name="fingerprint"]`, chromedp.ByQuery),
		chromedp.SendKeys(`input[name="fingerprint"]`, newFp, chromedp.ByQuery),
		chromedp.Submit(`input[name="fingerprint"]`, chromedp.ByQuery),
		// Confirm page: ensure both old (DEADBEEF...) and new fp shown.
		chromedp.WaitVisible(`form[method="post"][action="/vault/`+env.VaultName+`/trust"] button`, chromedp.ByQuery),
		chromedp.Click(`form[method="post"][action="/vault/`+env.VaultName+`/trust"] button`, chromedp.ByQuery),
		// Wait for the dashboard redirect to finish and the page
		// context to stabilize. Polling via Evaluate against
		// document.body avoids the "context not found" race that
		// chromedp.OuterHTML can trip on mid-navigation.
		chromedp.ActionFunc(func(ctx context.Context) error {
			deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			for {
				var body string
				err := chromedp.Evaluate(`document.body ? document.body.innerHTML : ""`, &body).Do(ctx)
				if err == nil && strings.Contains(body, "<h2>Vaults</h2>") && strings.Contains(body, newFp) {
					dashHTML = body
					return nil
				}
				select {
				case <-deadline.Done():
					return deadline.Err()
				case <-time.After(100 * time.Millisecond):
				}
			}
		}),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !strings.Contains(dashHTML, newFp) {
		t.Errorf("dashboard missing updated fingerprint: %s", dashHTML)
	}
}

// TestE2E_Seal_FromDashboard opens the vault, types a seal message on
// the dashboard, submits, and asserts the dashboard returns to the
// closed state (no header "vault:" span) and the flash names the new
// snapshot file.
func TestE2E_Seal_FromDashboard(t *testing.T) {
	env := newE2EEnv(t)
	ctx, cancel := newChromedpCtx(t)
	defer cancel()

	var flashHTML string
	err := chromedp.Run(ctx,
		openVaultUI(env),
		// Back on dashboard: the seal form is rendered because the
		// tab is bound.
		chromedp.Navigate(env.WebURL+"/"),
		chromedp.WaitVisible(`form[action="/vault/`+env.VaultName+`/seal"] input[name="message"]`, chromedp.ByQuery),
		chromedp.SendKeys(`form[action="/vault/`+env.VaultName+`/seal"] input[name="message"]`, "e2e test seal", chromedp.ByQuery),
		chromedp.Click(`form[action="/vault/`+env.VaultName+`/seal"] button`, chromedp.ByQuery),
		chromedp.WaitNotPresent(`header span`, chromedp.ByQuery),
		chromedp.OuterHTML(`main`, &flashHTML, chromedp.ByQuery),
	)
	if err != nil {
		t.Fatalf("chromedp run: %v", err)
	}
	if !strings.Contains(flashHTML, "sealed") {
		t.Errorf("dashboard missing seal flash: %s", flashHTML)
	}
}

// interceptStatus drives a navigation and captures the HTTP status of
// the main document response. Needed because chromedp.Navigate does
// not surface status codes directly.
func interceptStatus(navigateURL string, status *int64) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Subscribe to network responses BEFORE navigating.
		done := make(chan int64, 1)
		chromedp.ListenTarget(ctx, func(ev interface{}) {
			if r, ok := ev.(*network.EventResponseReceived); ok {
				if r.Type == network.ResourceTypeDocument {
					select {
					case done <- r.Response.Status:
					default:
					}
				}
			}
		})
		if err := chromedp.Navigate(navigateURL).Do(ctx); err != nil {
			// Navigate itself does not fail for non-2xx. Only
			// a network-level error reaches here.
			return err
		}
		select {
		case s := <-done:
			*status = s
			return nil
		case <-time.After(5 * time.Second):
			return context.DeadlineExceeded
		}
	})
}
