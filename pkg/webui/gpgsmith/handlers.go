package gpgsmith

import (
	"bytes"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	hexFingerprintRe = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
)

type (
	// baseView is the data struct every template receives. Per-page
	// data lives in a named subfield (Dashboard, Keys, Audit, ...)
	// so the layout partial can access Title/VaultName/Error without
	// caring which page is being rendered.
	baseView struct {
		Title     string
		VaultName string // informational — taken from the tabState
		Error     string
		Flash     string // transient success message (e.g. "sealed: snapshot …")

		Dashboard  *dashboardView
		Keys       *keysView
		Identities *identitiesView
		Cards      *cardsView
		Servers    *serversView
		Audit      *auditView
		Resume     *resumeView
		Confirm    *confirmView
		Trust      *trustView
	}

	// confirmView backs the generic confirmation page used by every
	// destructive Group A operation. Hidden fields are emitted in
	// iteration order — don't rely on a specific order across renders.
	confirmView struct {
		Title        string
		Summary      string
		Resource     string
		ConfirmLabel string
		ConfirmURL   string // POST target
		CancelURL    string // where the Cancel link goes
		Hidden       []confirmHidden
	}
	confirmHidden struct {
		Name  string
		Value string
	}

	trustView struct {
		CurrentFp string
		NewFp     string // only set on the confirm sub-page
	}

	dashboardView struct {
		Vaults       []dashboardVault
		Sessions     []dashboardSession
		TabVaultName string
	}
	dashboardVault struct {
		Name          string
		Path          string
		IsDefault     bool
		TrustedFp     string
		OpenInTab     bool
		OpenElsewhere bool
	}
	dashboardSession struct {
		VaultName string
		Hostname  string
		StartedAt string
		Status    string
	}

	keysView struct {
		Keys []keyRow

		// Cards is the inventory entries for YubiKeys linked to this
		// vault (always available — read from gpgsmith-inventory.yaml).
		Cards []keysCardRow

		// LiveCardError is the error message from the live
		// `gpg --card-status` call, if any. Empty when the call
		// succeeded or no card is plugged in.
		LiveCardError string

		// LiveCardSerial is the serial of the card that gpg is
		// currently talking to, if any. Used to mark which inventory
		// row is "currently plugged in".
		LiveCardSerial string
	}
	keysCardRow struct {
		Serial        string
		Label         string
		Model         string
		Status        string
		CurrentlyLive bool
	}
	keyRow struct {
		KeyID      string
		Algo       string
		Usage      string
		Validity   string
		Created    string
		Expires    string
		CardSerial string
	}

	identitiesView struct {
		Identities []identityRow
	}
	identityRow struct {
		Index     int32
		Status    string
		Created   string
		Revoked   string
		UID       string
		IsRevoked bool
		IsPrimary bool
	}

	cardsView struct {
		Cards []cardRow
	}
	cardRow struct {
		Serial       string
		Label        string
		Model        string
		Provisioning string
		Status       string
		Description  string
	}

	serversView struct {
		Servers []serverRow
		Lookup  []lookupRow
	}
	serverRow struct {
		Alias   string
		Type    string
		URL     string
		Enabled bool
	}
	lookupRow struct {
		URL    string
		Status string
	}

	auditView struct {
		Limit   int
		Entries []auditRow
	}
	auditRow struct {
		Timestamp string
		Action    string
		Details   string
	}

	resumeView struct {
		VaultName     string
		Hostname      string
		StartedAt     string
		LastHeartbeat string
		Status        string
		Divergent     bool
	}
)

const (
	auditLimit = 50
)

// templateFuncs is the func map attached to every parsed template.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		// hasC reports whether a GPG usage string contains the
		// certification capability flag "C", which marks the master
		// (primary) key. Used by keys.html to hide the Revoke button
		// on the master key.
		"hasC": func(usage string) bool {
			return strings.ContainsAny(usage, "Cc")
		},
	}
}

// routes wires up the HTTP mux. Uses Go 1.22 method+path routing.
func (s *Server) routes() {
	// Static assets are public so the 401 HTML error page can still
	// load its stylesheet.
	sub, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(sub)))

	s.mux.HandleFunc("GET /{$}", s.handleDashboard)

	s.mux.HandleFunc("POST /vault/{name}/open", s.handleVaultOpen)
	s.mux.HandleFunc("GET /vault/{name}/resume", s.handleVaultResumePrompt)
	s.mux.HandleFunc("POST /vault/{name}/resume", s.handleVaultResume)
	s.mux.HandleFunc("POST /vault/{name}/discard", s.handleVaultDiscard)

	s.mux.HandleFunc("GET /vault/{name}/keys", s.handleKeys)
	s.mux.HandleFunc("GET /vault/{name}/identities", s.handleIdentities)
	s.mux.HandleFunc("GET /vault/{name}/cards", s.handleCards)
	s.mux.HandleFunc("GET /vault/{name}/servers", s.handleServers)
	s.mux.HandleFunc("GET /vault/{name}/servers/lookup", s.handleServersLookupFragment)
	s.mux.HandleFunc("GET /vault/{name}/audit", s.handleAudit)

	// Group A mutations (v0.6.0).
	s.mux.HandleFunc("POST /vault/{name}/seal", s.handleVaultSeal)
	s.mux.HandleFunc("GET /vault/{name}/trust", s.handleVaultTrustPage)
	s.mux.HandleFunc("GET /vault/{name}/trust/confirm", s.handleVaultTrustConfirm)
	s.mux.HandleFunc("POST /vault/{name}/trust", s.handleVaultTrust)
	s.mux.HandleFunc("GET /vault/{name}/keys/revoke", s.handleKeyRevokeConfirm)
	s.mux.HandleFunc("POST /vault/{name}/keys/revoke", s.handleKeyRevoke)
	s.mux.HandleFunc("POST /vault/{name}/identities/add", s.handleIdentityAdd)
	s.mux.HandleFunc("GET /vault/{name}/identities/revoke", s.handleIdentityRevokeConfirm)
	s.mux.HandleFunc("POST /vault/{name}/identities/revoke", s.handleIdentityRevoke)
	s.mux.HandleFunc("POST /vault/{name}/identities/primary", s.handleIdentityPrimary)
	s.mux.HandleFunc("POST /vault/{name}/servers/add", s.handleServerAdd)
	s.mux.HandleFunc("GET /vault/{name}/servers/remove", s.handleServerRemoveConfirm)
	s.mux.HandleFunc("POST /vault/{name}/servers/remove", s.handleServerRemove)
	s.mux.HandleFunc("POST /vault/{name}/servers/enable", s.handleServerEnable)
	s.mux.HandleFunc("POST /vault/{name}/servers/disable", s.handleServerDisable)
}

// render writes an HTML page. name is the template block name
// ("dashboard", "keys", ...) — each page template defines a top-level
// block under its page name which invokes header+body+footer.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, view *baseView) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, view); err != nil {
		s.logger.ErrorContext(r.Context(), "webui: render template",
			slog.String("template", name),
			slog.String("error", err.Error()),
		)
		http.Error(w, "internal render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// requireBoundTab extracts the tabState from the request context,
// confirms a daemon session is bound, and that the URL's {name} path
// parameter matches the bound vault. On failure it writes an error
// response and returns nil.
func (s *Server) requireBoundTab(w http.ResponseWriter, r *http.Request) *tabState {
	tab, ok := tabFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	if tab.daemonToken == "" {
		http.Error(w, "no vault is open in this tab", http.StatusBadRequest)
		return nil
	}
	want := r.PathValue("name")
	if want != "" && want != tab.vaultName {
		http.Error(w, "vault name does not match session", http.StatusNotFound)
		return nil
	}
	return tab
}

// =============================================================================
// Handlers
// =============================================================================

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tab, _ := tabFromContext(ctx)

	view := &baseView{Title: "Dashboard"}
	if tab != nil && tab.vaultName != "" {
		view.VaultName = tab.vaultName
	}
	if e := r.URL.Query().Get("err"); e != "" {
		view.Error = e
	}
	if f := r.URL.Query().Get("flash"); f != "" {
		view.Flash = f
	}

	dv := &dashboardView{}
	if tab != nil {
		dv.TabVaultName = tab.vaultName
	}

	listResp, err := s.client.VaultList(ctx)
	if err != nil {
		view.Error = "list vaults: " + err.Error()
		view.Dashboard = dv
		s.render(w, r, "dashboard", view)
		return
	}
	statusResp, err := s.client.VaultStatus(ctx)
	if err != nil {
		view.Error = "vault status: " + err.Error()
		view.Dashboard = dv
		s.render(w, r, "dashboard", view)
		return
	}

	openByName := make(map[string]bool)
	for _, sess := range statusResp.GetOpen() {
		openByName[sess.GetVaultName()] = true
		started := ""
		if ts := sess.GetStartedAt(); ts != nil {
			started = ts.AsTime().Format(time.RFC3339)
		}
		dv.Sessions = append(dv.Sessions, dashboardSession{
			VaultName: sess.GetVaultName(),
			Hostname:  sess.GetHostname(),
			StartedAt: started,
			Status:    sess.GetStatus(),
		})
	}

	defaultName := listResp.GetDefaultVault()
	for _, v := range listResp.GetVaults() {
		name := v.GetName()
		openHere := tab != nil && tab.vaultName == name && tab.daemonToken != ""
		dv.Vaults = append(dv.Vaults, dashboardVault{
			Name:          name,
			Path:          v.GetPath(),
			IsDefault:     name == defaultName,
			TrustedFp:     v.GetTrustedMasterFp(),
			OpenInTab:     openHere,
			OpenElsewhere: !openHere && openByName[name],
		})
	}
	view.Dashboard = dv
	s.render(w, r, "dashboard", view)
}

func (s *Server) handleVaultOpen(w http.ResponseWriter, r *http.Request) {
	tab, ok := tabFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	passphrase := r.PostForm.Get("passphrase")
	if name == "" || passphrase == "" {
		http.Error(w, "missing vault name or passphrase", http.StatusBadRequest)
		return
	}

	if tab.daemonToken != "" {
		http.Error(w, "this tab already has a vault open; discard it first", http.StatusConflict)
		return
	}

	resp, err := s.client.VaultOpen(r.Context(), name, passphrase)
	if err != nil {
		s.logger.WarnContext(r.Context(), "webui: vault open failed",
			slog.String("vault", name),
			slog.String("error", err.Error()),
		)
		// Redirect home with a flash-ish error rendered by re-running
		// the dashboard handler with an inline error.
		http.Redirect(w, r, "/?err="+stringEscape("open: "+err.Error()), http.StatusSeeOther)
		return
	}

	token := resp.GetToken()
	if token == "" {
		if ra := resp.GetResumeAvailable(); ra != nil {
			// Daemon found a recoverable ephemeral for this vault and
			// needs the user to decide resume / discard / cancel.
			// Stash the passphrase in the tab's in-memory state so the
			// user does not have to retype it, then render the resume
			// prompt page.
			if !s.tabs.stashPendingResume(tab.cookieToken, name, passphrase) {
				http.Error(w, "tab lost", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, "/vault/"+name+"/resume", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?err="+stringEscape("daemon returned empty token"), http.StatusSeeOther)
		return
	}
	if !s.tabs.bind(tab.cookieToken, token, name) {
		http.Error(w, "tab lost", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleVaultResumePrompt(w http.ResponseWriter, r *http.Request) {
	tab, ok := tabFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if tab.pendingResume == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	name := r.PathValue("name")
	if name != tab.pendingResume.vaultName {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	view := &baseView{Title: "Resume session", Resume: &resumeView{VaultName: name}}
	// Fetch the ephemeral details so the user can see what they're
	// about to resume (started_at, last_heartbeat, divergent, etc.).
	if status, err := s.client.VaultStatus(r.Context()); err == nil {
		for _, rec := range status.GetRecoverable() {
			if rec.GetCanonicalBase() == "" {
				continue
			}
			if rec.GetHostname() != "" {
				view.Resume.Hostname = rec.GetHostname()
			}
			if ts := rec.GetStartedAt(); ts != nil {
				view.Resume.StartedAt = ts.AsTime().Format("2006-01-02 15:04:05 MST")
			}
			if ts := rec.GetLastHeartbeat(); ts != nil {
				view.Resume.LastHeartbeat = ts.AsTime().Format("2006-01-02 15:04:05 MST")
			}
			view.Resume.Status = rec.GetStatus()
			view.Resume.Divergent = rec.GetDivergent()
			break
		}
	}
	s.render(w, r, "resume", view)
}

func (s *Server) handleVaultResume(w http.ResponseWriter, r *http.Request) {
	tab, ok := tabFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	action := r.PostForm.Get("action")
	switch action {
	case "resume", "discard":
	case "cancel":
		s.tabs.takePendingResume(tab.cookieToken)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	default:
		http.Error(w, "missing or unknown action", http.StatusBadRequest)
		return
	}

	pending := s.tabs.takePendingResume(tab.cookieToken)
	if pending == nil {
		http.Redirect(w, r, "/?err="+stringEscape("no pending resume for this tab"), http.StatusSeeOther)
		return
	}
	if pending.vaultName != name {
		http.Redirect(w, r, "/?err="+stringEscape("resume vault name mismatch"), http.StatusSeeOther)
		return
	}

	resp, err := s.client.VaultResume(r.Context(), name, pending.passphrase, action == "resume")
	if err != nil {
		s.logger.WarnContext(r.Context(), "webui: vault resume failed",
			slog.String("vault", name),
			slog.String("action", action),
			slog.String("error", err.Error()),
		)
		http.Redirect(w, r, "/?err="+stringEscape(action+": "+err.Error()), http.StatusSeeOther)
		return
	}
	token := resp.GetToken()
	if token == "" {
		http.Redirect(w, r, "/?err="+stringEscape("daemon returned empty token after "+action), http.StatusSeeOther)
		return
	}
	if !s.tabs.bind(tab.cookieToken, token, name) {
		http.Error(w, "tab lost", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleVaultDiscard(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := s.client.VaultDiscard(r.Context(), tab.daemonToken); err != nil {
		s.logger.WarnContext(r.Context(), "webui: vault discard failed",
			slog.String("error", err.Error()),
		)
	}
	s.tabs.unbind(tab.cookieToken)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	view := &baseView{Title: "Keys", VaultName: tab.vaultName}
	if e := r.URL.Query().Get("err"); e != "" {
		view.Error = e
	}
	if f := r.URL.Query().Get("flash"); f != "" {
		view.Flash = f
	}

	listResp, err := s.client.KeyList(r.Context(), tab.daemonToken)
	if err != nil {
		view.Error = err.Error()
		view.Keys = &keysView{}
		s.render(w, r, "keys", view)
		return
	}
	statusResp, err := s.client.KeyStatus(r.Context(), tab.daemonToken)
	if err != nil {
		view.Error = err.Error()
		view.Keys = &keysView{}
		s.render(w, r, "keys", view)
		return
	}

	kv := &keysView{}
	for _, k := range listResp.GetKeys() {
		created := ""
		if ts := k.GetCreated(); ts != nil {
			created = ts.AsTime().Format("2006-01-02")
		}
		expires := ""
		if ts := k.GetExpires(); ts != nil && !ts.AsTime().IsZero() {
			expires = ts.AsTime().Format("2006-01-02")
		}
		kv.Keys = append(kv.Keys, keyRow{
			KeyID:      k.GetKeyId(),
			Algo:       k.GetAlgorithm(),
			Usage:      k.GetUsage(),
			Validity:   k.GetValidity(),
			Created:    created,
			Expires:    expires,
			CardSerial: k.GetCardSerial(),
		})
	}
	// Live gpg --card-status: capture the serial of whatever card gpg
	// is currently talking to, so we can highlight it in the inventory
	// below. A nil Card is NOT an error — it just means no card is
	// currently plugged in OR scdaemon could not acquire it.
	if card := statusResp.GetCard(); card != nil {
		kv.LiveCardSerial = card.GetSerial()
	}

	// Always fall back to the static inventory so the user sees their
	// registered YubiKeys even when the live gpg call fails or returns
	// nothing. This is the same data `gpgsmith card inventory` shows.
	invResp, invErr := s.client.CardInventory(r.Context(), tab.daemonToken)
	if invErr != nil {
		kv.LiveCardError = "live card status: " + invErr.Error()
		s.logger.WarnContext(r.Context(), "webui: card inventory failed",
			slog.String("error", invErr.Error()),
		)
	} else {
		for _, c := range invResp.GetCards() {
			serial := c.GetSerial()
			kv.Cards = append(kv.Cards, keysCardRow{
				Serial:        serial,
				Label:         c.GetLabel(),
				Model:         c.GetModel(),
				Status:        c.GetStatus(),
				CurrentlyLive: serial != "" && serial == kv.LiveCardSerial,
			})
		}
	}

	view.Keys = kv
	s.render(w, r, "keys", view)
}

func (s *Server) handleIdentities(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	view := &baseView{Title: "Identities", VaultName: tab.vaultName}
	if e := r.URL.Query().Get("err"); e != "" {
		view.Error = e
	}
	if f := r.URL.Query().Get("flash"); f != "" {
		view.Flash = f
	}

	resp, err := s.client.IdentityList(r.Context(), tab.daemonToken)
	if err != nil {
		view.Error = err.Error()
		view.Identities = &identitiesView{}
		s.render(w, r, "identities", view)
		return
	}
	iv := &identitiesView{}
	for _, id := range resp.GetIdentities() {
		created := ""
		if ts := id.GetCreated(); ts != nil && !ts.AsTime().IsZero() {
			created = ts.AsTime().Format("2006-01-02")
		}
		revoked := ""
		if ts := id.GetRevoked(); ts != nil && !ts.AsTime().IsZero() {
			revoked = ts.AsTime().Format("2006-01-02")
		}
		status := id.GetStatus()
		isRevoked := strings.EqualFold(status, "revoked") || (id.GetRevoked() != nil && !id.GetRevoked().AsTime().IsZero())
		iv.Identities = append(iv.Identities, identityRow{
			Index:     id.GetIndex(),
			Status:    status,
			Created:   created,
			Revoked:   revoked,
			UID:       id.GetUid(),
			IsRevoked: isRevoked,
			IsPrimary: id.GetIndex() == 1,
		})
	}
	view.Identities = iv
	s.render(w, r, "identities", view)
}

func (s *Server) handleCards(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	view := &baseView{Title: "Cards", VaultName: tab.vaultName}

	resp, err := s.client.CardInventory(r.Context(), tab.daemonToken)
	if err != nil {
		view.Error = err.Error()
		view.Cards = &cardsView{}
		s.render(w, r, "cards", view)
		return
	}
	cv := &cardsView{}
	for _, c := range resp.GetCards() {
		cv.Cards = append(cv.Cards, cardRow{
			Serial:       c.GetSerial(),
			Label:        c.GetLabel(),
			Model:        c.GetModel(),
			Provisioning: c.GetProvisioning(),
			Status:       c.GetStatus(),
			Description:  c.GetDescription(),
		})
	}
	view.Cards = cv
	s.render(w, r, "cards", view)
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	view := &baseView{Title: "Servers", VaultName: tab.vaultName}
	if e := r.URL.Query().Get("err"); e != "" {
		view.Error = e
	}
	if f := r.URL.Query().Get("flash"); f != "" {
		view.Flash = f
	}

	listResp, err := s.client.ServerList(r.Context(), tab.daemonToken)
	if err != nil {
		view.Error = err.Error()
		view.Servers = &serversView{}
		s.render(w, r, "servers", view)
		return
	}

	// The lookup is DELIBERATELY not called here — it fans out to
	// every enabled keyserver and takes seconds to tens of seconds
	// depending on network conditions. The page renders instantly
	// with just the static server list, and the HTMX placeholder at
	// the bottom of servers.html fetches the lookup fragment from
	// /vault/<name>/servers/lookup asynchronously.
	sv := &serversView{}
	for _, srv := range listResp.GetServers() {
		sv.Servers = append(sv.Servers, serverRow{
			Alias:   srv.GetAlias(),
			Type:    srv.GetType(),
			URL:     srv.GetUrl(),
			Enabled: srv.GetEnabled(),
		})
	}
	view.Servers = sv
	s.render(w, r, "servers", view)
}

// handleServersLookupFragment renders just the lookup-results table as
// a bare HTML fragment (no layout). Called by HTMX from servers.html
// after the full page has rendered, so the user sees their server list
// immediately instead of waiting for the per-keyserver network calls.
func (s *Server) handleServersLookupFragment(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}

	sv := &serversView{}
	lookupErr := ""
	resp, err := s.client.ServerLookup(r.Context(), tab.daemonToken)
	if err != nil {
		s.logger.WarnContext(r.Context(), "webui: server lookup",
			slog.String("error", err.Error()),
		)
		lookupErr = err.Error()
	}
	if resp != nil {
		for _, lr := range resp.GetResults() {
			sv.Lookup = append(sv.Lookup, lookupRow{
				URL:    lr.GetUrl(),
				Status: lr.GetStatus(),
			})
		}
	}

	view := &baseView{Servers: sv, Error: lookupErr}
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, "servers_lookup_fragment", view); err != nil {
		s.logger.ErrorContext(r.Context(), "webui: render lookup fragment",
			slog.String("error", err.Error()),
		)
		http.Error(w, "internal render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	view := &baseView{Title: "Audit", VaultName: tab.vaultName}

	resp, err := s.client.AuditShow(r.Context(), tab.daemonToken, auditLimit)
	if err != nil {
		view.Error = err.Error()
		view.Audit = &auditView{Limit: auditLimit}
		s.render(w, r, "audit", view)
		return
	}
	av := &auditView{Limit: auditLimit}
	for _, e := range resp.GetEntries() {
		ts := ""
		if t := e.GetTimestamp(); t != nil {
			ts = t.AsTime().Format(time.RFC3339)
		}
		av.Entries = append(av.Entries, auditRow{
			Timestamp: ts,
			Action:    e.GetAction(),
			Details:   e.GetDetails(),
		})
	}
	view.Audit = av
	s.render(w, r, "audit", view)
}

// stringEscape is a tiny helper to URL-encode an error message for the
// `?err=` flash parameter.
func stringEscape(s string) string {
	return url.QueryEscape(s)
}

// =============================================================================
// Group A mutation handlers (v0.6.0)
// =============================================================================

// redirectErr redirects back to `dest` with the error flashed via
// ?err=<encoded>.
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, dest, msg string) {
	http.Redirect(w, r, dest+"?err="+stringEscape(msg), http.StatusSeeOther)
}

// redirectFlash redirects with a ?flash= success message.
func (s *Server) redirectFlash(w http.ResponseWriter, r *http.Request, dest, msg string) {
	http.Redirect(w, r, dest+"?flash="+stringEscape(msg), http.StatusSeeOther)
}

func (s *Server) handleVaultSeal(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(r.PostForm.Get("message"))
	if msg == "" {
		s.redirectErr(w, r, "/", "seal: message is required")
		return
	}
	resp, err := s.client.VaultSeal(r.Context(), tab.daemonToken, msg)
	if err != nil {
		s.logger.WarnContext(r.Context(), "webui: vault seal failed",
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, "/", "seal: "+err.Error())
		return
	}
	// Sealing ends the daemon session; unbind the tab so the dashboard
	// renders the closed state.
	s.tabs.unbind(tab.cookieToken)

	flash := "vault sealed"
	if snap := resp.GetSnapshot(); snap != nil && snap.GetFilename() != "" {
		flash = "sealed: " + snap.GetFilename()
	}
	s.redirectFlash(w, r, "/", flash)
}

func (s *Server) handleVaultTrustPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := tabFromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.PathValue("name")
	if name == "" {
		http.Error(w, "missing vault name", http.StatusBadRequest)
		return
	}

	view := &baseView{Title: "Update trust anchor", VaultName: name}
	if e := r.URL.Query().Get("err"); e != "" {
		view.Error = e
	}
	tv := &trustView{}
	if listResp, err := s.client.VaultList(r.Context()); err == nil {
		for _, v := range listResp.GetVaults() {
			if v.GetName() == name {
				tv.CurrentFp = v.GetTrustedMasterFp()
				break
			}
		}
	}
	view.Trust = tv
	s.render(w, r, "trust", view)
}

func (s *Server) handleVaultTrustConfirm(w http.ResponseWriter, r *http.Request) {
	if _, ok := tabFromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	name := r.PathValue("name")
	if name == "" {
		http.Error(w, "missing vault name", http.StatusBadRequest)
		return
	}
	newFp := strings.TrimSpace(r.URL.Query().Get("fingerprint"))
	newFp = strings.ToUpper(strings.ReplaceAll(newFp, " ", ""))
	if !hexFingerprintRe.MatchString(newFp) {
		s.redirectErr(w, r, "/vault/"+name+"/trust", "fingerprint must be exactly 40 hex characters")
		return
	}

	view := &baseView{Title: "Confirm: update trust anchor", VaultName: name}
	tv := &trustView{NewFp: newFp}
	if listResp, err := s.client.VaultList(r.Context()); err == nil {
		for _, v := range listResp.GetVaults() {
			if v.GetName() == name {
				tv.CurrentFp = v.GetTrustedMasterFp()
				break
			}
		}
	}
	view.Trust = tv
	view.Confirm = &confirmView{
		Title: "Confirm: update trust anchor",
		Summary: "This replaces the TOFU-trusted master fingerprint for vault " + name +
			". After this change, gpgsmith will only accept snapshots signed by the new fingerprint.",
		Resource:     newFp,
		ConfirmLabel: "Replace trust anchor",
		ConfirmURL:   "/vault/" + name + "/trust",
		CancelURL:    "/vault/" + name + "/trust",
		Hidden: []confirmHidden{
			{Name: "fingerprint", Value: newFp},
		},
	}
	s.render(w, r, "trust_confirm", view)
}

func (s *Server) handleVaultTrust(w http.ResponseWriter, r *http.Request) {
	if _, ok := tabFromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	newFp := strings.TrimSpace(r.PostForm.Get("fingerprint"))
	newFp = strings.ToUpper(strings.ReplaceAll(newFp, " ", ""))
	if !hexFingerprintRe.MatchString(newFp) {
		s.redirectErr(w, r, "/vault/"+name+"/trust", "fingerprint must be exactly 40 hex characters")
		return
	}
	if err := s.client.VaultTrust(r.Context(), name, newFp); err != nil {
		s.logger.WarnContext(r.Context(), "webui: vault trust failed",
			slog.String("vault", name),
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, "/vault/"+name+"/trust", "trust: "+err.Error())
		return
	}
	s.redirectFlash(w, r, "/", "trust anchor updated for "+name)
}

func (s *Server) handleKeyRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	keyID := strings.TrimSpace(r.URL.Query().Get("key_id"))
	if keyID == "" {
		s.redirectErr(w, r, "/vault/"+tab.vaultName+"/keys", "revoke: missing key_id")
		return
	}
	view := &baseView{Title: "Confirm: revoke subkey", VaultName: tab.vaultName}
	view.Confirm = &confirmView{
		Title: "Confirm: revoke subkey",
		Summary: "This will mark subkey " + keyID +
			" as revoked on the master key and auto-republish the master public key to enabled keyservers. The revocation is permanent.",
		Resource:     keyID,
		ConfirmLabel: "Revoke subkey",
		ConfirmURL:   "/vault/" + tab.vaultName + "/keys/revoke",
		CancelURL:    "/vault/" + tab.vaultName + "/keys",
		Hidden: []confirmHidden{
			{Name: "key_id", Value: keyID},
		},
	}
	s.render(w, r, "confirm", view)
}

func (s *Server) handleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	keyID := strings.TrimSpace(r.PostForm.Get("key_id"))
	dest := "/vault/" + tab.vaultName + "/keys"
	if keyID == "" {
		s.redirectErr(w, r, dest, "revoke: missing key_id")
		return
	}
	if err := s.client.KeyRevoke(r.Context(), tab.daemonToken, keyID); err != nil {
		s.logger.WarnContext(r.Context(), "webui: key revoke failed",
			slog.String("key_id", keyID),
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "revoke: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "subkey "+keyID+" revoked")
}

func (s *Server) handleIdentityAdd(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(r.PostForm.Get("uid"))
	dest := "/vault/" + tab.vaultName + "/identities"
	if uid == "" {
		s.redirectErr(w, r, dest, "add identity: uid is required")
		return
	}
	if err := s.client.IdentityAdd(r.Context(), tab.daemonToken, uid); err != nil {
		s.logger.WarnContext(r.Context(), "webui: identity add failed",
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "add identity: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "identity added: "+uid)
}

func (s *Server) handleIdentityRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	uid := strings.TrimSpace(r.URL.Query().Get("uid"))
	if uid == "" {
		s.redirectErr(w, r, "/vault/"+tab.vaultName+"/identities", "revoke identity: missing uid")
		return
	}
	view := &baseView{Title: "Confirm: revoke identity", VaultName: tab.vaultName}
	view.Confirm = &confirmView{
		Title:        "Confirm: revoke identity",
		Summary:      "This will mark the identity as revoked on the master key and auto-republish the updated master key to enabled keyservers.",
		Resource:     uid,
		ConfirmLabel: "Revoke identity",
		ConfirmURL:   "/vault/" + tab.vaultName + "/identities/revoke",
		CancelURL:    "/vault/" + tab.vaultName + "/identities",
		Hidden: []confirmHidden{
			{Name: "uid", Value: uid},
		},
	}
	s.render(w, r, "confirm", view)
}

func (s *Server) handleIdentityRevoke(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(r.PostForm.Get("uid"))
	dest := "/vault/" + tab.vaultName + "/identities"
	if uid == "" {
		s.redirectErr(w, r, dest, "revoke identity: missing uid")
		return
	}
	if err := s.client.IdentityRevoke(r.Context(), tab.daemonToken, uid); err != nil {
		s.logger.WarnContext(r.Context(), "webui: identity revoke failed",
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "revoke identity: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "identity revoked")
}

func (s *Server) handleIdentityPrimary(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	uid := strings.TrimSpace(r.PostForm.Get("uid"))
	dest := "/vault/" + tab.vaultName + "/identities"
	if uid == "" {
		s.redirectErr(w, r, dest, "primary identity: missing uid")
		return
	}
	if err := s.client.IdentityPrimary(r.Context(), tab.daemonToken, uid); err != nil {
		s.logger.WarnContext(r.Context(), "webui: identity primary failed",
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "primary identity: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "primary identity set")
}

func (s *Server) handleServerAdd(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	alias := strings.TrimSpace(r.PostForm.Get("alias"))
	u := strings.TrimSpace(r.PostForm.Get("url"))
	dest := "/vault/" + tab.vaultName + "/servers"
	if alias == "" || u == "" {
		s.redirectErr(w, r, dest, "add server: alias and url are required")
		return
	}
	if err := s.client.ServerAdd(r.Context(), tab.daemonToken, alias, u); err != nil {
		s.logger.WarnContext(r.Context(), "webui: server add failed",
			slog.String("alias", alias),
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "add server: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "server added: "+alias)
}

func (s *Server) handleServerRemoveConfirm(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	alias := strings.TrimSpace(r.URL.Query().Get("alias"))
	if alias == "" {
		s.redirectErr(w, r, "/vault/"+tab.vaultName+"/servers", "remove server: missing alias")
		return
	}
	view := &baseView{Title: "Confirm: remove keyserver", VaultName: tab.vaultName}
	view.Confirm = &confirmView{
		Title:        "Confirm: remove keyserver",
		Summary:      "This will delete the keyserver entry from the vault's publish list. Future publish runs will no longer target it.",
		Resource:     alias,
		ConfirmLabel: "Remove keyserver",
		ConfirmURL:   "/vault/" + tab.vaultName + "/servers/remove",
		CancelURL:    "/vault/" + tab.vaultName + "/servers",
		Hidden: []confirmHidden{
			{Name: "alias", Value: alias},
		},
	}
	s.render(w, r, "confirm", view)
}

func (s *Server) handleServerRemove(w http.ResponseWriter, r *http.Request) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	alias := strings.TrimSpace(r.PostForm.Get("alias"))
	dest := "/vault/" + tab.vaultName + "/servers"
	if alias == "" {
		s.redirectErr(w, r, dest, "remove server: missing alias")
		return
	}
	if err := s.client.ServerRemove(r.Context(), tab.daemonToken, alias); err != nil {
		s.logger.WarnContext(r.Context(), "webui: server remove failed",
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, "remove server: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "server removed: "+alias)
}

func (s *Server) handleServerEnable(w http.ResponseWriter, r *http.Request) {
	s.handleServerToggle(w, r, true)
}

func (s *Server) handleServerDisable(w http.ResponseWriter, r *http.Request) {
	s.handleServerToggle(w, r, false)
}

func (s *Server) handleServerToggle(w http.ResponseWriter, r *http.Request, enable bool) {
	tab := s.requireBoundTab(w, r)
	if tab == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	alias := strings.TrimSpace(r.PostForm.Get("alias"))
	dest := "/vault/" + tab.vaultName + "/servers"
	verb := "enable"
	if !enable {
		verb = "disable"
	}
	if alias == "" {
		s.redirectErr(w, r, dest, verb+" server: missing alias")
		return
	}
	var err error
	if enable {
		err = s.client.ServerEnable(r.Context(), tab.daemonToken, alias)
	} else {
		err = s.client.ServerDisable(r.Context(), tab.daemonToken, alias)
	}
	if err != nil {
		s.logger.WarnContext(r.Context(), "webui: server toggle failed",
			slog.String("verb", verb),
			slog.String("error", err.Error()),
		)
		s.redirectErr(w, r, dest, verb+" server: "+err.Error())
		return
	}
	s.redirectFlash(w, r, dest, "server "+verb+"d: "+alias)
}
