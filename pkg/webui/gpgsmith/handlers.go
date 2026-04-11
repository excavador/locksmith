package gpgsmith

import (
	"bytes"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"time"
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

		Dashboard  *dashboardView
		Keys       *keysView
		Identities *identitiesView
		Cards      *cardsView
		Servers    *serversView
		Audit      *auditView
		Resume     *resumeView
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
		Index   int32
		Status  string
		Created string
		Revoked string
		UID     string
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
	return template.FuncMap{}
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
		iv.Identities = append(iv.Identities, identityRow{
			Index:   id.GetIndex(),
			Status:  id.GetStatus(),
			Created: created,
			Revoked: revoked,
			UID:     id.GetUid(),
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
