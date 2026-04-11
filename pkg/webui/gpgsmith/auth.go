package gpgsmith

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
)

const (
	// cookieName is the HTTP cookie that carries the per-tab auth token.
	// The cookie is HttpOnly + SameSite=Strict and scoped to 127.0.0.1.
	cookieName = "gpgsmith_webui"

	// tokenBytes is the number of random bytes in each startup token
	// and cookie token. 32 bytes → 64 hex characters.
	tokenBytes = 32
)

// newRandomToken returns a fresh 64-char hex string sourced from
// crypto/rand. Panics on read failure; this is only called at server
// startup and during cookie issuance, both of which cannot meaningfully
// proceed if the kernel's CSPRNG is unavailable.
func newRandomToken() string {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		panic("gpgsmith webui: read random: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// constantTimeEqual compares two tokens in constant time so a timing
// attack cannot discriminate against a near-correct startup token.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// authMiddleware enforces the startup-token → cookie handshake for
// every non-static request. The flow is:
//
//  1. If the request carries ?t=<startup-token> and the token matches
//     the server's one-shot startup token, issue a fresh cookie token,
//     register a new tabState, redirect to the same path without ?t.
//  2. If the request carries a valid cookie, forward to next with the
//     tabState attached to the request context.
//  3. Otherwise respond 401.
//
// The startup token can be used more than once — each browser tab that
// hits the URL with ?t= ends up with its own cookie and its own
// tabState, so multiple independent tabs work as intended.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Static assets are public — they contain no vault data.
		if len(r.URL.Path) >= len("/static/") && r.URL.Path[:len("/static/")] == "/static/" {
			next.ServeHTTP(w, r)
			return
		}

		// Path 1: startup-token handoff. Accepts any HTTP verb so the
		// user can bookmark a URL with ?t= and it'll auto-issue the
		// cookie on the next GET.
		if t := r.URL.Query().Get("t"); t != "" {
			if !constantTimeEqual(t, s.startupToken) {
				http.Error(w, "invalid startup token", http.StatusUnauthorized)
				return
			}
			cookieToken := newRandomToken()
			s.tabs.create(cookieToken)
			http.SetCookie(w, &http.Cookie{
				Name:     cookieName,
				Value:    cookieToken,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				// No Secure=true: we bind 127.0.0.1 over plain HTTP
				// on purpose. The cookie scope + loopback is the
				// security boundary.
			})
			// Strip ?t= and redirect so the token does not linger in
			// history, referrers, or screenshots.
			q := r.URL.Query()
			q.Del("t")
			r.URL.RawQuery = q.Encode()
			http.Redirect(w, r, r.URL.RequestURI(), http.StatusSeeOther)
			return
		}

		// Path 2: existing cookie.
		c, err := r.Cookie(cookieName)
		if err != nil || c.Value == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tab := s.tabs.get(c.Value)
		if tab == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := contextWithTab(r.Context(), tab)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
