package gpgsmith

import (
	"sync"
	"time"
)

type (
	// tabState carries the per-browser-tab auth and daemon-session
	// binding. One cookie token maps to exactly one tabState.
	//
	// daemonToken is empty until the user opens a vault from this tab;
	// after that it carries the token returned by VaultService.Open and
	// is stamped onto every daemon RPC made on behalf of this tab via
	// wire.ContextWithSessionToken.
	tabState struct {
		cookieToken string
		daemonToken string
		vaultName   string
		lastSeen    time.Time

		// pendingResume carries the passphrase the user just typed into
		// the open form when the daemon reported that the vault has a
		// recoverable ephemeral and needs a resume/discard decision.
		// Cleared once the decision is made (either branch of
		// handleVaultResume) or when the user navigates away and makes
		// a fresh open attempt. The in-memory process is loopback-only,
		// so the passphrase never leaves this host.
		pendingResume *pendingResume
	}

	pendingResume struct {
		vaultName  string
		passphrase string
	}

	// tabStore is a tiny in-memory map of cookieToken → tabState with
	// its own lock. The web UI process is single-node and local-only,
	// so we do not persist this anywhere.
	tabStore struct {
		mu   sync.Mutex
		tabs map[string]*tabState
	}
)

func newTabStore() *tabStore {
	return &tabStore{tabs: make(map[string]*tabState)}
}

// create inserts a fresh empty tab under the given cookie token. Used
// during the startup-token → cookie handoff in the auth middleware.
func (s *tabStore) create(cookieToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tabs[cookieToken] = &tabState{
		cookieToken: cookieToken,
		lastSeen:    time.Now(),
	}
}

// get returns the tabState for a cookie token, or nil if unknown.
// Updates lastSeen on a hit.
func (s *tabStore) get(cookieToken string) *tabState {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tabs[cookieToken]
	if !ok {
		return nil
	}
	t.lastSeen = time.Now()
	return t
}

// bind sets the daemon-session token and vault name on a tab. Returns
// false if the cookie token is unknown.
func (s *tabStore) bind(cookieToken, daemonToken, vaultName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tabs[cookieToken]
	if !ok {
		return false
	}
	t.daemonToken = daemonToken
	t.vaultName = vaultName
	t.lastSeen = time.Now()
	return true
}

// unbind clears the daemon-session binding after a Discard. The cookie
// itself remains valid so the user can open another vault from the
// same tab.
func (s *tabStore) unbind(cookieToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tabs[cookieToken]; ok {
		t.daemonToken = ""
		t.vaultName = ""
		t.pendingResume = nil
		t.lastSeen = time.Now()
	}
}

// stashPendingResume stores the passphrase for an in-progress resume
// decision on the tab. Returns false if the cookie is unknown.
func (s *tabStore) stashPendingResume(cookieToken, vaultName, passphrase string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tabs[cookieToken]
	if !ok {
		return false
	}
	t.pendingResume = &pendingResume{vaultName: vaultName, passphrase: passphrase}
	t.lastSeen = time.Now()
	return true
}

// takePendingResume returns and clears the pending resume stash for a
// tab. Returns nil if none.
func (s *tabStore) takePendingResume(cookieToken string) *pendingResume {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tabs[cookieToken]
	if !ok || t.pendingResume == nil {
		return nil
	}
	p := t.pendingResume
	t.pendingResume = nil
	return p
}
