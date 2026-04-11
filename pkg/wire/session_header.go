package wire

import (
	"context"
	"os"
	"strings"

	"connectrpc.com/connect"
)

const (
	// SessionHeader is the HTTP header used to bind an RPC to a specific
	// daemon-side session. The value is an opaque token returned by
	// OpenVault / ResumeVault / CreateVault.
	SessionHeader = "Gpgsmith-Session"

	// SessionTokenListHeader is stamped by the daemon onto
	// DaemonService.ListSessions responses. Its value is a
	// comma-separated list of "<token>=<vault_name>" pairs. Used by
	// local CLI callers to auto-bind GPGSMITH_SESSION when exactly one
	// session is open.
	SessionTokenListHeader = "Gpgsmith-Session-Tokens"

	// SessionEnvVar is the environment variable CLI frontends read to
	// populate the SessionHeader on outbound requests.
	SessionEnvVar = "GPGSMITH_SESSION"

	// SessionVaultNameEnvVar is an informational env var the CLI
	// exports alongside GPGSMITH_SESSION inside a wrapped subshell, so
	// the user's PS1 and scripts can reference the vault name without
	// calling the daemon.
	SessionVaultNameEnvVar = "GPGSMITH_VAULT_NAME"
)

type (
	sessionCtxKey struct{}

	// envSessionClientInterceptor stamps every outbound unary + streaming
	// request with the SessionHeader, lifting the token from the
	// GPGSMITH_SESSION environment variable at request time. No-op when
	// the env var is unset.
	envSessionClientInterceptor struct{}

	// serverSessionInterceptor moves the SessionHeader off the incoming
	// request headers into the request context under sessionCtxKey, so
	// Backend handlers can read it via TokenFromContext.
	serverSessionInterceptor struct{}
)

// ContextWithSessionToken returns ctx with the given token stored under
// the private session context key. Exported for tests that want to
// exercise handlers without going through an HTTP round-trip.
func ContextWithSessionToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, token)
}

// TokenFromContext returns the session token stamped onto ctx by the
// server-side interceptor, if any.
func TokenFromContext(ctx context.Context) (string, bool) {
	tok, ok := ctx.Value(sessionCtxKey{}).(string)
	if !ok || tok == "" {
		return "", false
	}
	return tok, true
}

// WithEnvSessionInterceptor returns a connect.ClientOption that installs
// the env-var session interceptor. Used by NewUnixSocketClient.
func WithEnvSessionInterceptor() connect.ClientOption {
	return connect.WithInterceptors(envSessionClientInterceptor{})
}

// WithServerSessionInterceptor returns a connect.HandlerOption that
// installs the server-side session header → context interceptor.
func WithServerSessionInterceptor() connect.HandlerOption {
	return connect.WithInterceptors(serverSessionInterceptor{})
}

// clientSessionToken returns the token to stamp onto an outbound
// request. Per-request context (set via ContextWithSessionToken) takes
// priority over the process-global GPGSMITH_SESSION env var, so
// multiple callers sharing one wire.Client — e.g., the web UI binding
// each browser tab to its own daemon session — do not have to mutate
// the process environment.
func clientSessionToken(ctx context.Context) string {
	if tok, ok := TokenFromContext(ctx); ok {
		return tok
	}
	return os.Getenv(SessionEnvVar)
}

// WrapUnary implements connect.Interceptor for the client side.
func (envSessionClientInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if tok := clientSessionToken(ctx); tok != "" {
			req.Header().Set(SessionHeader, tok)
		}
		return next(ctx, req)
	}
}

func (envSessionClientInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		if tok := clientSessionToken(ctx); tok != "" {
			conn.RequestHeader().Set(SessionHeader, tok)
		}
		return conn
	}
}

func (envSessionClientInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	// Client-side interceptor: handler path is a pass-through.
	return next
}

// WrapUnary implements connect.Interceptor for the server side.
func (serverSessionInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if tok := req.Header().Get(SessionHeader); tok != "" {
			ctx = ContextWithSessionToken(ctx, tok)
		}
		return next(ctx, req)
	}
}

func (serverSessionInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	// Server-side interceptor: client path is a pass-through.
	return next
}

func (serverSessionInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if tok := conn.RequestHeader().Get(SessionHeader); tok != "" {
			ctx = ContextWithSessionToken(ctx, tok)
		}
		return next(ctx, conn)
	}
}

// errMissingSessionToken is returned by session-bearing handlers when
// the client did not supply a token.
func errMissingSessionToken() error {
	return connect.NewError(
		connect.CodeUnauthenticated,
		errMissingToken,
	)
}

// encodeSessionTokens renders the session-token list for the
// Gpgsmith-Session-Tokens response header as "tok1=vault1,tok2=vault2".
// The tokens are opaque hex so they do not contain "=" or ",".
func encodeSessionTokens(entries []SessionTokenEntry) string {
	if len(entries) == 0 {
		return ""
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Token == "" {
			continue
		}
		parts = append(parts, e.Token+"="+e.VaultName)
	}
	return strings.Join(parts, ",")
}

// DecodeSessionTokens parses the Gpgsmith-Session-Tokens response
// header value back into (token, vaultName) pairs. Exported for the
// CLI's auto-bind path.
func DecodeSessionTokens(header string) []SessionTokenEntry {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]SessionTokenEntry, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		out = append(out, SessionTokenEntry{
			Token:     p[:eq],
			VaultName: p[eq+1:],
		})
	}
	return out
}
