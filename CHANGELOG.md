# Changelog

## Unreleased

## v0.6.0 - 2026-04-11

This is the first of four phased releases bringing the web UI to
feature parity with the CLI. v0.6.0 adds every **Group A mutation** —
synchronous, single-RPC, sub-second operations — to the web UI,
together with server-rendered confirmation pages for destructive
actions. The CLI and Web UI are now equivalent for these operations;
you can pick whichever one suits your workflow.

### Added

#### Web UI mutations (Group A)

All 10 simple-mutation operations now have a web UI counterpart:

- **`POST /vault/{name}/seal`** — inline form on the dashboard with a
  `message` field. The session ends and the new snapshot filename is
  surfaced via a success flash on the closed-state dashboard.
- **`GET /vault/{name}/trust`, `GET …/trust/confirm`, `POST …/trust`** —
  full page to view and replace the TOFU master fingerprint anchor,
  with a side-by-side old-vs-new confirmation page. 40-hex-char
  regex validation server-side; spaces are tolerated.
- **`GET /vault/{name}/keys/revoke`, `POST …/keys/revoke`** — per-row
  `Revoke` button on the keys table for subkeys only (primary/master
  keys are not revokable this way, matching `gpgsmith keys revoke`).
  GET returns a confirm page; POST executes.
- **`POST /vault/{name}/identities/add`** — inline form at the top of
  the identities page with a `uid` text input.
- **`GET /vault/{name}/identities/revoke`, `POST …/identities/revoke`** —
  per-row `Revoke` button with confirm page. Hidden on already-revoked
  rows.
- **`POST /vault/{name}/identities/primary`** — per-row `Set primary`
  button. Suppressed on already-primary rows and revoked rows.
- **`POST /vault/{name}/servers/add`** — inline form at the top of
  the servers page with `alias` and `url` text inputs.
- **`GET /vault/{name}/servers/remove`, `POST …/servers/remove`** —
  per-row `Remove` button with confirm page.
- **`POST /vault/{name}/servers/enable`**, **`POST …/servers/disable`** —
  toggle button per row, no confirm required.

#### New web UI primitives

- **`confirm.html`** — generic server-rendered confirmation template.
  Every destructive mutation routes through this page on a GET first,
  then POSTs to the real endpoint. No native `confirm()` dialogs, no
  JavaScript beyond HTMX, no inline-fragment confirmation.
- **`trust.html`** — dedicated vault-trust update page with a
  side-by-side old-vs-new fingerprint confirm variant. Replacing the
  TOFU anchor is the most security-sensitive operation in gpgsmith,
  so it gets an explicit two-step flow.
- **Success flash channel.** New `?flash=<message>` query parameter
  with a `.Flash` field on `baseView`, rendered in the layout
  alongside `.Error`. Used by the seal handler to surface snapshot
  filenames and by other mutations as a success breadcrumb.
- **11 new `DaemonClient` interface methods:** `VaultSeal`,
  `VaultTrust`, `KeyRevoke`, `IdentityAdd`, `IdentityRevoke`,
  `IdentityPrimary`, `ServerAdd`, `ServerRemove`, `ServerEnable`,
  `ServerDisable` — all thin wrappers around the existing daemon
  RPCs. Each also has a matching `wireAdapter` production
  implementation and a recording stub on the test `fakeClient`.

#### Tests

- **14 new unit tests** in `pkg/webui/gpgsmith/webui_test.go` covering
  every new handler: happy-path POSTs, confirm-page rendering, form
  validation failures (`TestServerAdd_InvalidInput_FlashesError`),
  and the trust confirm page showing both old and new fingerprints.
- **5 new e2e tests** in `pkg/webui/gpgsmith/e2e_test.go`:
  `TestE2E_ServerAdd_FormSubmit`, `TestE2E_ServerEnable_Toggle`,
  `TestE2E_ServerRemove_ConfirmFlow`, `TestE2E_VaultTrust_ConfirmFlow`,
  `TestE2E_Seal_FromDashboard`. Identity / key revoke flows are
  covered by unit tests only because the DEADBEEF-fp test vault has
  no real GPG keyring to mutate (would require ~5s of RSA 2048 gen
  per test).
- Shared `openVaultUI` helper factored out of the navigation test for
  reuse by the mutation tests.
- E2E suite runtime: ~9.9 seconds locally, still under the 10s target
  even with 5 additional tests.

#### Supporting changes

- **End-to-end browser tests for the web UI.** New
  `pkg/webui/gpgsmith/e2e_test.go` (behind `//go:build e2e`) drives a
  headless Chromium via `github.com/chromedp/chromedp` against a real
  in-process daemon + wire server + web UI chain. Covers the full
  read-only MVP flow: startup-token → cookie handshake, unauthenticated
  401, wrong-passphrase flash, correct-passphrase vault open, keys /
  identities / cards / audit page renders, servers-page HTMX lazy
  swap, and vault discard. All tests share one chromium instance per
  top-level `Test*` function via subtests, and the servers test ships
  an empty server registry in the test vault so the HTMX swap does
  not depend on real keyserver network round-trips. Runs in ~3.3
  seconds locally, zero network dependency.
  - New `just e2e` recipe runs `go test -tags e2e`
  - `just lint` now passes `--build-tags e2e` so lint covers the
    tagged file too
  - CI workflow runs `just e2e` after `just build`
  - `chromium@latest` added to `devbox.json`
  - `github.com/chromedp/chromedp` added to `go.mod`

## v0.5.4 - 2026-04-11

### Fixed

- **Web UI `/servers` page hung for ~16 seconds on load.** The
  handler called `ServerService.Lookup` synchronously, which fans
  out to every enabled keyserver (`keys.openpgp.org`,
  `keyserver.ubuntu.com`, etc.) and waits for each HTTP round-trip
  before rendering the page. With several enabled keyservers the
  total wall time easily exceeds 15 seconds, during which the tab
  appears frozen.

  Fix: the servers page now renders instantly with just the static
  server list from `ServerService.List`, and the lookup results are
  loaded asynchronously via an HTMX `hx-get` + `hx-trigger="load"`
  placeholder that hits a new fragment endpoint
  `GET /vault/<name>/servers/lookup`. The fragment returns only the
  lookup table HTML (no layout) and HTMX swaps it into the page
  when it arrives. The user sees their configured servers
  immediately; the "currently available on keyservers" status
  appears a moment later.

  This was the first on-page use of HTMX in the web UI — the
  library has been vendored since v0.5.0 but no page needed it
  until now.

## v0.5.3 - 2026-04-11

### Fixed

- **Web UI keys page "No card detected" when scdaemon conflicts.**
  The "Card (from KeyService.Status)" section silently showed "No card
  detected" whenever the daemon's live `gpg --card-status` call failed
  (for example when another scdaemon on the same host held the
  YubiKey despite the v0.4.0-era retry, which can happen after
  several daemon restarts leave stale scdaemons around). The webui
  now falls back to `CardService.Inventory` — the same static
  `gpgsmith-inventory.yaml` the `Cards` tab shows — and renders every
  registered YubiKey with a "currently plugged in" badge derived
  from the live call's response. When the live call returned no
  card, a muted diagnostic is shown under the table explaining that
  the inventory is static and why the live status might be
  unavailable. The section is renamed to "YubiKeys linked to this
  vault" to reflect that it is now inventory-backed.
- **Daemon swallowed live card-status errors silently.**
  `daemon.KeyStatus` used `info, _ := client.CardStatus(ctx)` and
  returned `(keys, nil)` with no indication of what went wrong. It
  now logs the card-status error at DEBUG level so operators can
  diagnose unexpected "no card detected" states without attaching
  a debugger. Behavior is unchanged: the keys list is still
  returned even when the live card call fails.

## v0.5.2 - 2026-04-11

### Fixed

- **CLI `vault open --resume` crash on orphan `.info` sidecars.** The
  daemon's `OpenVault` flow found any `.session-<host>.info` sidecar on
  disk and eagerly returned `ResumeAvailable`, even when the companion
  encrypted state file was missing. Sessions that were started but
  never flushed any mutations (so no state file was ever written), or
  that were killed before `AutoSealAndDrop` could run, left behind
  orphan `.info` files that looked like resume candidates. The user
  answered "Resume? Y" to the CLI prompt and the daemon crashed with
  `resume session: ephemeral has no state file on disk`. Fix: the new
  `isRecoverable` helper requires both the `.info` and the state file
  to be on disk. `OpenVault` and `StatusVaults` both use it now.
  Orphaned `.info` files are logged as warnings and ignored; the next
  session opened against the same vault overwrites them with its own
  heartbeat. Regression tests `TestDaemonOpenIgnoresOrphanInfo` and
  `TestDaemonStatusIgnoresOrphanInfo` added in `pkg/daemon/daemon_test.go`.
- **`ResumeSession` error message** when a caller somehow still reaches
  it with a state-file-less ephemeral now explains the likely cause
  (session killed before flushing) and the remediation (discard the
  orphan, or retry `vault open` to overwrite it).

- **Web UI keys page missing card label.** The `KeyService.Status`
  response includes the card's `label` field, but the web UI's
  `keysView` only propagated `serial` and `model`. The
  `[label][model][serial]` line on `/vault/<name>/keys` now shows all
  three, matching the CLI's `keys status` output.

### Added

- **Web UI resume flow.** Previously, a POST to `/vault/<name>/open`
  that returned a `ResumeAvailable` response redirected to the
  dashboard with a flash alert telling the user to "resume from the
  CLI." The web UI now renders a proper resume prompt page at
  `GET /vault/<name>/resume` with Resume / Discard / Cancel buttons
  and a summary of the ephemeral (hostname, started-at, last
  heartbeat, status, divergent flag). The user's typed passphrase is
  stashed in the tab's in-memory state (loopback-only, never written
  to disk or sent to the browser) for the follow-up call, so they do
  not have to retype it. New `DaemonClient.VaultResume` method on the
  web UI's narrow interface, new `wireAdapter.VaultResume`
  implementation, and tests `TestVaultOpen_ResumeAvailable_RedirectsToResumePrompt`
  and `TestVaultResume_POSTCallsDaemonAndBinds` in
  `pkg/webui/gpgsmith/webui_test.go`.

## v0.5.1 - 2026-04-11

### Fixed

- **Web UI session binding.** Every session-bearing RPC from the web UI
  failed with `unauthenticated: no session token; set GPGSMITH_SESSION
  or open a vault` once a user opened a vault and navigated to any
  detail page (keys, identities, cards, servers, audit). The client-side
  Connect interceptor in `pkg/wire/session_header.go` only read the
  session token from `os.Getenv(GPGSMITH_SESSION)` and ignored tokens
  stamped onto the per-request context via
  `wire.ContextWithSessionToken`. The web UI uses the context-stamping
  path so each browser tab can bind to its own daemon session without
  mutating the process-global env var — and that path silently did
  nothing. The interceptor now prefers the context-stamped token and
  falls back to the env var. Added two regression tests in
  `pkg/wire/wire_test.go` that exercise the real `NewHTTPClient` +
  `WithEnvSessionInterceptor` path with a ctx-stamped token (one with
  and one without a conflicting env var) to guard against future
  regressions.

## v0.5.0 - 2026-04-11

This release introduces **token-keyed sessions** and a **loopback-only web
UI**. The daemon's session map is now keyed by an opaque per-session token
instead of by vault name; multiple terminals can each open the same vault
and get fully independent sessions with their own decrypted GNUPGHOME, gpg
agent, and idle timer. Each terminal binds to its session via a
`GPGSMITH_SESSION` environment variable, set automatically by `gpgsmith
vault open` when it spawns a child `$SHELL`. The new `gpgsmith webui`
command exposes the same session model to a browser tab via an HttpOnly
cookie.

### Breaking

- **`gpgsmith vault open` now spawns a subshell by default.** Previous
  behavior (return to the parent shell after sealing the daemon-side
  state) is gone. Use `--no-shell` to get the old return-immediately
  ergonomic with an `export GPGSMITH_SESSION=...` line on stdout for
  `eval $(...)`.
- **`gpgsmith vault seal` and `gpgsmith vault discard` no longer take
  a vault name argument.** They target the session bound by
  `GPGSMITH_SESSION` (or, if exactly one session is open, auto-bind to
  it).
- **The global `--vault` flag is removed.** Sessions are selected by
  the `Gpgsmith-Session` HTTP header, which the CLI sets from the
  `GPGSMITH_SESSION` env var. The `--vault-dir` flag (registry override
  for tests) is unchanged.
- **Wire schema:** every session-bearing Request message dropped its
  `string vault_name = 1` field; field 1 is now `reserved`. Affected
  services: KeyService, IdentityService, CardService, ServerService,
  AuditService, EventService, plus VaultService.SealRequest /
  DiscardRequest. Non-session vault ops (Open, Resume, Create, Import,
  Export, Trust, Snapshots) still take a vault name in the request body.
- **`OpenResponse`, `ResumeResponse`, and `CreateVaultResponse`** now
  return a `string token` field — the daemon's session token to be sent
  back via the `Gpgsmith-Session` header on subsequent calls.

### Added

#### New CLI commands and behavior

- **`gpgsmith webui [--bind 127.0.0.1:0] [--open|--no-open]`** — start a
  loopback-only HTTP server that talks to the daemon and serves the
  read-only web UI. Refuses any non-loopback bind address. Prints a
  one-shot URL `http://127.0.0.1:<port>/?t=<startup-token>` on stderr
  and (with `--open`, default true) launches the default browser.
- **`gpgsmith vault open <name>`** spawns a child `$SHELL` (bash, zsh
  detected from `$SHELL`, fish falls back to sh) with `GPGSMITH_SESSION`
  and `GPGSMITH_VAULT_NAME` set in its environment. The subshell's
  prompt is prefixed `[gpgsmith:<vault>]` via a generated rc file.
  Exiting the subshell returns to the parent shell with the subshell's
  exit code; the daemon retains the session until its idle timer fires.
- **`gpgsmith vault open --no-shell <name>`** — scripted form. Prints
  `export GPGSMITH_SESSION=<token>` and `export GPGSMITH_VAULT_NAME=<name>`
  to stdout for `eval $(...)`. Human-readable status goes to stderr.
- **CLI auto-bind fallback.** When `GPGSMITH_SESSION` is unset and the
  daemon has exactly one open session, the CLI auto-binds to it (the
  daemon's `Daemon.ListSessions` reply ships an out-of-band
  `Gpgsmith-Session-Tokens` HTTP response header that the CLI consumes;
  the header is Unix-socket-only by convention and never sent over a
  network listener).

#### New packages

- **`pkg/webui/gpgsmith`** — loopback-only HTTP frontend. Stack:
  `net/http` with Go 1.22+ method-aware mux, `html/template` for views,
  vendored HTMX (47 KB) for client interactivity, hand-written CSS with
  `prefers-color-scheme` dark mode, all assets embedded via `go:embed`,
  zero JavaScript toolchain. Auth: per-startup random token in URL is
  exchanged for an HttpOnly + SameSite=Strict cookie scoped to the
  loopback host; per-tab cookie tokens map to in-memory `tabState`
  records that hold the daemon session token. Pages: vault dashboard
  (open / discard), keys, identities, cards, servers, audit log
  (read-only). The web UI server holds a narrow `DaemonClient` interface
  in front of `wire.Client`, with a wire adapter that stamps each tab's
  daemon session token via `wire.ContextWithSessionToken`.

#### New wire layer primitives

- **`pkg/wire/session_header.go`** — Connect interceptors that read the
  `Gpgsmith-Session` header from the request context (server) or stamp
  it from `GPGSMITH_SESSION` env (client). Includes
  `ContextWithSessionToken(ctx, token)` for explicit per-request token
  binding (used by the web UI to bind each browser tab independently).
- **`Backend.ListSessionTokens`** plus the `Gpgsmith-Session-Tokens`
  response header on `Daemon.ListSessions` — a side-channel that lets
  same-host CLI clients enumerate the daemon's open sessions and their
  tokens for the auto-bind fallback. Tokens are never carried in any
  proto message body.

### Fixed

- **Multiple sessions per vault.** The v0.4.0 daemon refused a second
  `vault open` for the same vault name. v0.5.0 lifts that restriction:
  two opens produce two independent sessions with distinct tokens,
  workdirs, gpg-agents, and idle timers. Mutations in one are not
  visible in the other until each is sealed.

### Removed

- **Global `--vault` flag.** Session targeting now goes through
  `GPGSMITH_SESSION` (env var or header).
- **`vault_name` field on every session-bearing proto Request.** Replaced
  by the `Gpgsmith-Session` header. Field 1 reserved on every affected
  message; field numbering on the rest is unchanged.

### Changed (internal architecture)

- **`pkg/daemon` session map** is now `map[token]*sessionEntry` instead
  of `map[vaultName]*sessionEntry`. Per-session bookkeeping (idle timer,
  gpg-agent kill on cleanup) is unchanged. Token generation: 32 random
  bytes from `crypto/rand` → 64 hex chars.
- **`Backend` interface (`pkg/wire/backend.go`)** — every session-bearing
  method's vault-name parameter became a token. Methods that mint a
  session (`OpenVault`, `ResumeVault`, `CreateVault`) return the token
  alongside their existing return values.
- **`pkg/cli/gpgsmith/subshell.go`** restored from the v0.3.0-era
  shell-wrapper machinery. The bash/zsh rc file approach is the same;
  the env var name changed from `GPGSMITH_VAULT_KEY` (passphrase) to
  `GPGSMITH_SESSION` (opaque token). The passphrase **never leaves the
  daemon process** in v0.5.0 — the env var is just a session selector,
  so leaking it is far less dangerous than the v0.3.0 model.

### Migration

- Replace `gpgsmith vault open work && gpgsmith keys list && gpgsmith
  vault seal` flows with the new subshell flow:
  ```
  gpgsmith vault open work        # spawns [gpgsmith:work] $ subshell
  gpgsmith keys list              # inside the subshell
  gpgsmith vault seal -m "..."    # inside the subshell
  exit                            # back to parent shell
  ```
  Or use `--no-shell` for scripts:
  ```
  eval "$(gpgsmith vault open --no-shell work)"
  gpgsmith keys list
  gpgsmith vault seal -m "..."
  unset GPGSMITH_SESSION
  ```
- Drop any `--vault <name>` flag usages from your shell history. The
  flag is gone.
- If you have a tool that calls the daemon's RPC API directly (Connect
  client), you must now stamp the `Gpgsmith-Session` header on every
  session-bearing request. Use the env-var interceptor in
  `pkg/wire/client.go` for the simple case, or
  `wire.ContextWithSessionToken(ctx, token)` for explicit per-request
  binding.

## v0.4.0 - 2026-04-08

This release replaces gpgsmith's single-process CLI architecture with a
**daemon + thin clients** model. A long-running `gpgsmith daemon` process
holds open vaults in memory across CLI invocations; every `gpgsmith` command
is now a thin ConnectRPC client that talks to the daemon over a per-user
Unix socket. The interactive shell wrapper is gone, the env-var session
state is gone, and commands that follow a `vault open` are sub-millisecond
RPCs instead of full vault decrypt cycles.

The daemon also adds **idle auto-seal-to-ephemeral with resume on next
open**: after 5 minutes of no activity, the daemon flushes the in-memory
workdir to an encrypted `.session-<host>` file pair on disk and drops the
session state from memory. The next `vault open` for the same vault detects
the file and prompts to resume.

This is a breaking change for anyone using the old `eval $(gpgsmith vault
open)` shell pattern. See **Migration** below.

### Breaking

- **The CLI is now a thin ConnectRPC client of the daemon.** Every
  `gpgsmith <noun> <verb>` command auto-spawns the daemon via
  `EnsureDaemon` (or uses the already-running one) and talks to it over
  the per-user Unix socket. No CLI command touches GPG, the vault, or
  the audit log directly anymore.
- **The interactive shell wrapper is gone.** `gpgsmith vault open <name>`
  no longer spawns `$SHELL` with `GNUPGHOME` set; instead it hands the
  session to the daemon and returns. Subsequent commands
  (`gpgsmith keys list`, `gpgsmith card provision`, ...) operate on the
  daemon-held session.
- **`GPGSMITH_VAULT_KEY` and `GPGSMITH_SESSION` env vars are no longer
  used.** Remove any `eval "$(gpgsmith vault open ...)"` patterns from
  your shell aliases / scripts. The daemon holds the vault passphrase
  in memory for the duration of the session.
- **`gpgsmith vault open` now takes the vault name as a positional
  argument** (`gpgsmith vault open work`), matching `vault seal`,
  `vault discard`, and the other session-bearing commands. The root
  `--vault` flag is used by per-session commands like `keys list` when
  the daemon has multiple vaults open.
- **`gpgsmith vault restore` removed.** Use `gpgsmith vault export <name>
  <target>` to materialize a specific vault's latest canonical if you
  need the escape hatch.

### Added

#### New CLI commands

- **`gpgsmith daemon {start,stop,status,restart}`** — manage the
  background daemon explicitly. `start` runs `--foreground` in-process
  or backgrounds itself via `setpgid` detach. `status` follows the
  `systemctl status --user` exit-code convention (`0` running,
  `3` inactive, `1` error). The daemon binary is the same `gpgsmith`
  binary.
- **`gpgsmith vault status`** — shows which vaults the daemon currently
  has open and which ones have a recoverable ephemeral on disk ready to
  be resumed.
- **`gpgsmith vault export <name> <target>`** — offline escape hatch
  that decrypts the latest canonical of the named vault to a
  user-supplied directory. Does not create a session and does not touch
  daemon state.
- **`gpgsmith vault trust <name> <fp>`** — explicit TOFU re-anchor after
  a legitimate master-key rotation.
- **`gpgsmith vault create <name>`** — new semantics: creates a vault
  registry entry, writes the vault directory, encrypts an empty initial
  snapshot, and opens a session on it. Follow up with `gpgsmith keys
  create` to generate the master key.

#### Behavior

- **Auto-spawn daemon on every user-facing command.** If the daemon is
  not running when you invoke a CLI command, a detached copy starts
  automatically; the first command pays the startup cost and subsequent
  commands are sub-millisecond RPCs.
- **Idle auto-seal-to-ephemeral.** After 5 minutes of no activity, the
  daemon flushes the in-memory workdir to the encrypted ephemeral file
  pair and drops the session state from memory, allowing the next
  `vault open` on the same vault to offer to resume.
- **Vault registry: multi-vault support in `~/.config/locksmith/config.yaml`.**
  The config file supports a `vaults:` list with named entries plus a
  `default:` selector, alongside the existing single-vault `vault_dir:`
  form. Both forms remain valid and may coexist; the legacy `vault_dir:`
  is exposed as a synthetic registry entry named `default`. New global
  flag `--vault <name>` selects an entry from the registry.
- **TOFU master-key trust.** First time `vault open` decrypts a vault,
  the daemon reads `master_fp` from the embedded `gpgsmith.yaml` and
  records it as `trusted_master_fp` in the registry entry. Subsequent
  opens verify the embedded fingerprint matches and refuse loudly with
  `MasterKeyMismatchError` on mismatch (the loud security signal that
  the snapshot was either replaced by an attacker with write access to
  the vault directory, or generated from a fresh setup that overwrote
  your real vault).
- **Process hardening at daemon startup.** The daemon calls
  `prctl(PR_SET_DUMPABLE, 0)` on Linux (`ptrace(PT_DENY_ATTACH)` on
  macOS) plus `setrlimit(RLIMIT_CORE, 0)`. This blocks `ptrace`,
  `process_vm_readv`, and `/proc/<pid>/{mem,maps,root}` reads from
  same-user processes (the kernel re-owns those files to root once
  dumpable=0), and prevents core dumps from leaking heap on crash.
  The single biggest defense available without root or systemd.
- **Loopback pinentry mode is enforced** in every per-session
  GNUPGHOME. The daemon writes `gpg.conf` (`pinentry-mode loopback`)
  and `gpg-agent.conf` (`allow-loopback-pinentry`) into the
  freshly-decrypted workdir, then passes the vault passphrase to gpg
  over a private OS pipe (fd 3 via `ExtraFiles`). No GUI pinentry
  popup; no dependency on `pinentry-tty` / `pinentry-curses` being
  installed; works identically on desktops, headless servers,
  containers, and CI runners.

#### New packages and architecture

- **`pkg/gpgsmith` — the kernel.** Owns the `Session` type, ephemeral
  session file convention, TOFU + heartbeat + auto-seal-to-ephemeral
  lifecycle, and process hardening primitives. Importable by
  third-party Go code that wants to script against the same surface
  the daemon exposes.
- **`pkg/daemon` — the daemon runtime.** Implements `wire.Backend`
  against the kernel. In-process broker with per-topic ring buffer
  (~80 LOC, no external dependencies, no NATS) backs the future
  per-job event streaming. Unix socket bind with stale-socket
  recovery (the standard connect-then-EConnRefused-then-unlink-then-bind
  idiom). Per-session idle timer fires `Session.AutoSealAndDrop` on
  expiry and emits a `session.ended` event. Graceful shutdown
  auto-seals every open session within a configurable budget.
- **`pkg/wire` — the ConnectRPC adapter layer.** Hand-written server
  handlers (one per service), typed client wrapper that bundles all
  eight generated `*ServiceClient` interfaces, proto↔kernel type
  conversion. The package is named `wire` rather than `rpc` because
  Go's stdlib has `net/rpc` and revive flags the shadowed name. Eight
  Connect services cover the full kernel surface: `DaemonService`,
  `VaultService`, `KeyService`, `IdentityService`, `CardService`,
  `ServerService`, `AuditService`, and `EventService`.
- **`pkg/cli/gpgsmith` — the CLI frontend.** Every command is a thin
  `wire.Client` call that auto-spawns the daemon via `EnsureDaemon`
  and renders the response with `text/tabwriter`. Sibling packages
  `pkg/webui/gpgsmith` and `pkg/tui/gpgsmith` are reserved for the
  future web UI and TUI frontends.
- **`pkg/gen/gpgsmith/v1` — generated proto stubs.** Committed to git
  so `go install` and CI work without buf. Regenerate with
  `just generate` (which runs `go generate ./pkg/gen` → `buf generate`).
  The buf, protoc-gen-go, and protoc-gen-connect-go binaries come
  from `devbox.json` so contributors get them via `direnv allow`.
- **`proto/gpgsmith/v1/*.proto` — wire schemas.** Source of truth for
  the daemon API.

### Fixed

- **`gpg --card-status` now succeeds even when another `scdaemon` already
  holds the YubiKey.** On systems without `pcscd` (where `scdaemon` uses
  its internal CCID driver via libusb), only one `scdaemon` at a time can
  claim the OpenPGP applet. A typical Linux desktop has a long-running
  `gpg-agent` for `~/.gnupg` (often via `enable-ssh-support` and the
  systemd `gpg-agent.socket` unit) whose `scdaemon` claims the card on
  first use. When gpgsmith opened a vault session and tried to call
  `gpg --card-status` against the freshly-decrypted GNUPGHOME in
  `/dev/shm`, the new `scdaemon` couldn't acquire the card and returned
  `gpg: selecting card failed: No such device`. `gpgsmith card discover`,
  `card provision`, `card rotate`, etc. all hit this error.

  `pkg/gpg.Client.CardStatus` now detects this specific failure mode and
  recovers automatically: it runs `gpgconf --kill scdaemon` to terminate
  every `scdaemon` under the current user account, then retries the
  `--card-status` call once. The killed `scdaemon` instances respawn on
  the next gpg call from any homedir, so the user's normal gpg flow is
  briefly interrupted but no permanent state is lost.

- **`parseUIDs` reports the original creation date, not the latest
  re-signing date.** Field 5 of gpg's `uid:` colon record reflects the
  LATEST self-signature, which gpg refreshes whenever the UID is
  touched (`--quick-set-primary-uid` rewrites the binding signature
  with today's timestamp). Naively trusting it made a UID created in
  2022 look like it was created today right after a primary toggle.
  The parser now always walks `sig:` records following each `uid:`
  line and picks the EARLIEST one as the authoritative origin date.

- **`vault list` and `vault status` no longer return duplicate rows.**
  After TOFU first-use writes a `vaults:` registry entry to the user's
  config, the legacy `vault_dir:` field is intentionally preserved for
  backward compat — but both forms point at the same path. The daemon
  was returning the same vault twice. The new `mergeVaultEntries`
  helper deduplicates registry vs legacy entries by name AND by path.

- **Per-session `gpg-agent` and `scdaemon` are killed on session end.**
  Previously every `Seal` / `Discard` / `AutoSealAndDrop` left an
  orphan gpg-agent + scdaemon pair pointing at a workdir we were
  about to remove from `/dev/shm`. They accumulated in the user's
  process table over time. Session end paths now run
  `gpgconf --homedir <workdir> --kill all` before removing the workdir.

- **`gpgsmith vault snapshots` works without an open session.** Listing
  canonical filenames is a stateless directory read; the daemon no
  longer requires a session lookup for it.

### Removed

- **`pkg/gpgsmith/lock.go` and `pkg/gpgsmith/lock_test.go`** (flock-based
  single-holder enforcement). The daemon's in-process session map is
  now the single source of truth for which vaults are open; cross-host
  coordination was never possible via flock anyway.
- **`tty.go` session wrapper machinery**: `newSessionRC`, `bashSessionRC`,
  `zshSessionRC`, `sessionRC`, `shellEscapeSingleQuote`, and
  `runInteractiveSession` are deleted. `promptLine`, `readPassphrase`,
  and `readPassphraseWithConfirm` remain as small terminal helpers.

### Changed (internal architecture)

- **CLI implementation moved from `pkg/gpgsmith` to `pkg/cli/gpgsmith`**
  to free up `pkg/gpgsmith` for the kernel package.
- **`vault.Config.Resolve(name)` and `vault.Entry`** added to
  `pkg/vault` to handle the multi-vault registry resolution with
  backward-compatible precedence over the legacy `vault_dir:` form.

### Migration

- Remove `eval $(gpgsmith vault open ...)` or equivalent patterns from
  your shell rc files — they are no-ops now.
- The daemon binary is the same `gpgsmith` binary. You can start it
  explicitly with `gpgsmith daemon start`, or let auto-spawn handle it
  on first use.
- Existing vaults from prior versions Just Work — no conversion step.
  The first `vault open` populates the TOFU trust anchor, the new
  loopback `gpg.conf` and `gpg-agent.conf` get baked into the next
  sealed snapshot, and subsequent opens are unchanged.
- The `--vault` global flag is OPTIONAL when exactly one vault is open
  in the daemon. REQUIRED when zero or two-or-more are open. The CLI
  surfaces a clear error message if ambiguous.

## v0.3.0 - 2026-04-10

### Added

- **`keys identity` subcommand group** — full lifecycle management for User
  IDs (name+email pairs) on the master key. Closes the gap Sergey Vilgelm
  reported in [excavador/locksmith#1](https://github.com/excavador/locksmith/issues/1):
  previously the only way to add a new email or revoke an old one was to
  drop into raw `gpg --edit-key`, with no audit trail and no automatic
  publish. Four operations:
  - `keys identity list` — show all identities with their creation and
    revocation dates, plus validity status (`ultimate`, `revoked`, etc.).
  - `keys identity add "Name <email@example.com>"` — attach a new identity.
  - `keys identity revoke <identity-or-index>` — revoke by exact UID string
    or 1-based index from `identity list`.
  - `keys identity primary <identity-or-index>` — promote an identity to
    primary.

  All mutations are captured in the audit log (`add-identity`,
  `revoke-identity`, `set-primary-identity`) and automatically re-published
  to enabled servers so keyservers pick up the new state without a manual
  `server publish`. `keys uid` is registered as a hidden alias for users
  who prefer GPG's historical terminology.

  Implementation uses GPG 2.1+'s non-interactive `--quick-add-uid`,
  `--quick-revoke-uid`, and `--quick-set-primary-uid` commands — no
  fragile `--command-fd` / `--edit-key` scripting required.

- **Loopback pinentry mode by default.** Every gpgsmith vault session now
  writes a per-vault `gpg.conf` (`pinentry-mode loopback`) and
  `gpg-agent.conf` (`allow-loopback-pinentry` + 1h/8h cache TTLs) into the
  ephemeral GNUPGHOME, bypassing pinentry entirely. Consequences:
  - **No GUI pinentry popup, ever** — key generation, subkey rotation,
    UID edits, and card operations work identically on desktops, headless
    servers, containers, and CI runners.
  - **No dependency** on `pinentry-tty` / `pinentry-curses` being installed.
  - The vault passphrase doubles as the master-key passphrase and is
    supplied to gpg over a **private OS pipe (fd 3 via `ExtraFiles`)** —
    never via argv, environment, or a disk file, so it never appears in
    `/proc/<pid>/cmdline`.
  - gpg-agent's cache (1h default, 8h max) means a single passphrase entry
    covers a typical interactive session.
  - Inside the interactive gpgsmith shell, `GPGSMITH_VAULT_KEY` is now
    exported alongside `GNUPGHOME`, so subsequent `gpgsmith` commands
    inherit the passphrase transparently.

- **Recovered creation/revocation dates for revoked UIDs.** `keys identity
  list` now shows both the CREATED and REVOKED columns for every identity,
  including revoked ones. This required switching from `gpg --list-keys`
  (which strips field 5 from revoked `uid:` records) to `gpg --list-sigs`
  and teaching `parseUIDs` to recover the creation date from the trailing
  self-signature (`sig:`) record and the revocation date from the companion
  `rev:` record.

### Changed

- **gpg record-type strings extracted as package constants** (`recPub`,
  `recSec`, `recSub`, `recSsb`, `recFpr`, `recUID`, `recSig`, `recRev`) in
  `pkg/gpg/keys.go`, deduplicating them across `parseColonsOutput` and the
  new `parseUIDs`.

- **Status strings unified.** `statusActive`, `statusRevoked`, `statusExpired`
  constants in `pkg/gpgsmith/cmd_keys.go`, shared between `keyStatus` (for
  subkeys) and `identityStatus` (for identities).

## v0.2.0 - 2026-04-10

### Added

- **`setup` first-time wizard.** New top-level `gpgsmith setup` command creates
  a vault, prompts for passphrase, generates a master key + S/E/A subkeys, and
  opens an interactive session in one step. Accepts `--name`, `--email`,
  `--algo`, `--subkey-algo`, `--subkey-expiry` flags; prompts interactively
  for any missing required fields.

- **`keys create` command.** Generates a new certify-only master key plus S/E/A
  subkeys via `gpg --quick-gen-key`, saves the resulting fingerprint and subkey
  defaults to `gpgsmith.yaml`, initializes the server registry, and writes an
  audit entry. Supports `--name`, `--email`, `--algo`, `--expiry`,
  `--subkey-algo`, `--subkey-expiry`. No more "(planned)" stub.

- **`keys export` command.** Exports the public key and card-bound private key
  stubs from the vault GNUPGHOME into the local `~/.gnupg` keyring, so
  card-based signing keys work outside the vault session (e.g., for git
  commit signing). Copies all card stubs automatically.

- **Server registry for publish targets.** New `server` top-level command with
  `list`, `add`, `remove`, `enable`, `disable`, `publish`, and `lookup`
  subcommands. Publish targets (keyservers and GitHub) are now managed as a
  persistent registry (`gpgsmith-servers.yaml`) with aliases and enable/disable
  support. Built-in defaults: openpgp and ubuntu (enabled), github, mailvelope,
  mit, gnupg (disabled).

- **GitHub OAuth scope validation.** `server enable github` checks that the
  `gh` CLI is installed, authenticated, and has the required `admin:gpg_key`
  and `admin:public_key` scopes before enabling. Prints the exact
  `gh auth refresh` command if scopes are missing.

- **Automatic migration from old config.** On first load, the server registry
  migrates `publish_targets` from `gpgsmith.yaml`, merges with built-in
  defaults, and removes the old config field.

### Changed

- **`keys publish` now uses server registry.** Accepts positional alias args
  (`gpgsmith keys publish openpgp github`) instead of the old `--target` flag.
  No args publishes to all enabled servers.

- **`keys lookup` uses server registry.** Checks all registered keyservers
  (enabled and disabled) instead of a hardcoded well-known list.

- **Card commands use server registry.** `card provision`, `card rotate`, and
  `card revoke` now publish to enabled servers from the registry instead of
  config `publish_targets`.

- **Pinned golangci-lint to v2.10.1** to work around a gosec v2.24.x hang bug
  in v2.11.0+ ([golangci/golangci-lint#6416](https://github.com/golangci/golangci-lint/issues/6416)).

### Fixed

- **MoveToCard: keys silently not written to card during rotation.** When
  `--command-fd` is active, GPG reads "Replace existing key?" answers from
  stdin instead of honoring `--yes`. The confirmation consumed the `save`
  command, so the session exited without saving. Fixed by providing explicit
  `y` answers for the replacement prompt. Also added post-move verification
  that checks card fingerprints match the expected keys.

- **card rotate/provision: new subkeys not associated with card in inventory.**
  After `MoveToCard`, the inventory update relied on `CardSerial` matching from
  a re-listed keyring, but GPG doesn't always update the card serial
  immediately. Fixed by using the known key IDs from before the move.

- **card discover: subkeys not refreshed for existing cards.** `card discover`
  only updated the model for cards already in inventory, never syncing the
  subkey list. Now always syncs subkeys to match what's physically on the card.

- **GitHub publish: SSH key mismatch after card rotation.** `publishToGitHub`
  used `gpg --export-ssh-key` (keyring-based), which could differ from the key
  the agent actually serves from the card. Now prefers `ssh-add -L` (the real
  agent key). Also deletes old SSH keys with the same title before adding.

- **SSH pubkey export picks revoked key.** `ExportSSHPubKey` picked the first
  auth subkey found, even if revoked. Now selects the latest active auth
  subkey.

- **card rotate: keytocard fails with exit status 2 on keyrings with expired subkeys.**
  When card slots were already occupied (e.g. during rotation), GPG asked an extra
  "Replace existing key?" prompt that the pre-written command sequence did not account
  for, causing stdin commands to desynchronize. Fixed by passing `--yes` to GPG to
  auto-confirm all yes/no prompts.

- **card rotate: master key passphrase prompted three times (once per subkey).**
  Each subkey was moved in a separate `gpg --edit-key` process, each triggering its
  own pinentry passphrase dialog. Fixed by batching all keytocard operations into a
  single `--edit-key` session so the passphrase is requested only once.
