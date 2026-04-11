# Changelog

## Unreleased

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

  No user-facing change in behavior — `gpgsmith card discover` "just
  works" now.

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
- **`VaultService.Create` RPC** — the wire surface backing
  `gpgsmith vault create` and `gpgsmith setup`.
- **Real `VaultService.Export` / `Backend.ExportVault` implementation**
  on the daemon side (was a stub in commit 5b).
- **Auto-spawn daemon on every user-facing command.** If the daemon is
  not running when you invoke a CLI command, a detached copy starts
  automatically; the first command pays the startup cost and subsequent
  commands are sub-millisecond RPCs.
- **Idle auto-seal-to-ephemeral.** After 5 minutes of no activity, the
  daemon flushes the in-memory workdir to the encrypted ephemeral file
  pair and drops the session state from memory, allowing the next
  `vault open` on the same vault to offer to resume.

### Removed

- **`pkg/gpgsmith/lock.go` and `pkg/gpgsmith/lock_test.go`** (flock-based
  single-holder enforcement). The daemon's in-process session map is
  now the single source of truth for which vaults are open; cross-host
  coordination was never possible via flock anyway.
- **`tty.go` session wrapper machinery**: `newSessionRC`, `bashSessionRC`,
  `zshSessionRC`, `sessionRC`, `shellEscapeSingleQuote`, and
  `runInteractiveSession` are deleted. `promptLine`, `readPassphrase`,
  and `readPassphraseWithConfirm` remain as small terminal helpers.

### Migration

- Remove `eval $(gpgsmith vault open ...)` or equivalent patterns from
  your shell rc files — they are no-ops now.
- The daemon binary is the same `gpgsmith` binary. You can start it
  explicitly with `gpgsmith daemon start`, or let auto-spawn handle it
  on first use.

### Added (earlier, from prior commits)

- **`pkg/wire` ConnectRPC adapter layer.** The hand-written ConnectRPC
  layer that wraps the generated stubs from `pkg/gen` and adapts them
  to the kernel API: server handlers (one per service), a typed client
  wrapper that bundles all eight service clients, and a proto↔kernel
  type-conversion layer. The package is named `wire` rather than `rpc`
  because Go's standard library already has `net/rpc` and golangci-lint's
  revive var-naming rule flags the shadowed name; the new name also
  clearly conveys "this is the wire format / wire protocol layer".

  - `Backend` interface — the contract that handlers call into. Exposes
    the gpgsmith kernel surface in a session-aware, daemon-style API
    where every session-bearing method takes a vault name. Implemented
    by the daemon (forthcoming).
  - One handler file per service (`handlers_daemon.go`,
    `handlers_vault.go`, `handlers_key.go`, `handlers_identity.go`,
    `handlers_card.go`, `handlers_server.go`, `handlers_audit.go`,
    `handlers_event.go`). Each handler embeds the corresponding
    `Unimplemented*ServiceHandler` from the generated package and
    delegates to a `Backend` method, translating proto types in/out via
    `mapping.go`.
  - `mapping.go` — proto↔kernel type converters. The only place in the
    codebase where protobuf types appear in hand-written code; the rest
    of the codebase sees only kernel-shaped Go values.
  - `errors.go` — translates kernel errors into Connect-coded errors:
    `MasterKeyMismatchError` → `CodeFailedPrecondition`,
    `LockContentionError` → `CodeAlreadyExists`,
    `context.Canceled` → `CodeCanceled`, everything else → `CodeInternal`.
  - `Server` — bundles all handlers into a single `http.Handler` that
    the daemon mounts on its Unix socket.
  - `Client` — typed client wrapper that bundles all eight generated
    `*ServiceClient` interfaces. Constructors:
    `NewUnixSocketClient(path)` for the production daemon connection
    and `NewHTTPClient(client, baseURL)` for tests using
    `httptest.Server`.
  - Seven round-trip tests using an in-process Connect server with a
    fake `Backend`: daemon status, identity list (with revoked UID),
    identity add, backend error propagation as Connect codes,
    Unix-socket client construction, server handler construction, and
    HTTP routing.

  Not yet wired into a real daemon process — `pkg/daemon` is the next
  commit. The wire layer is complete and tested in isolation against
  the fake backend.

- **Protobuf schema and ConnectRPC code generation foundation** for the
  upcoming gpgsmith daemon. The wire format is the dedicated package
  `gpgsmith.v1` defined under `proto/gpgsmith/v1/`. Eight services cover
  the full kernel surface: `DaemonService` (status, shutdown, list
  sessions), `VaultService` (list, status, open, resume, seal, discard,
  snapshots, import, export, trust), `KeyService` (create, generate,
  list, revoke, export, ssh-pubkey, status), `IdentityService` (list,
  add, revoke, primary), `CardService` (provision, rotate, revoke,
  inventory, discover), `ServerService` (publish-target registry +
  publish + lookup), `AuditService` (show), and `EventService`
  (server-streaming pub/sub for job progress and "touch your YubiKey"
  prompts).

  Tooling:

  - `devbox.json` adds `buf`, `protoc-gen-go`, and `protoc-gen-connect-go`
    so contributors get the toolchain via `direnv allow` with no manual
    install steps.
  - `proto/buf.yaml` configures the buf module with the STANDARD lint
    rules (with two stylistic naming exceptions documented inline) plus
    file-level breaking-change checks.
  - `proto/buf.gen.yaml` (v2 schema) drives codegen via the local
    `protoc-gen-go` and `protoc-gen-connect-go` plugins delivered by
    devbox. Output goes to `pkg/gen/gpgsmith/v1/` (message types) and
    `pkg/gen/gpgsmith/v1/gpgsmithv1connect/` (service interfaces, client
    constructors, handler factories).
  - `pkg/gen/gen.go` holds the `//go:generate buf generate ...` directive
    so `go generate ./pkg/gen` regenerates everything.
  - **Generated code is committed to git** so `go install`, CI, and
    contributors who only touch Go do not need buf.
  - `just generate` regenerates the wire schema.
  - `just lint-proto` runs `buf lint`, separate from `just lint` so a
    misformatted .proto file does not break the Go developer feedback loop.
  - `just generate-check` is a CI helper that runs `just generate` and
    fails if the working tree is dirty afterwards (catches missing
    regeneration after .proto edits).

  No new functionality or behavior change in this commit — purely setting
  up the wire format. The kernel API and existing CLI are untouched.
  The schema and generated stubs become callable in the next commit when
  the daemon and the `pkg/rpc` adapter package land.

- **Vault registry: multi-vault support in `~/.config/locksmith/config.yaml`.**
  The config file now supports a `vaults:` list with named entries plus a
  `default:` selector, alongside the existing single-vault `vault_dir:` form.
  Both forms remain valid and may coexist; the legacy `vault_dir:` is exposed
  as a synthetic registry entry named `default`.

  ```yaml
  vaults:
    - name: personal
      path: ~/Dropbox/Private/vault
      identity: ~/.config/locksmith/personal.age   # optional, per-vault
    - name: work
      path: ~/work/vault
  default: personal
  ```

  New global flag `--vault <name>` selects an entry from the registry.
  `--vault-dir <path>` still works for tests and one-off scripted runs and
  takes precedence over the registry. Per-entry `identity` and `gpg_binary`
  fields override the top-level legacy fields when set.

  `vault config show` now prints the full registry when present.
  `vault config set` continues to operate on the legacy top-level fields;
  registry editing is done by editing the YAML directly for now.

### Changed (internal, no user-visible behavior change)

- **CLI implementation moved from `pkg/gpgsmith` to `pkg/cli/gpgsmith`** to free
  up `pkg/gpgsmith` for the upcoming kernel package. The new layout is:
  `pkg/gpg`, `pkg/vault`, `pkg/audit` (primitives) → `pkg/gpgsmith` (kernel,
  forthcoming) → `pkg/cli/gpgsmith` (CLI frontend). Future siblings:
  `pkg/cli/pkismith` (when pkismith ships), `pkg/webui/gpgsmith`,
  `pkg/tui/gpgsmith`. Pure mechanical rename — no behavior change.

- **`vault.Config.Resolve(name)` and `vault.Entry`** added to `pkg/vault`.
  Resolves a vault name to an effective entry, handling all combinations of
  legacy + registry forms with backward-compatible precedence. Tests cover
  every resolution path.

- **`Session` type, TOFU, and process hardening in `pkg/gpgsmith`.** This is the
  first piece of the kernel API that consumes the ephemeral file convention
  from the previous commit and ties together all the lower-level pieces
  (`pkg/vault`, `pkg/gpg`, agent config, ephemeral helpers).

  **`Session` lifecycle**:

  - `OpenSession(ctx, vault, entry, opts)` — decrypts the latest canonical
    snapshot of `entry` into a tmpfs workdir, writes loopback `gpg.conf`/
    `gpg-agent.conf`, constructs an authenticated `gpg.Client`, performs the
    TOFU check (see below), writes the initial `.info` sidecar with status
    `active`, and starts a heartbeat goroutine. Returns an `OpenSessionResult`
    with the `Session` plus a `TOFUFingerprint` side-channel that the caller
    persists into the vault registry on first use.
  - `Session.Seal(ctx, message)` — explicit seal: writes a new canonical
    snapshot, deletes the ephemeral file pair, stops the heartbeat, marks
    the session closed.
  - `Session.Discard(ctx)` — explicit discard: removes the workdir, deletes
    the ephemeral file pair, stops the heartbeat, marks the session closed.
  - `Session.AutoSealAndDrop(ctx)` — idle-timeout end-path: forces a final
    flush of the workdir to the encrypted `.session-<host>` ephemeral file,
    marks `.info` status as `idle-sealed`, drops the in-memory workdir, and
    leaves the ephemeral pair on disk so the next `OpenSession` on the
    same vault can offer to resume.
  - `Session.MarkChanged()` — bumps an atomic mutation counter that the
    heartbeat goroutine uses to decide whether to re-flush the encrypted
    ephemeral state on each tick.
  - `Session.IsClosed()` — state-machine probe.

  **Heartbeat goroutine** runs for the lifetime of an open Session. Default
  tick interval is 30 seconds (`DefaultHeartbeatInterval`). Each tick:
  refreshes the `.info` sidecar with a fresh `last_heartbeat` timestamp;
  if the mutation generation has advanced since the last flush, also
  re-flushes the workdir to the encrypted `.session-<host>` file.

  **TOFU master-key trust**: a new `TrustedMasterFP` field on `vault.Entry`
  records the master fingerprint of the vault on first use. `OpenSession`
  reads `gpgsmith.yaml` from the decrypted workdir; if the entry has no
  trusted fingerprint yet, it returns the discovered one in
  `OpenSessionResult.TOFUFingerprint` for the caller to persist; if the
  entry has a trusted fingerprint and it does NOT match, `OpenSession`
  refuses with `MasterKeyMismatchError` (a typed error with
  `IsMasterKeyMismatch(err)` test) carrying expected/found/snapshot for
  the loud user-facing message:

  ```
  vault "personal": master key mismatch — expected ABC... found XYZ... in
    20260410T143012Z_setup.tar.age
  This snapshot was either replaced by an attacker with write access to
  the vault directory, or generated from a fresh setup that overwrote
  your real vault.
  If you legitimately rotated your master key, update the trust anchor
  with: gpgsmith vault trust personal XYZ...
  ```

  **`vault.SealEphemeral(ctx, workdir, targetPath)`** is a new method on
  `*vault.Vault` that tars and encrypts a workdir into a caller-supplied
  target path (the `.session-<host>` ephemeral file location), reusing the
  vault's encryption identity. Atomic: temp file + rename so concurrent
  readers see either the previous version or the new one, never a half
  write. Unlike `Seal`, it does NOT remove the workdir or generate a
  timestamped canonical name.

  **Process hardening** (`HardenProcess`): cross-platform best-effort
  same-user attack mitigations, intended to be called once at daemon
  startup. On Linux: `prctl(PR_SET_DUMPABLE, 0)` (blocks ptrace,
  process_vm_readv, and `/proc/<pid>/{mem,maps,root}` from non-root same-user
  processes — the kernel re-owns those files to root) plus
  `setrlimit(RLIMIT_CORE, 0)` (no core dumps leaking heap on crash). On
  macOS: `ptrace(PT_DENY_ATTACH)` (the macOS analog of `PR_SET_DUMPABLE`)
  plus `RLIMIT_CORE`. The function is exported but **not** called
  automatically by `OpenSession` or any other kernel API: the daemon
  binary's main() is responsible for opting in, because hardening is a
  process-wide flag that would also affect tests and developer debugging.

  **Twelve unit tests** cover the full lifecycle: open + discard, open
  + seal, TOFU first-use, TOFU match, TOFU mismatch (verifies no
  leftover files on the failed-open path), TOFU skip on key-less vaults,
  double-end errors, MarkChanged generation counter, heartbeat
  `.info` advancement, heartbeat-triggered ephemeral flush on mutation,
  AutoSealAndDrop idle-path semantics, and `HardenProcess` idempotence.
  Tests use a generous deadline-based polling helper to accommodate age's
  scrypt KDF (~1 second per encrypt) without flakiness. Not yet wired into
  the CLI; that lands when the daemon arrives.

- **Ephemeral session file convention** in `pkg/gpgsmith`. Defines and implements
  the on-disk shape of "session in progress" markers that the daemon will
  write into the vault directory alongside canonical snapshots:

  ```
  <vault-dir>/20260410T143012Z_setup.tar.age                                 ← canonical (immutable)
  <vault-dir>/20260410T143012Z_setup.tar.age.session-laptop.local            ← in-progress encrypted state
  <vault-dir>/20260410T143012Z_setup.tar.age.session-laptop.local.info       ← liveness sidecar (plaintext)
  ```

  The base canonical filename is preserved in the suffix so the parent
  relationship is visible at a glance, and **divergence detection becomes a
  filename comparison**: if a session file references canonical X but a newer
  canonical Y is in the same directory, the user has changes from another
  machine that the in-progress session does not include.

  The hostname suffix lets multiple machines (in a Dropbox/Syncthing-synced
  vault directory) coexist without colliding on filenames. Each machine has
  at most one in-progress session per vault, named after its own hostname.

  `pkg/gpgsmith/ephemeral.go` provides:

  - `SessionFilenamesFor(canonical, hostname)` — derive both filenames
  - `ParseSessionFilename(name)` — split a name back into canonical + hostname
  - `WriteEphemeralInfo` / `ReadEphemeralInfo` — atomic YAML read/write
    for the `.info` sidecar (temp file + rename)
  - `EphemeralInfo.IsStale(now)` — heartbeat-timestamp staleness check
    (`StaleHeartbeatThreshold` = 90 seconds, generously larger than the
    `HeartbeatInterval` = 30 seconds to tolerate sync delay)
  - `ListEphemerals(vaultDir)` — find every `.session-<host>.info` in a
    vault dir, parse each, return sorted by hostname; junk and unparseable
    files are silently skipped
  - `FindEphemeralFor(vaultDir, hostname)` — lookup by hostname
  - `Ephemeral.IsDivergent(canonicalNames)` — compare canonical base
    against the dir's canonical list, true if a newer one exists
  - `DeleteEphemeralFiles` — idempotent cleanup of the file pair

  11 unit tests covering filename round-trip, parser edge cases, atomic
  write, mode-0600 permissions, multi-host listing, junk filtering,
  staleness detection (including clock-skew futures), divergence detection
  (no-other / older-only / newer-present / missing-canonical cases),
  and idempotent deletion. Not yet wired into a Session type — that lands
  in the next commit.

- **New kernel package `pkg/gpgsmith` with vault lock primitive**
  (`AcquireVaultLock`, `Lock.Release`, `LockContentionError`,
  `ReadLockInfoFor`, `ForceUnlockVault`). Uses `flock(2)` so the kernel
  automatically releases the lock when the holding process dies (even on
  `SIGKILL`) — no stale-PID-file cleanup. A sidecar `.info` YAML file
  records the holder's PID, source (`cli` / `ui` / `tui`), start time, and
  hostname for diagnostic messages on contention. Lock files live under
  `${XDG_RUNTIME_DIR}/gpgsmith/locks` on Linux and `${TMPDIR}/gpgsmith/locks`
  on macOS, named by the SHA-256 of the absolute vault path so different
  vaults at different paths get distinct locks. **Per-host only** — file-sync
  setups (Dropbox, Syncthing) cannot be coordinated by this mechanism.
  Eight unit tests cover acquire, release, contention, double-release,
  re-acquire after release, distinct-vault independence, path-canonicalization
  (a relative path contends with the same vault opened by absolute path),
  force-unlock, and a subprocess test that proves kernel auto-release on
  process exit. Not yet wired into the CLI; that lands in the next commit.

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
