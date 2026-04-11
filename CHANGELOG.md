# Changelog

## Unreleased

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
