# Changelog

## Unreleased

### Changed (internal, no user-visible behavior change)

- **CLI implementation moved from `pkg/gpgsmith` to `pkg/cli/gpgsmith`** to free
  up `pkg/gpgsmith` for the upcoming kernel package. The new layout is:
  `pkg/gpg`, `pkg/vault`, `pkg/audit` (primitives) → `pkg/gpgsmith` (kernel,
  forthcoming) → `pkg/cli/gpgsmith` (CLI frontend). Future siblings:
  `pkg/cli/pkismith` (when pkismith ships), `pkg/webui/gpgsmith`,
  `pkg/tui/gpgsmith`. Pure mechanical rename — no behavior change.

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
