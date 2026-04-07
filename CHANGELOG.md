# Changelog

## Unreleased

### Added

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
