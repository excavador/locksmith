# locksmith

GPG key lifecycle manager with encrypted vault storage and YubiKey support.

**gpgsmith** automates the routine of generating, rotating, provisioning, and
revoking GPG subkeys across multiple YubiKeys. Keys live in append-only
encrypted snapshots so every change is recoverable, and the whole vault syncs
via any file-sync service (Dropbox, Syncthing, etc.) with no special tooling.

## The Problem

Managing GPG keys with YubiKeys is a manual, error-prone process:

- Decrypt a LUKS volume (requires root, specific OS, specific hardware)
- Set `GNUPGHOME`, run a dozen `gpg` commands in the right order
- Remember which subkeys are on which YubiKey
- Re-encrypt, hope you didn't forget a step
- No audit trail, no inventory, no easy recovery

gpgsmith replaces this with a single tool that handles encryption, key
operations, YubiKey provisioning, publishing, and record-keeping automatically.

## Use Cases

**First-time setup (existing keys)** -- migrate keys from a LUKS vault or
`~/.gnupg` into gpgsmith's encrypted vault.

**First-time setup (new keys)** -- `gpgsmith setup` wizard creates a vault,
generates a master key + S/E/A subkeys, and opens a session where you can
provision a YubiKey.

**Routine subkey rotation** -- revoke expiring subkeys, generate new ones,
provision to YubiKey, publish, and export SSH key with `card rotate`.

**Provision a second YubiKey** -- restore a pre-card snapshot and provision a
spare YubiKey with the same or unique subkeys.

**Lost YubiKey** -- revoke all subkeys associated with a card and publish
revocations with `card revoke`.

**New workstation** -- open the vault (synced via Dropbox), export SSH public
key, done.

**Scripted automation** -- `eval $(gpgsmith vault open)` for CI or cron-style
workflows, following the ssh-agent pattern.

## Prerequisites

- **[devbox](https://www.jetify.com/devbox/docs/installing_devbox/)** -- portable dev environment (provides Go, golangci-lint, just, goreleaser)
- **[direnv](https://direnv.net/docs/installation.html)** -- auto-loads the devbox environment on `cd`
- **gpg** -- GnuPG 2.x must be installed and on `PATH`

### Optional dependencies

- **[ykman](https://developers.yubico.com/yubikey-manager/)** (yubikey-manager) -- enables specific YubiKey model detection (e.g., "YubiKey 5 NFC" instead of generic "Yubico YubiKey"). Install via `pip install yubikey-manager` or your package manager.
- **[gh](https://cli.github.com/)** -- GitHub CLI, enables publishing GPG and SSH keys to GitHub via `server publish github`. Requires `admin:gpg_key` and `admin:public_key` OAuth scopes.

## Installation

### From source (recommended during development)

```bash
cd locksmith
direnv allow
just build          # builds bin/gpgsmith
```

### Go install

```bash
go install github.com/excavador/locksmith/cmd/gpgsmith@latest
```

### GitHub releases

Pre-built binaries for Linux and macOS (amd64/arm64) are published on
[GitHub Releases](https://github.com/excavador/locksmith/releases) via
goreleaser on every tagged version.

## Quick Start

### 1a. First-time setup (new keys) -- recommended

```bash
# All-in-one wizard: creates vault, generates master key + subkeys, opens session
gpgsmith setup --name "Your Name" --email "you@example.com"

# Inside the gpgsmith shell:
gpgsmith keys list                  # verify your new keys
gpgsmith card provision green --description "on keychain"  # optional: provision a YubiKey
exit                                # prompts to seal or discard
```

### 1b. Create a vault and import existing keys

```bash
# Create a new vault (prompts for passphrase, opens a session)
gpgsmith vault create

# Or import an existing GNUPGHOME
gpgsmith vault create
gpgsmith vault import ~/.gnupg
```

### 1c. Create a vault and generate keys manually

```bash
gpgsmith vault create

# Inside the gpgsmith shell:
gpgsmith keys create --name "Your Name" --email "you@example.com"
gpgsmith keys list                  # verify: 1 master (C) + 3 subkeys (S/E/A)
exit                                # seal: "initial key creation"
```

### 2. Open the vault

```bash
# Interactive: spawns a subshell with GNUPGHOME set
gpgsmith vault open

# Inside the gpgsmith shell:
gpgsmith keys list
gpgsmith card provision green --description "on keychain"
gpg --list-keys                     # raw gpg works too
exit                                # prompts to seal or discard
```

### 3. Discover existing YubiKeys

```bash
gpgsmith vault open
gpgsmith card discover              # detect connected YubiKey, prompt for label
# Label: green
# Description: on keychain
# Added "green" (19750652) to inventory.
exit
```

### 4. Provision a YubiKey

```bash
gpgsmith vault open
gpgsmith card provision green       # generate + to-card + publish + ssh-pubkey
exit                                # seal: "provisioned green YubiKey"
```

### 5. Rotate subkeys

```bash
gpgsmith vault open
gpgsmith card rotate green          # revoke old + generate new + to-card + publish + ssh
exit                                # seal: "rotated subkeys 2026"
```

### 6. Manage identities (add/revoke email, change primary)

```bash
gpgsmith vault open
gpgsmith keys identity list                                         # current UIDs on the master key
gpgsmith keys identity add "Your Name <new@example.com>"            # attach a new identity
gpgsmith keys identity primary 2                                    # promote by 1-based index
gpgsmith keys identity revoke "Your Name <old@example.com>"         # revoke by exact match
gpgsmith keys identity revoke 3                                     # or revoke by index
exit                                                                # seal: "identity changes"
```

Every mutation is captured in the audit log and auto-republished to enabled servers.
`keys uid` is kept as an alias for users who prefer GPG's terminology.

### 7. Check inventory and audit log

```bash
gpgsmith vault open
gpgsmith card inventory             # which cards, which keys
gpgsmith audit show --last 10       # recent operations
gpgsmith vault discard              # read-only, nothing to seal
```

## CLI Reference

```
gpgsmith
├── setup                  first-time wizard: vault create + keys create + card provision
├── vault                  manage encrypted vault
│   ├── create             create a new vault
│   ├── import <path>      import existing GNUPGHOME as first snapshot
│   ├── open               decrypt latest snapshot and start session
│   ├── seal <message>     save current session as new snapshot
│   ├── discard            discard session without saving
│   ├── list               list all snapshots
│   ├── restore <ref>      restore a specific snapshot and start session
│   └── config
│       ├── show           show vault config
│       └── set <k> <v>    set a vault config value
├── keys                   GPG key operations (requires GNUPGHOME set via vault open)
│   ├── create             generate new master key and subkeys
│   ├── generate           add new S/E/A subkeys
│   ├── to-card            move subkeys to YubiKey (--same-keys / --unique-keys)
│   ├── list               list keys and subkeys
│   ├── revoke <key-id>    revoke a specific subkey
│   ├── export             export public key to local ~/.gnupg keyring
│   ├── ssh-pubkey         export auth subkey as SSH public key (~/.ssh/)
│   ├── status             show key and card info
│   ├── identity           manage identities (name+email UIDs) on the master key
│   │   ├── list           list identities (with creation + revocation dates)
│   │   ├── add <id>       add a new identity (e.g. "Name <email@example.com>")
│   │   ├── revoke <ref>   revoke an identity by exact match or 1-based index
│   │   └── primary <ref>  set an identity as primary
│   └── config
│       ├── show           show GPG config (inside GNUPGHOME)
│       └── set <k> <v>    set a GPG config value
├── card                   high-level YubiKey workflows (requires GNUPGHOME set via vault open)
│   ├── provision <label>  generate subkeys + to-card + publish + ssh-pubkey (--description, --same-keys / --unique-keys)
│   ├── rotate <label>     revoke old + generate new + to-card + publish + ssh
│   ├── revoke <label>     revoke all subkeys for a card + publish revocation
│   ├── inventory          list all known YubiKeys
│   └── discover           detect connected YubiKey and add to inventory
├── server                 manage publish targets (keyservers and GitHub)
│   ├── publish [alias...] publish public key to enabled servers (or specific aliases)
│   ├── lookup             check which servers have your public key
│   ├── list               list all publish targets
│   ├── add <alias> <url>  add a custom keyserver
│   ├── remove <alias>     remove a server from the registry
│   ├── enable <alias>     enable a server for publishing
│   └── disable <alias>    disable a server for publishing
├── audit
│   └── show               display audit entries (--last N)
└── version                show version information
```

`<label>` accepts a card label (e.g., "green") or serial number.

`keys` commands are low-level building blocks. `card` commands are high-level
workflows that compose `keys` operations internally.

All `keys` and `card` commands require `GNUPGHOME` to be set (via `vault open`).

`vault create`, `vault import`, `vault open`, and `vault restore` all support
`--no-interactive` to output env exports instead of spawning a shell.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--vault-dir` | from config | Override vault directory |
| `--verbose` | `false` | Debug logging to stderr |
| `--dry-run` | `false` | Print commands without executing |

## Architecture

locksmith is structured as two independent layers:

### Layer 1: Vault (age + tar)

Manages encrypted, append-only snapshots. Shared and reusable -- future tools
like `pkismith` (PKI CA management) will use the same vault layer.

- Each snapshot is a self-contained `.tar.age` file (encrypted tarball)
- Append-only: new snapshot per operation, old ones never modified
- Encryption via [filippo.io/age](https://filippo.io/age) -- passphrase-based
  (scrypt) or key file
- Filename format: `<ISO8601>_<slugified-message>.tar.age`

### Layer 2: GPG + YubiKey

Operates on a `GNUPGHOME` directory. Shells out to the `gpg` binary with
`--homedir`. Stateless -- takes a directory, performs operations, done. Doesn't
know or care about encryption or storage.

### Workflow

```
vault open  ->  find latest .tar.age -> decrypt -> untar -> tmpdir
                   |
                GNUPGHOME = tmpdir (via subshell or env export)
                   |
                perform GPG operations (generate / revoke / to-card / ...)
                   |
vault seal  ->  tar tmpdir -> encrypt -> write new .tar.age -> cleanup
```

### Vault directory structure

```
~/Dropbox/Private/vault/
├── 2026-01-01T000000Z_initial-import.tar.age
├── 2026-03-15T103000Z_rotate-subkeys.tar.age
├── 2026-04-01T153000Z_new-yubikey-2.tar.age
└── ...
```

### GNUPGHOME contents (inside each tarball)

```
GNUPGHOME/
├── pubring.kbx
├── trustdb.gpg
├── gpg.conf                   # pinentry-mode loopback (set by gpgsmith)
├── gpg-agent.conf             # allow-loopback-pinentry + cache TTLs (set by gpgsmith)
├── private-keys-v1.d/
├── gpgsmith.yaml              # GPG config (master_fp, algo, expiry)
├── gpgsmith-servers.yaml      # publish target registry (keyservers, GitHub)
├── gpgsmith-inventory.yaml    # YubiKey inventory
└── gpgsmith-audit.yaml        # audit log
```

### Pinentry: loopback, always

Every gpgsmith vault is configured for **loopback pinentry mode**. gpgsmith
writes `gpg.conf` and `gpg-agent.conf` into the ephemeral GNUPGHOME with:

```
# gpg.conf
pinentry-mode loopback

# gpg-agent.conf
allow-loopback-pinentry
default-cache-ttl 3600
max-cache-ttl 28800
```

This means:

- **No GUI pinentry popup, ever** — works identically on desktops, headless
  servers, containers, and CI runners.
- **No dependency** on `pinentry-tty` / `pinentry-curses` being installed.
- The master-key passphrase is identical to the vault passphrase. gpgsmith
  passes it to gpg over a private OS pipe (fd 3 via `ExtraFiles`), never via
  argv (`--passphrase`), environment, or disk file.
- gpg-agent's cache (1 hour default, 8 hours max) covers a typical interactive
  session so the user isn't re-prompted.
- Inside the interactive gpgsmith shell, `GPGSMITH_VAULT_KEY` is exported so
  subsequent `gpgsmith` invocations inherit the passphrase transparently.

## Encryption

gpgsmith uses [age](https://age-encryption.org/) for vault encryption, not GPG.
This avoids a circular dependency (needing GPG keys to decrypt GPG keys).

Two modes:

- **Passphrase** (default): prompted from terminal, scrypt-derived key. No key
  file to manage.
- **Key file**: set `identity` in vault config to an age key file path. Useful
  for scripted/automated workflows.

### Secure temporary directory

On Linux, decrypted vaults are stored in `/dev/shm` (RAM-backed tmpfs), so
private keys never touch disk. On macOS, `os.TempDir()` is used (per-user
`/var/folders/...`). Permissions are set to `0700`. Signal handlers clean up on
interrupt.

## Interactive vs Scripted Mode

gpgsmith follows the **ssh-agent pattern** for session management.

### Interactive mode (default when TTY detected)

`vault open` (and `create`, `import`, `restore`) spawns `$SHELL` with
`GNUPGHOME` set and a `(gpgsmith)` prompt prefix. The `GPGSMITH_SESSION=1`
environment variable is also set, so you can customize your shell prompt in
`.bashrc`/`.zshrc` based on it. On shell exit, prompts to seal or discard:

```bash
$ gpgsmith vault open
Entering gpgsmith shell. GNUPGHOME is set.
Run gpgsmith commands or raw gpg. Type 'exit' when done.

gpgsmith$ gpgsmith card rotate green
gpgsmith$ exit
Seal vault? [Y/n/message]: rotated subkeys
Sealed: 2026-04-01T153000Z_rotated-subkeys.tar.age
```

### Scripted mode (non-TTY or `--no-interactive`)

Like `ssh-agent` -- outputs shell exports to stdout:

```bash
eval $(gpgsmith vault open)              # export GNUPGHOME=...; export GPGSMITH_VAULT_KEY=...;
gpgsmith card rotate green               # uses GNUPGHOME from env
eval $(gpgsmith vault seal "rotated")    # unset GNUPGHOME; unset GPGSMITH_VAULT_KEY;
```

`GPGSMITH_VAULT_KEY` is exported so that subsequent vault commands in the same
scripted session skip the passphrase prompt.

### TTY detection

| Condition | Behavior |
|-----------|----------|
| TTY, no flag | Interactive (subshell) |
| TTY + `--no-interactive` | Scripted (env export) |
| No TTY | Scripted (env export) |

## Configuration

### Vault config: `~/.config/locksmith/config.yaml`

Machine-local, always available. Needed before decryption.

```yaml
vault_dir: ~/Dropbox/Private/vault
identity: ~/.config/locksmith/age-key.txt   # optional; prompts passphrase if absent
gpg_binary: gpg
```

### GPG config: `GNUPGHOME/gpgsmith.yaml`

Lives inside the encrypted tarball, travels with the keys. Available after
`vault open`.

```yaml
master_fp: 6E1FD854CD2D225DDAED8EB7822B3952F976544E
subkey_algo: rsa4096
subkey_expiry: 2y
```

### Server registry: `GNUPGHOME/gpgsmith-servers.yaml`

Publish targets (keyservers and GitHub) with aliases and enable/disable.
Managed via `server` commands. Initialized with built-in defaults on first use.

```yaml
servers:
  - alias: openpgp
    type: keyserver
    url: hkps://keys.openpgp.org
    enabled: true
  - alias: ubuntu
    type: keyserver
    url: hkps://keyserver.ubuntu.com
    enabled: true
  - alias: github
    type: github
    enabled: false
  - alias: mailvelope
    type: keyserver
    url: hkps://keys.mailvelope.com
    enabled: false
  - alias: mit
    type: keyserver
    url: hkps://pgp.mit.edu
    enabled: false
  - alias: gnupg
    type: keyserver
    url: hkps://keys.gnupg.net
    enabled: false
```

### Resolution order (lowest to highest priority)

1. Hardcoded defaults
2. Config files (vault config + GPG config after open)
3. CLI flags

No environment variables for configuration. `GNUPGHOME`, `GPGSMITH_VAULT_KEY`,
and `GPGSMITH_SESSION` are env vars used as session state (not configuration).

## Project Structure

```
locksmith/
├── cmd/gpgsmith/          binary entrypoint (ldflags for version info)
├── pkg/
│   ├── vault/             encrypted snapshot storage (age + tar), shared
│   ├── audit/             audit logging, shared
│   ├── gpg/               GPG operations, inventory, card management
│   └── gpgsmith/          CLI wiring (urfave/cli/v3)
├── testdata/              fixtures for GPG output parsing
├── Justfile               build/test/lint commands
├── devbox.json            dev environment (Go, golangci-lint, just, goreleaser)
└── .goreleaser.yaml       release configuration
```

## Development

```bash
just build    # build binary to bin/gpgsmith
just test     # run all tests
just lint     # run golangci-lint
just check    # lint + test
just fmt      # format code
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Ensure `just check` passes (lint + tests)
4. Open a pull request

The project uses strict golangci-lint configuration. CI runs lint and tests on
every push and pull request.

## License

[MIT](LICENSE) -- Copyright (c) 2026 Oleg Tsarev
