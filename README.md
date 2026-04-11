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

**Scripted automation** -- start the daemon once (`gpgsmith daemon start`),
open the vault (`gpgsmith vault open work`), then run any number of
`gpgsmith <noun> <verb>` commands against the daemon-held session.

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

gpgsmith runs as a background daemon that holds open vaults in memory.
Every CLI command talks to the daemon over a per-user Unix socket, so
commands that follow a `vault open` are sub-millisecond RPCs.

Each open vault is a **session** identified by an opaque token. The CLI
binds your terminal to a session by spawning a subshell with
`GPGSMITH_SESSION=<token>` set in its environment; the web UI binds a
browser tab to a session via an HttpOnly cookie. A daemon may hold many
sessions at once; each auto-seals after 5 minutes of idle time.

### 1. First-time setup (new keys) -- recommended

```bash
# All-in-one wizard: creates registry entry, writes vault, generates keys.
gpgsmith setup --name "Your Name" --email "you@example.com"

gpgsmith keys status                            # verify your new keys
gpgsmith card provision green --description "on keychain"  # optional
gpgsmith vault seal --message "initial setup"   # save the new snapshot
```

### 2. Open and work with a vault

```bash
$ gpgsmith vault open work                        # prompts for passphrase
Vault passphrase:
opened work as session 7f3a... (5 min idle timeout)
[gpgsmith:work] $ gpgsmith keys list              # subshell has GPGSMITH_SESSION set
[gpgsmith:work] $ gpgsmith card provision green
[gpgsmith:work] $ gpgsmith vault seal --message "provisioned green"
[gpgsmith:work] $ exit                            # back to your normal shell
```

`gpgsmith vault open` spawns a child `$SHELL` (bash, zsh — fish falls back
to sh) with the session token in its environment. Inside the subshell
every `gpgsmith` invocation automatically targets the bound session.
Exiting the subshell returns to your parent shell; the daemon keeps the
session in memory until its 5-minute idle timer fires.

For scripted use: `eval "$(gpgsmith vault open --no-shell work)"` prints
`export GPGSMITH_SESSION=...` to stdout instead of spawning a subshell.

### 3. Import an existing GNUPGHOME

```bash
gpgsmith vault create work                      # creates registry entry + empty vault
gpgsmith vault import ~/.gnupg --name work      # seals ~/.gnupg as a snapshot
```

All examples below assume you've already run `gpgsmith vault open work`
and are inside the resulting `[gpgsmith:work] $` subshell.

### 4. Discover existing YubiKeys

```bash
[gpgsmith:work] $ gpgsmith card discover         # detect connected YubiKey
[gpgsmith:work] $ gpgsmith vault seal --message "added card to inventory"
```

### 5. Rotate subkeys

```bash
[gpgsmith:work] $ gpgsmith card rotate green     # revoke old + new + to-card + publish + ssh
[gpgsmith:work] $ gpgsmith vault seal --message "rotated subkeys 2026"
```

### 6. Manage identities (add/revoke email, change primary)

```bash
[gpgsmith:work] $ gpgsmith keys identity list
[gpgsmith:work] $ gpgsmith keys identity add "Your Name <new@example.com>"
[gpgsmith:work] $ gpgsmith keys identity primary 2     # 1-based index
[gpgsmith:work] $ gpgsmith keys identity revoke "Your Name <old@example.com>"
[gpgsmith:work] $ gpgsmith vault seal --message "identity changes"
```

Every mutation is captured in the audit log and auto-republished to enabled servers.
`keys uid` is kept as an alias for users who prefer GPG's terminology.

### 7. Check inventory, audit log, and daemon state

```bash
gpgsmith vault status                           # which vaults does the daemon hold?
[gpgsmith:work] $ gpgsmith card inventory
[gpgsmith:work] $ gpgsmith audit show --last 10
[gpgsmith:work] $ gpgsmith vault discard        # end session without sealing
```

### 8. Browse the vault from a web browser

```bash
gpgsmith webui                                  # auto-spawns daemon, opens browser
# logs: gpgsmith web UI: http://127.0.0.1:41753/?t=<startup-token>
```

`gpgsmith webui` starts a loopback-only HTTP server (random port), prints
a single-use URL containing a startup token, and (with `--open`) launches
your default browser. The startup token is exchanged for an HttpOnly,
SameSite=Strict cookie scoped to the loopback host; each browser tab is
its own independent session. Pages: vault dashboard (open / discard),
keys, identities, cards, servers, audit log. Read-only for the v0.5.0 MVP.

### 9. Controlling the daemon explicitly

```bash
gpgsmith daemon status                          # is it running?
gpgsmith daemon start                           # or let auto-spawn handle it
gpgsmith daemon stop
gpgsmith daemon restart
```

## CLI Reference

```
gpgsmith
├── daemon                          manage the gpgsmith background daemon
│   ├── start [--foreground]
│   ├── stop [--timeout]
│   ├── status
│   └── restart
├── setup                           first-time wizard: vault create + keys create
├── vault                           manage encrypted vaults
│   ├── list                        list all configured vaults from the registry
│   ├── status                      show which sessions are open (+ recoverable ephemerals)
│   ├── create <name>               create a new vault entry + empty initial snapshot
│   ├── open <name> [--no-shell]    open a vault and spawn a bound subshell
│   ├── seal                        seal the bound session
│   ├── discard                     discard the bound session without sealing
│   ├── snapshots <name>            list canonical snapshots of a vault
│   ├── import <path>               encrypt an existing GNUPGHOME as a new snapshot
│   ├── export <name> <target>      decrypt the latest snapshot to a target dir
│   └── trust <name> <fp>           update the TOFU trust anchor after a rotation
├── keys                            GPG key operations (against the bound session)
│   ├── create                      generate new master key and subkeys
│   ├── generate                    add new S/E/A subkeys
│   ├── list                        list keys and subkeys
│   ├── revoke <key-id>             revoke a specific subkey
│   ├── export                      export public key to ~/.gnupg
│   ├── ssh-pubkey                  export auth subkey as SSH public key
│   ├── status                      show key and card info
│   └── identity                    manage identities on the master key
│       ├── list
│       ├── add <id>
│       ├── revoke <id-or-index>
│       └── primary <id-or-index>
├── card                            high-level YubiKey workflows
│   ├── provision <label>           generate subkeys + to-card + publish + ssh-pubkey
│   ├── rotate <label>              revoke old + generate new + to-card + publish + ssh
│   ├── revoke <label>              revoke all subkeys for a card
│   ├── inventory
│   └── discover
├── server                          manage publish targets
│   ├── list, add, remove, enable, disable
│   ├── publish [alias...]
│   └── lookup
├── audit
│   └── show [--last N]
├── webui [--bind] [--open]         start the loopback-only web UI
└── version                         show version information
```

`<label>` accepts a card label (e.g., "green") or serial number.

`keys` commands are low-level building blocks. `card` commands are high-level
workflows that compose `keys` operations internally.

Every session-bearing command (`keys`, `card`, `server`, `audit`, `vault seal`,
`vault discard`) targets the session identified by `GPGSMITH_SESSION` in your
environment. `gpgsmith vault open` sets that variable for you by spawning a
subshell. If you invoke a session-bearing command from a terminal where
`GPGSMITH_SESSION` is unset and the daemon has exactly one open session, the
CLI auto-binds to it.

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--vault-dir` | _(unset)_ | Override vault directory (ignores the registry; useful for tests) |
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
                daemon holds session (GNUPGHOME = tmpdir, in-memory)
                   |
                CLI RPCs -> daemon -> gpg --homedir tmpdir ...
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
- The passphrase stays inside the daemon process for the lifetime of the
  session and is never exported into any client shell.

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

## Sessions, terminals, and tabs

gpgsmith follows the **gpg-agent / ssh-agent pattern**: a long-running
daemon owns the decrypted vaults; thin clients (CLI, web UI, future TUI)
attach to a session via an opaque token.

### Sessions are token-bound

Every `gpgsmith vault open` creates an independent session: the daemon
decrypts the latest snapshot into `/dev/shm` (Linux) or the temp dir
(macOS), spawns its own gpg-agent + scdaemon pair, mints a 64-character
hex token, and returns it to the client. Two `gpgsmith vault open work`
calls in two terminals produce two separate sessions with two separate
workdirs and two separate tokens — they do not share state.

### CLI: subshell binding

```bash
$ gpgsmith vault open work
Vault passphrase:
opened work as session 7f3a... (5 min idle timeout)
[gpgsmith:work] $ gpgsmith keys list      # GPGSMITH_SESSION is set in this subshell
[gpgsmith:work] $ exit                    # back to the parent shell
```

The subshell is `$SHELL` (bash, zsh — fish falls back to sh) with a
small generated rc file that prepends `[gpgsmith:<vault>]` to your
prompt. Inside the subshell every `gpgsmith` invocation reads
`GPGSMITH_SESSION` from the environment and sends it to the daemon as
the `Gpgsmith-Session` HTTP header. Exit the subshell to release the
binding from your terminal; the daemon keeps the session open until its
5-minute idle timer fires.

For scripted use, `gpgsmith vault open --no-shell work` prints
`export GPGSMITH_SESSION=...` to stdout for `eval $(...)`.

### Web UI: cookie binding

`gpgsmith webui` starts a loopback-only HTTP server that binds each
browser tab to a session via an HttpOnly + SameSite=Strict cookie. The
URL printed at startup carries a one-shot startup token; visiting it
exchanges the token for a per-tab cookie and redirects to the bare URL.
A tab opens its own session (with passphrase) from the dashboard;
closing the tab releases the binding (the daemon's idle timer eventually
sweeps the session). Multi-tab is supported — each tab is independent.

### Auto-bind fallback

When you invoke a session-bearing CLI command without `GPGSMITH_SESSION`
set and the daemon has exactly one open session, the CLI auto-binds to
that session. With zero or two-plus open sessions, the CLI errors and
asks you to either `gpgsmith vault open <name>` or set the env var
explicitly.

### Idle auto-seal

Each session has its own 5-minute idle timer. After expiry the daemon
flushes the workdir to an encrypted `.session-<host>` file pair on disk
and drops the in-memory state. The next `vault open` for the same vault
detects the ephemeral and offers to resume or discard.

### Daemon auto-spawn

If the daemon is not running, any CLI command (or `gpgsmith webui`)
auto-spawns it as a detached child. Explicit `gpgsmith daemon start` is
optional.

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

No environment variables for configuration itself. Session state
(decrypted GNUPGHOME path, vault passphrase) lives entirely in the
daemon process. The CLI uses **one** environment variable —
`GPGSMITH_SESSION` — as a per-terminal selector pointing at one of the
daemon's open sessions; it carries an opaque token, never the
passphrase. The web UI uses an HttpOnly cookie for the equivalent
per-tab selector. Both are set automatically by `gpgsmith vault open`
and `gpgsmith webui`.

## Project Structure

```
locksmith/
├── cmd/gpgsmith/          binary entrypoint (ldflags for version info)
├── pkg/
│   ├── vault/             encrypted snapshot storage (age + tar), shared
│   ├── audit/             audit logging, shared
│   ├── gpg/               GPG operations, inventory, card management
│   ├── gpgsmith/          session type, TOFU trust, process hardening
│   ├── daemon/            long-running daemon: token-keyed session map, idle auto-seal
│   ├── wire/              ConnectRPC adapter (server + client over UDS/h2c, session header)
│   ├── gen/               buf-generated protobuf + ConnectRPC stubs
│   ├── cli/gpgsmith/      CLI wiring (urfave/cli/v3), thin daemon client + subshell wrapping
│   └── webui/gpgsmith/    loopback-only HTTP frontend (html/template + HTMX, embedded assets)
├── proto/                 protobuf schema (buf-managed)
├── testdata/              fixtures for GPG output parsing
├── Justfile               build/test/lint commands
├── devbox.json            dev environment (Go, golangci-lint, just, goreleaser, buf, protoc-gen-*)
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
