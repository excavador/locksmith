# locksmith — Design Plan (v6)

## Context

Oleg regularly rotates GPG subkeys across YubiKeys and workstations. The workflow involves decrypting a vault of GPG keys, performing operations (generate, provision, revoke, publish), and saving the result as a new encrypted snapshot. `gpgsmith` automates the entire lifecycle with YubiKey inventory tracking and audit logging.

Future: `pkismith` (PKI root/intermediate CA management) will share the vault layer.

## Repository

- **Repo:** `github.com/excavador/locksmith` (monorepo, two binaries)
- **Local path:** `~/opwerm/locksmith`
- **Module:** `github.com/excavador/locksmith`
- **Binaries:** `gpgsmith` (now), `pkismith` (future)

## Stack & Tooling

- **Language:** Go 1.26+
- **CLI framework:** urfave/cli/v3
- **GPG interaction:** shell out to `gpg` binary via `os/exec`
- **Encryption:** `filippo.io/age` (native Go library, no shelling out)
- **TTY detection:** `github.com/mattn/go-tty`
- **Config:** YAML (`gopkg.in/yaml.v3`)
- **Logging:** `log/slog` to stderr (text handler, `--verbose` for debug level)
- **stdout:** minimal/unix — only actionable output for pipe-ability
- **Dev environment:** DevBox (go, golangci-lint, just, goreleaser) + DirEnv
- **Linting:** golangci-lint (strict config)
- **Build tool:** just (Justfile)
- **Releases:** goreleaser (free) + GitHub Actions
- **CI:** GitHub Actions (free for public repos) — lint + test on push/PR, release on tag
- **License:** MIT
- **Testing:** integration tests (require gpg installed) + mocked exec for YubiKey/card ops
- **Platforms:** Linux + macOS (tested on Linux, macOS support from the start)

## Use Cases

### First time setup (existing GPG keys)
You already have GPG keys in a LUKS vault or `~/.gnupg`. Migrate to gpgsmith:
```bash
gpgsmith vault create
gpgsmith vault import /mnt/vault/gpg/2025-12-31
gpgsmith vault open
gpgsmith card discover           # detect existing YubiKey, label it "green"
exit                             # seal: "imported from LUKS vault"
```

### First time setup (new keys)
```bash
gpgsmith setup                   # wizard: vault create + keys create + card provision
# prompts for: passphrase, card label, description
# does everything automatically
```

### Routine subkey rotation
Subkeys are expiring, generate new ones and provision to YubiKey:
```bash
gpgsmith vault open
gpgsmith card rotate green       # revoke old + generate new + to-card + publish + ssh
exit                             # seal: "rotated subkeys 2026"
```

### Provision second YubiKey (same subkeys)
```bash
gpgsmith vault restore <pre-card-snapshot>
gpgsmith vault open
gpgsmith card provision spare --same-keys
exit                             # seal: "provisioned spare YubiKey"
```

### Lost YubiKey — emergency revocation
```bash
gpgsmith vault open
gpgsmith card revoke green       # revoke all subkeys + publish + update inventory
exit                             # seal: "revoked lost green YubiKey"
```

### New workstation setup
You have gpgsmith installed, Dropbox synced, and a YubiKey:
```bash
gpgsmith vault config set vault_dir ~/Dropbox/Private/vault
gpgsmith vault open
gpgsmith keys ssh-pubkey         # export SSH pub key to ~/.ssh/
gpgsmith vault discard           # read-only, nothing to seal
```

### Scripted automation
```bash
eval $(gpgsmith vault open)
gpgsmith card rotate green
eval $(gpgsmith vault seal "automated rotation $(date +%Y-%m-%d)")
```

### Check inventory and audit
```bash
gpgsmith vault open
gpgsmith card inventory          # which cards, which keys
gpgsmith audit show --last 10    # recent operations
gpgsmith vault discard           # read-only session
```

## Architecture — Two Layers

### Layer 1: Vault (age + tar) — shared, reusable

Manages encrypted, append-only snapshots. No LUKS, no git, no sudo.

- Each snapshot is a self-contained `.tar.age` file (encrypted tarball)
- Append-only: new snapshot per operation, old ones never modified
- Decryption produces a tmpdir
- On Linux, prefer `/dev/shm` (RAM-backed) for tmpdir; fallback to `os.TempDir()` on macOS/other
- `filippo.io/age` for encryption — passphrase-based (`ScryptIdentity`) or key file
- Designed for reuse by future `pkismith`

### Layer 2: GPG + YubiKey — gpgsmith-specific

Operates on a GNUPGHOME directory. Doesn't know or care about encryption or storage.

- Shells out to `gpg` binary with `--homedir <tmpdir>`
- Stateless — takes a directory, performs operations, done

### Workflow

```
open    →  find latest .tar.age → decrypt → untar → tmpdir
              ↓
           GNUPGHOME = tmpdir (exported via eval or subshell)
              ↓
           perform GPG operations (generate/revoke/to-card/etc.)
              ↓
seal    →  tar tmpdir → encrypt → write new dated .tar.age → cleanup tmpdir
```

### Vault Directory Structure

```
~/Dropbox/Private/vault/
├── 2026-01-01T000000Z_initial-import.tar.age
├── 2026-03-15T103000Z_rotate-subkeys.tar.age
├── 2026-04-01T153000Z_new-yubikey-2.tar.age
└── ...
```

Filename format: `<ISO8601>_<slugified-message>.tar.age`

### GNUPGHOME Contents (inside each tarball)

```
GNUPGHOME/
├── pubring.kbx
├── trustdb.gpg
├── gpg.conf
├── private-keys-v1.d/
├── gpgsmith.yaml              # GPG config (master_fp, algo, expiry, publish targets)
├── gpgsmith-inventory.yaml    # YubiKey inventory
└── gpgsmith-audit.yaml        # audit log
```

## CLI Subcommand Tree

```
gpgsmith
├── setup                  # first-time wizard: vault create + keys create + card provision
├── vault
│   ├── create             # create new vault dir, set up age encryption
│   ├── import <path>      # import existing GNUPGHOME as first snapshot
│   ├── open               # decrypt latest → tmpdir (interactive or scripted)
│   ├── seal "msg"         # tar + encrypt → new snapshot, cleanup
│   ├── discard            # drop changes, cleanup without saving
│   ├── list               # list all snapshots
│   ├── restore <ref>      # decrypt specific snapshot
│   └── config
│       ├── show           # show vault config
│       └── set            # set vault config value
├── keys                   # low-level GPG key operations (requires GNUPGHOME set)
│   ├── create             # generate new master key + subkeys
│   ├── generate           # add new S/E/A subkeys
│   ├── to-card            # move subkeys to YubiKey (--same-keys / --unique-keys)
│   ├── list               # list keys/subkeys
│   ├── revoke <id>        # revoke specific subkey
│   ├── publish            # publish to configured targets (keyserver, GitHub)
│   ├── ssh-pubkey         # export auth subkey to ~/.ssh/gpgsmith-<keyid>.pub
│   ├── status             # key info + card info
│   └── config
│       ├── show           # show GPG config (inside GNUPGHOME)
│       └── set            # set GPG config value
├── card                   # high-level YubiKey workflows (requires GNUPGHOME set)
│   ├── provision <label>  # generate subkeys + to-card + publish + ssh-pubkey
│   ├── rotate <label>     # revoke old + generate new + to-card + publish + ssh
│   ├── revoke <label>     # revoke all subkeys for a card + publish revocation
│   ├── inventory          # list all known YubiKeys
│   └── discover           # detect connected YubiKey, add to inventory
├── audit
│   └── show               # display audit entries (--last N for recent)
└── version
```

`<label>` accepts card label (e.g., "green") or serial number.
`keys` commands are low-level building blocks. `card` commands are high-level workflows
that compose `keys` operations internally.
All `keys` and `card` commands require `GNUPGHOME` to be set (via `vault open`).

## Session Model — ssh-agent pattern, no session file

### Interactive mode (default when TTY detected)

`vault open` spawns `$SHELL` with `GNUPGHOME=<tmpdir>` set.
On shell exit, prompts to seal or discard.

```bash
$ gpgsmith vault open
Decrypting latest snapshot...
Entering gpgsmith shell. GNUPGHOME is set.
Run gpgsmith commands or raw gpg. Type 'exit' when done.

gpgsmith$ gpgsmith card rotate green
gpgsmith$ gpg --list-keys           # raw gpg works too
gpgsmith$ exit
Seal vault? [Y/n/message]: rotated subkeys
Sealed: 2026-04-01T153000Z_rotated-subkeys.tar.age
```

### Scripted mode (non-TTY, or `--no-interactive`)

Like `ssh-agent` — `vault open` outputs shell exports to stdout:

```bash
eval $(gpgsmith vault open)              # outputs: export GNUPGHOME=/dev/shm/gpgsmith-abc123;
gpgsmith card rotate green               # uses GNUPGHOME from env
eval $(gpgsmith vault seal "rotated")    # outputs: unset GNUPGHOME;
```

- `vault open` → stdout: `export GNUPGHOME=/dev/shm/gpgsmith-abc123;`
- All other commands → read `$GNUPGHOME` env var
- `vault seal` → reads `$GNUPGHOME`, encrypts, cleans up, stdout: `unset GNUPGHOME;`
- `vault discard` → reads `$GNUPGHOME`, removes tmpdir, stdout: `unset GNUPGHOME;`

No session file. The shell environment IS the session.

### TTY detection

`github.com/mattn/go-tty`
- TTY + no flag → interactive (subshell)
- TTY + `--no-interactive` → scripted (env var output)
- No TTY → scripted (env var output)
- No TTY + `--interactive` → error

## Configuration — Two Files, Two Concerns

### Vault config: `~/.config/locksmith/config.yaml`

Machine-local, always available. Needed before decryption.

```yaml
vault_dir: ~/Dropbox/Private/vault
identity: ~/.config/locksmith/age-key.txt   # optional, prompts passphrase if absent
gpg_binary: gpg
```

### GPG config: `GNUPGHOME/gpgsmith.yaml`

Lives inside the encrypted tarball, travels with the keys. Available after `open`.

```yaml
master_fp: 6E1FD854CD2D225DDAED8EB7822B3952F976544E
subkey_algo: rsa4096
subkey_expiry: 2y
publish_targets:
  - type: keyserver
    url: hkps://keys.openpgp.org
  - type: github
    # uses 'gh' CLI; skipped with warning if gh not installed/authenticated
```

Auto-discovered on first `open` from the keyring — user confirms.
Restoring an old snapshot brings its own config from that point in time.

### Resolution order (lowest to highest)

1. Hardcoded defaults
2. Config files (vault config + GPG config after open)
3. CLI flags (only for overrides and operational flags)

### CLI flags (minimal)

| Flag | Default | Description |
|------|---------|-------------|
| `--vault-dir` | from config | Override vault location |
| `--verbose` | `false` | Debug logging to stderr |
| `--dry-run` | `false` | Print commands without executing |

No env vars for config — config files handle persistence, flags handle overrides.
`GNUPGHOME` is the only env var, used as session state.

## Publishing — Multi-target

`keys publish` sends public key to all configured targets:

- **keyserver:** `gpg --keyserver <url> --send-keys <fp>`
- **github:** `gh gpg-key add <pubkey-file>` + `gh ssh-key add <ssh-pubkey-file>`

Behavior:
- If `gh` is not installed or not authenticated → skip GitHub, log warning with manual instructions
- `server publish openpgp` to publish to a specific target by alias
- On failure for any target, continue to next, report all results at the end

## SSH Public Key Export

`keys ssh-pubkey` exports the auth subkey as an SSH public key:

- Output: `~/.ssh/gpgsmith-<keyid>.pub`
- Always named by subkey ID (not card label)
- Comment inside the pub file includes card associations from inventory
- Same subkeys on multiple cards → one file (same key ID)
- Unique subkeys per card → one file per unique auth subkey
- On `keys revoke` of auth subkey → offer to remove the corresponding pub file

## YubiKey Inventory

Stored in `GNUPGHOME/gpgsmith-inventory.yaml`, travels with the keys.

```yaml
yubikeys:
  - serial: "12345678"
    label: "green"                    # short alias for CLI commands
    model: "YubiKey 5 NFC"           # auto-detected from card
    description: "on keychain"        # optional free-form
    provisioning: same-keys           # or "unique-keys"
    subkeys:
      - keyid: "0x886F425C412784FD"
        usage: sign
        created: 2025-12-31
        expires: 2027-12-31
      - keyid: "0x79584112B688AB89"
        usage: encrypt
        created: 2025-12-31
        expires: 2027-12-31
      - keyid: "0x571151F0CB6B35FF"
        usage: auth
        created: 2025-12-31
        expires: 2027-12-31
    provisioned_at: 2025-12-31T14:30:00Z
    status: active                    # active | revoked

  - serial: "87654321"
    label: "spare"
    model: "YubiKey 5C"
    description: "in safe deposit box"
    provisioning: same-keys
    subkeys: [...]
    provisioned_at: 2026-01-15T10:00:00Z
    status: active
```

Card label resolution: try serial first, then label match.

### Auto-update on operations

| Command | Inventory update | Audit entry |
|---------|-----------------|-------------|
| `keys generate` | — | yes |
| `keys to-card` | add/update YubiKey entry | yes |
| `keys revoke` | mark subkey revoked | yes |
| `card provision` | add YubiKey entry | yes (multiple) |
| `card rotate` | update YubiKey entry | yes (multiple) |
| `card revoke` | mark card revoked | yes |
| `card discover` | add/update YubiKey entry | yes |
| `keys publish` | — | yes |

### Card inventory display

```
$ gpgsmith card inventory
SERIAL      LABEL    MODEL            STATUS   SUBKEYS  DESCRIPTION
12345678    green    YubiKey 5 NFC    active   3/3      on keychain
87654321    spare    YubiKey 5C       active   3/3      in safe deposit box
```

### Discovery flow

```
$ gpgsmith card discover
Found YubiKey: serial 87654321, model YubiKey 5C
Card holds subkeys:
  - 0xAABB... (sign) — matches master key ✓
  - 0xCCDD... (encrypt) — matches master key ✓
  - 0xEEFF... (auth) — matches master key ✓
Not in inventory. Add? [Y/n]
Label: spare
Description (optional): in safe deposit box
Added to inventory.
```

### Lost YubiKey scenario

```
$ gpgsmith card revoke green
This will revoke 3 subkeys associated with "green" (12345678, YubiKey 5 NFC):
  - 0x886F... (sign)
  - 0x7958... (encrypt)
  - 0x5711... (auth)
Proceed? [y/N] y
Subkeys revoked. Inventory updated.
Publish revocation to all targets? [Y/n] y
Published to keyserver. GitHub: skipped (gh not authenticated).
```

## Audit Log

Stored in `GNUPGHOME/gpgsmith-audit.yaml`, append-only, travels with the keys.

```yaml
entries:
  - timestamp: 2025-12-31T14:00:00Z
    action: generate-subkeys
    details: "S/E/A rsa4096 expires 2027-12-31"
    subkeys: ["0x886F...", "0x7958...", "0x5711..."]

  - timestamp: 2025-12-31T14:30:00Z
    action: to-card
    mode: same-keys
    yubikey_serial: "12345678"
    subkeys: ["0x886F...", "0x7958...", "0x5711..."]

  - timestamp: 2026-04-01T15:00:00Z
    action: revoke-card
    yubikey_serial: "12345678"
    subkeys: ["0x886F..."]
    reason: "YubiKey lost"
```

## YubiKey Provisioning — Two Modes

`keys to-card` (and `card provision`) prompt the user to choose:

### Same-keys mode (`--same-keys`)
1. Auto-saves pre-card snapshot (preserves real private keys)
2. Runs `keytocard` for S/E/A → YubiKey
3. Updates inventory + audit
4. User seals (stubs-only snapshot)
5. To provision another card: restore pre-card snapshot, repeat

### Unique-keys mode (`--unique-keys`)
1. Generates fresh S/E/A subkeys
2. Runs `keytocard` — moves to YubiKey
3. Private keys are now only on the card (no backup)
4. Updates inventory + audit
5. Lost card → revoke + generate new

## Project Structure

```
locksmith/                           # monorepo
├── .claude/
│   └── CLAUDE.md
├── .github/
│   └── workflows/
│       ├── ci.yaml                  # lint + test on push/PR
│       └── release.yaml             # goreleaser on tag push
├── .envrc
├── .gitignore
├── .golangci.yaml
├── .goreleaser.yaml
├── Justfile
├── LICENSE                          # MIT
├── README.md
├── devbox.json                      # go, golangci-lint, just, goreleaser
├── go.mod
├── go.sum
├── cmd/
│   ├── gpgsmith/
│   │   └── main.go                  # ldflags vars, calls gpgsmith.Main()
│   └── pkismith/                   # future
│       └── main.go
├── pkg/
│   ├── vault/                       # shared: encrypted snapshot storage
│   │   ├── vault.go                 # Vault struct, Open/Seal/Discard/List/Restore
│   │   ├── vault_test.go
│   │   ├── config.go                # vault config (~/.config/locksmith/config.yaml)
│   │   ├── tmpdir_linux.go          # /dev/shm preference
│   │   └── tmpdir_other.go          # os.TempDir fallback
│   ├── audit/                       # shared: audit logging
│   │   ├── audit.go
│   │   └── audit_test.go
│   ├── gpgsmith/                   # gpgsmith CLI wiring
│   │   └── gpgsmith.go             # Main(): signal.NotifyContext, slog, cli app
│   ├── gpg/                         # gpgsmith-specific: GPG operations
│   │   ├── client.go                # Client struct, constructor
│   │   ├── config.go                # GPG config (GNUPGHOME/gpgsmith.yaml)
│   │   ├── keys.go                  # key listing, parsing --with-colons output
│   │   ├── subkeys.go               # generate, revoke subkeys
│   │   ├── card.go                  # keytocard operations (both modes)
│   │   ├── publish.go               # multi-target publishing (keyserver, GitHub)
│   │   ├── ssh.go                   # SSH public key export
│   │   ├── inventory.go             # YubiKey inventory
│   │   ├── keys_test.go
│   │   ├── subkeys_test.go
│   │   └── card_test.go             # mocked
│   └── pkismith/                   # future: PKI operations
└── testdata/                        # fixtures: sample gpg output, etc.
```

## Key Types & Interfaces

### `pkg/vault` (shared)

```go
type Vault struct {
    dir      string
    identity age.Identity
    logger   *slog.Logger
}

type Snapshot struct {
    Path      string
    Timestamp time.Time
    Message   string
}

func New(cfg VaultConfig) (*Vault, error)
func (v *Vault) Create() error
func (v *Vault) Import(sourcePath string) (Snapshot, error)
func (v *Vault) Open() (workdir string, snapshot Snapshot, err error)
func (v *Vault) Seal(workdir string, message string) (Snapshot, error)
func (v *Vault) Discard(workdir string) error
func (v *Vault) List() ([]Snapshot, error)
func (v *Vault) Restore(ref string) (workdir string, err error)
```

### `pkg/audit` (shared)

```go
type Entry struct {
    Timestamp time.Time
    Action    string
    Details   string
    Metadata  map[string]string
}

func Append(dir string, entry Entry) error
func Load(dir string) ([]Entry, error)
```

### `pkg/gpg`

```go
type Client struct {
    binary   string
    homeDir  string       // from GNUPGHOME env var
    masterFP string
    logger   *slog.Logger
}

type SubKey struct {
    KeyID       string
    Fingerprint string
    Algorithm   string
    Usage       string    // S, E, A, C
    Created     time.Time
    Expires     time.Time
    CardSerial  string
}

type YubiKeyEntry struct {
    Serial        string
    Label         string
    Model         string
    Description   string
    Provisioning  string    // "same-keys" | "unique-keys"
    Subkeys       []SubKeyRef
    ProvisionedAt time.Time
    Status        string    // "active" | "revoked"
}

type PublishTarget struct {
    Type string   // "keyserver" | "github"
    URL  string   // for keyserver
}

func New(opts Options) *Client
func (c *Client) ListKeys(ctx context.Context) ([]SubKey, error)
func (c *Client) GenerateSubkeys(ctx context.Context, opts SubkeyOpts) error
func (c *Client) MoveToCard(ctx context.Context, mode CardMode) error
func (c *Client) Revoke(ctx context.Context, keyID string) error
func (c *Client) Publish(ctx context.Context, targets []PublishTarget) []PublishResult
func (c *Client) ExportSSHPubKey(ctx context.Context) (path string, err error)
func (c *Client) CardStatus(ctx context.Context) (*CardInfo, error)
func (c *Client) DiscoverCard(ctx context.Context) (*YubiKeyEntry, error)

// Config
func (c *Client) LoadConfig() (*GPGConfig, error)
func (c *Client) SaveConfig(cfg *GPGConfig) error
func (c *Client) AutoDiscoverConfig(ctx context.Context) (*GPGConfig, error)

// Inventory
func (c *Client) LoadInventory() (*Inventory, error)
func (c *Client) SaveInventory(inv *Inventory) error
```

### `cmd/gpgsmith/main.go`

```go
var (
    Version   = "dev"
    Commit    = "none"
    Date      = "unknown"
    GoVersion = "unknown"
)

func main() {
    os.Exit(gpgsmith.Main(Version, Commit, Date, GoVersion))
}
```

## CI / CD

### `.github/workflows/ci.yaml` — on push/PR

1. Checkout
2. Set up Go
3. `golangci-lint run`
4. `go test ./...`

### `.github/workflows/release.yaml` — on tag push (v*)

1. Checkout
2. Set up Go
3. Run goreleaser — builds gpgsmith for linux/darwin × amd64/arm64, creates GitHub Release

## Security

- **Tmpdir on Linux:** `/dev/shm` (RAM-backed, never touches disk)
- **Tmpdir on macOS:** `os.TempDir()` (per-user `/var/folders/...`)
- **Permissions:** tmpdir created with 0700
- **Cleanup:** `os.RemoveAll` on seal/discard; signal handler for cleanup on interrupt
- **Passphrase:** prompted from terminal, held in memory only for session duration
- **Unique-keys mode:** private keys exist only on YubiKey, no backup

## Output Contract

- **stdout:** only machine-parseable output (env exports, key IDs, file paths, snapshot names)
- **stderr:** slog-based logging (info level default, debug with `--verbose`)
- **Exit codes:** 0 = success, 1 = general error, 2 = precondition failure

## Error Handling

- Check preconditions (GNUPGHOME set? YubiKey present? master key available?)
- Wrap errors with context: `fmt.Errorf("vault open: %w", err)`
- Exit 2 for user/precondition errors, exit 1 for system errors
- Signal handler (SIGINT, SIGTERM) cleans up tmpdir

## Testing Strategy

- **`pkg/vault`**: integration tests with temp dirs, real age encrypt/decrypt
- **`pkg/audit`**: unit tests with temp dirs
- **`pkg/gpg`**: integration tests with temp GNUPGHOME + real gpg. Card tests use mock.
- **`testdata/`**: sample `--with-colons` output, card-status output for parsing

## Justfile

```just
default:
    @just --list

build:
    go build -ldflags "-X main.Version=dev -X main.Commit=$(git rev-parse --short HEAD) -X main.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.GoVersion=$(go version | cut -d' ' -f3)" -o bin/gpgsmith ./cmd/gpgsmith

test:
    go test ./...

lint:
    golangci-lint run

fmt:
    gofmt -w .

check: lint test

release-snapshot:
    goreleaser release --snapshot --clean
```

## Implementation Order

1. Rename repo to `locksmith`, module to `github.com/excavador/locksmith`, restructure paths
2. Add LICENSE (MIT), CI workflows
3. `pkg/vault` — config, age encrypt/decrypt, tar pack/unpack, secure tmpdir, create/import/open/seal/discard/list/restore
4. `pkg/audit` — shared audit logging
5. `pkg/gpg` — config, auto-discovery, key listing/parsing
6. `pkg/gpg` — inventory (YubiKey tracking with label/model/description)
7. `pkg/gpg` — subkey generation
8. `pkg/gpg` — card operations (keytocard, both modes)
9. `pkg/gpg` — publish (multi-target: keyserver + GitHub), ssh export
10. `pkg/gpgsmith` — wire up all subcommands: setup, vault, keys, card, audit, version
11. Interactive mode (TTY detection, subshell) + scripted mode (ssh-agent pattern)
12. Integration tests

## Verification

1. `just check` — lint + tests pass
2. `just build` — binary builds with version info
3. CI green on push
4. Manual smoke test:
   - `gpgsmith vault create` → creates vault dir, sets up encryption
   - `gpgsmith vault import /path/to/gnupghome` → imports as first snapshot
   - `gpgsmith vault open` → decrypts, enters interactive shell
   - `gpgsmith card provision green` → generate + to-card + publish + ssh
   - `gpgsmith card inventory` → shows YubiKey inventory
   - `gpgsmith audit show` → shows operation history
   - exit → seal prompt → creates snapshot
   - `gpgsmith vault list` → shows all snapshots
   - Scripted: `eval $(gpgsmith vault open)` → sets GNUPGHOME
