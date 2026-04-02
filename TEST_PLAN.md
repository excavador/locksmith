# Test Plan — locksmith/gpgsmith

## QA Round 1

| ID  | Area     | Test                                              | File                        | Status |
|-----|----------|---------------------------------------------------|-----------------------------|--------|
| T01 | vault    | Slugify produces correct slug                     | pkg/vault/vault_test.go     | PASS   |
| T02 | vault    | Format and parse snapshot filename                 | pkg/vault/vault_test.go     | PASS   |
| T03 | vault    | Parse invalid snapshot filenames                   | pkg/vault/vault_test.go     | PASS   |
| T04 | vault    | Config save/load round-trip                        | pkg/vault/vault_test.go     | PASS   |
| T05 | vault    | Create and List (empty vault)                      | pkg/vault/vault_test.go     | PASS   |
| T06 | vault    | Import, Open, Seal, Discard lifecycle              | pkg/vault/vault_test.go     | PASS   |
| T07 | vault    | Open with no snapshots fails                       | pkg/vault/vault_test.go     | PASS   |
| T08 | vault    | Restore nonexistent snapshot fails                 | pkg/vault/vault_test.go     | PASS   |
| T09 | vault    | New requires vault dir                             | pkg/vault/vault_test.go     | PASS   |
| T10 | vault    | Import non-directory fails                         | pkg/vault/vault_test.go     | PASS   |
| T11 | vault    | expandHome works correctly                         | pkg/vault/vault_test.go     | PASS   |
| T12 | vault    | SecureTmpDir creates 0700 dir                      | pkg/vault/vault_test.go     | PASS   |
| T13 | vault    | Vault with identity file round-trip                | pkg/vault/vault_test.go     | PASS   |
| T14 | vault    | validateWorkdir rejects dangerous paths            | pkg/vault/vault_test.go     | PASS   |
| T15 | vault    | shouldSkipFile filters runtime files               | pkg/vault/vault_test.go     | PASS   |
| T16 | vault    | tarDir skips runtime files                         | pkg/vault/vault_test.go     | PASS   |
| T17 | vault    | Seal rejects invalid workdir                       | pkg/vault/vault_test.go     | PASS   |
| T18 | vault    | Wrong passphrase rejected                          | pkg/vault/vault_test.go     | PASS   |
| T19 | vault    | Multiple seal cycles preserve history              | pkg/vault/vault_test.go     | PASS   |
| T20 | vault    | Discard rejects invalid workdir                    | pkg/vault/vault_test.go     | PASS   |
| T21 | cmd      | Confirm passphrases (match/mismatch/error)         | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T22 | cmd      | GPGSMITH_VAULT_KEY from env                        | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T23 | cmd      | Vault subcommands have --no-interactive flag        | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T24 | cmd      | vault open rejects positional args                 | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T25 | cmd      | vault restore has ArgsUsage                        | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T26 | cmd      | Session guard on all vault entrypoints             | pkg/gpgsmith/cmd_vault_test.go | PASS |
| T27 | cmd      | shellEscapeSingleQuote                             | pkg/gpgsmith/cmd_vault_test.go | PASS |

## QA Round 2 — Bug fixes

| ID  | Bug  | Area     | Test                                              | File                        | Status |
|-----|------|----------|---------------------------------------------------|-----------------------------|--------|
| T28 | #63  | vault    | Import creates vault dir if it doesn't exist       | pkg/vault/vault_test.go     | PASS   |
| T29 | #64  | cmd/keys | loadGPGConfig auto-discovers and saves config      | (manual / integration only) | TODO   |

### T28 — Bug #63: vault import creates vault dir

**What:** `Vault.Import()` should call `os.MkdirAll(v.dir, 0o700)` so that
importing into a non-existent vault directory works without a prior `vault create`.

**Test:** `TestVaultImportCreatesVaultDir` in `pkg/vault/vault_test.go`
- Creates a temp source dir with a dummy file
- Points Vault at a non-existent subdirectory within a temp dir
- Calls Import() and asserts success
- Verifies the vault dir was created with 0700 permissions
- Round-trips through Open() to confirm the snapshot is valid

### T29 — Bug #64: loadGPGConfig auto-discover fallback

**What:** `loadGPGConfig` should fall back to `AutoDiscoverConfig` + `SaveConfig`
when the config file doesn't exist, so that `keys generate` works on first use.

**Why not unit-tested:** `loadGPGConfig` is a private function in `pkg/gpgsmith`
that requires a `*gpg.Client` with a real GPG binary and GNUPGHOME. There is no
existing test pattern for cmd_keys (no `cmd_keys_test.go`). Testing would require
either:
1. An integration test with a real GPG setup (preferred, but out of scope for unit QA)
2. Refactoring to accept an interface (would change production code)

**Manual verification steps:**
1. Start fresh: `vault create`, `vault open`
2. In the session, delete `gpgsmith.yaml` from GNUPGHOME if it exists
3. Run `keys config show` — should auto-discover and save gpgsmith.yaml
4. Run `keys generate` — should succeed using the saved config
