# locksmith Test Plan

## 1. Unit Test Matrix

### pkg/vault

| Function/Area | Status | Notes |
|---|---|---|
| `slugify` | Covered | Various inputs including empty, special chars |
| `formatSnapshotFilename` | Covered | Round-trip with `parseSnapshotFilename` |
| `parseSnapshotFilename` | Covered | Valid + invalid filenames |
| `expandHome` | Covered | `~`, absolute, relative, empty |
| `SecureTmpDir` | Covered | Permissions check (0700) |
| `validateWorkdir` | Covered | Valid locksmith dirs, rejects unsafe paths |
| `Config SaveConfig/LoadConfig` | Covered | Round-trip with all fields |
| `New` / `NewWithPassphrase` | Covered | Rejects empty vault dir |
| `Create` | Covered | Creates vault dir |
| `Import` | Covered | Directory with nested files; rejects non-directory |
| `Open` | Covered | Decrypts latest snapshot; fails with no snapshots |
| `Seal` | Covered | Creates new snapshot, cleans workdir; rejects invalid workdir |
| `Discard` | Covered | Removes workdir; rejects invalid workdir |
| `List` | Covered | Empty vault, after import, after seal |
| `Restore` | Covered | By filename; fails for nonexistent |
| Identity file mode | Covered | X25519 key file encrypt/decrypt round-trip |
| Wrong passphrase rejection | Covered | `TestVaultWrongPassphrase` |
| Import -> Open -> Seal -> List cycle | Partially | Covered in `TestVaultImportOpenSealDiscard` but could test more edge cases |
| `tarDir` / `untarToDir` path traversal | Implicit | Covered by import/open tests but no explicit traversal attack test |
| `LoadConfig` with default path | Not tested | Would require mocking `os.UserConfigDir` |

### pkg/audit

| Function/Area | Status | Notes |
|---|---|---|
| `Append` + `Load` round-trip | Covered | Single and multiple entries |
| `Load` empty directory | Covered | Returns empty slice |
| `Append` auto-timestamp | Covered | Zero timestamp gets auto-set |
| `Append` no metadata | Covered | Nil metadata preserved |
| Audit file YAML format | Covered | Checks `entries:` prefix |
| Sequential append safety | Covered | 20 sequential appends, verifies ordering |
| Corrupted YAML file | Covered | `TestLoadCorruptedYAML` |
| **Concurrent append safety** | Known issue | #32: Append is not concurrency-safe by design (single-user CLI) |

### pkg/gpg

| Function/Area | Status | Notes |
|---|---|---|
| `parseColonsOutput` (standard) | Covered | pub/sub with fingerprints |
| `parseColonsOutput` (empty) | Covered | Returns empty slice |
| `parseColonsOutput` (sec/ssb) | Covered | Secret key records |
| `parseColonsOutput` expired keys | Covered | Validity field = "e" (expired) |
| `parseColonsOutput` revoked keys | Covered | Validity field = "r" (revoked) |
| `parseColonsOutput` multiple UIDs | Covered | uid records interleaved |
| `parseColonsOutput` keys on card | Covered | Field 14 (card serial) populated |
| `parseColonsOutput` short fields | Covered | Lines with fewer than expected fields skipped |
| `parseCardStatus` | Covered | Valid card status |
| `parseCardStatus` (no card) | Covered | Empty input |
| `parseCardStatus` reader fallback | Covered | Card without cardtype, model from Reader field |
| `extractModelFromReader` | Covered | Various YubiKey reader strings |
| `algoName` | Covered | Known + unknown algorithms |
| `parseEpoch` | Covered | Valid + invalid epoch strings |
| `New` client | Covered | Requires HomeDir, defaults |
| `ValidateFingerprint` | Covered | Valid 40-hex, invalid inputs |
| `ValidateKeyID` | Covered | Valid 16-hex, invalid inputs |
| `ValidateSerial` | Covered | Valid numeric, invalid inputs |
| `truncate` | Covered | Short, long, whitespace inputs |
| `slotForIndex` | Covered | Indices 1-3 + out-of-range |
| `UsageLabel` | Covered | s/e/a lowercase + S/E/A uppercase + passthrough |
| `parseUsage` | Covered | Master (pub/sec) vs subkey caps extraction |
| Config `LoadConfig` / `SaveConfig` | Covered | Round-trip with publish targets |
| Config `LoadConfig` not found | Covered | Error on missing config |
| Inventory `LoadInventory` / `SaveInventory` | Covered | Round-trip with subkeys |
| `LoadInventory` empty dir | Covered | Returns empty inventory |
| `FindByLabel` | Covered | Match by serial, by label, serial priority, no match |

### pkg/gpgsmith

| Function/Area | Status | Notes |
|---|---|---|
| `confirmPassphrases` | Covered | Match, mismatch, read errors |
| `vaultCmd` flags | Covered | Checks --no-interactive on create/import/open/restore |
| `vaultOpen` arg rejection | Covered | Verifies open has no ArgsUsage; restore has ArgsUsage |
| `cardCmd` subcommands | Covered | All expected subcommands exist |
| `cardCmd` discover | Covered | Subcommand exists with action |
| `newSessionRC` (bash) | Covered | Creates temp rcfile with prompt + .bashrc source |
| `newSessionRC` (zsh) | Covered | Creates ZDOTDIR with .zshrc prompt override |
| `newSessionRC` (unknown) | Covered | Returns no-op for unknown shells |
| `newSessionRC` cleanup | Covered | Temp files removed after cleanup |
| `promptLineFrom` | Covered | Normal input, whitespace trim, empty, EOF |
| `shellEscapeSingleQuote` | Covered | No quotes, single quotes, multiple quotes, empty |
| `GPGSMITH_VAULT_KEY` env var | Covered | Set and unset |

## 2. Integration Test Scenarios

These require `gpg` installed and create real temp GNUPGHOME directories.

| Scenario | Status | Notes |
|---|---|---|
| Vault create -> import -> open -> seal -> list -> restore | Covered | `TestVaultImportOpenSealDiscard` |
| Wrong passphrase on open | Covered | `TestVaultWrongPassphrase` |
| Multiple seal cycles | **Missing** | Import, seal, open, modify, seal again, verify both snapshots |
| Restore specific snapshot | Covered | By filename prefix |
| Identity file round-trip | Covered | `TestVaultWithIdentityFile` |

## 3. End-to-End Scenarios (from use cases)

These map to the design plan use cases but test the full CLI flow.
Currently none are implemented -- they would require building the binary and running it.

| Use Case | Feasibility | Notes |
|---|---|---|
| First time setup (existing keys) | Medium | Requires gpg keyring setup in test |
| Routine subkey rotation | Hard | Requires YubiKey or mock |
| New workstation setup | Medium | vault open + ssh-pubkey + discard |
| Scripted automation | Medium | eval $(vault open) pattern |

## 4. Edge Cases

| Case | Package | Status |
|---|---|---|
| Empty vault (no snapshots) | vault | Covered (`TestVaultOpenNoSnapshots`) |
| Wrong passphrase | vault | Covered (`TestVaultWrongPassphrase`) |
| Corrupted .tar.age file | vault | **Missing** |
| Snapshot filename with no message part | vault | Covered (rejected by regex) |
| Very long snapshot message | vault | Not tested (slugify handles it) |
| Non-existent vault directory | vault | Not tested |
| Corrupted audit YAML | audit | Covered (`TestLoadCorruptedYAML`) |
| Sequential audit appends | audit | Covered (`TestSequentialAppendPreservesAll`) |
| GPG output with no keys | gpg | Covered (empty parse) |
| GPG output with expired/revoked keys | gpg | Covered |
| Card status with no card | gpg | Covered |
| Card status reader fallback | gpg | Covered |
| Inventory with no file | gpg | Covered (LoadInventory returns empty) |
| FindByLabel serial vs label priority | gpg | Covered |
| Invalid fingerprint/keyID/serial formats | gpg | Covered |
| Shell quoting of passphrases | gpgsmith | Covered (`TestShellEscapeSingleQuote`) |
| Session RC file creation + cleanup | gpgsmith | Covered (bash, zsh, unknown shells) |
| vault open rejects positional args | gpgsmith | Covered (ArgsUsage check) |
| Card discover duplicate detection | gpg + gpgsmith | Covered (FindByLabel serial priority) |

## 5. Mocking Requirements

| Area | Approach |
|---|---|
| YubiKey/card operations (`MoveToCard`, `keytocardSingle`) | Must mock -- requires physical hardware |
| `GenerateSubkeys` | Can integration test with real gpg (creates real keys in temp GNUPGHOME) |
| `Revoke` | Can integration test with real gpg |
| `Publish` (keyserver) | Must mock -- requires network |
| `Publish` (GitHub) | Must mock -- requires gh CLI + auth |
| `ExportSSHPubKey` | Can integration test with real gpg |
| `CardStatus` / `DiscoverCard` | Must mock -- requires physical hardware |
| `AutoDiscoverConfig` | Can integration test with real gpg |

## 6. Test Fixtures

### Existing (testdata/)
- `list-keys-colons.txt` -- standard pub/sub output with 1 master + 3 subkeys
- `card-status-colons.txt` -- YubiKey 5 NFC card status
- `list-keys-expired.txt` -- output with expired subkeys (validity "e")
- `list-keys-revoked.txt` -- output with revoked keys (validity "r")
- `list-keys-multiuid.txt` -- output with multiple UIDs
- `list-keys-oncard.txt` -- output with card serial in field 14
