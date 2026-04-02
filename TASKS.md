# Task History — locksmith/gpgsmith

## Completed

### Round 0 — Scaffolding
- [x] #1: Rename repo to locksmith, module to github.com/excavador/locksmith
- [x] #2: Set up GitHub Actions CI workflow
- [x] #3: Set up GitHub Actions release workflow
- [x] #4: Implement pkg/vault — encrypted snapshot storage
- [x] #5: Implement pkg/audit — shared audit logging
- [x] #6: Security review of pkg/vault and pkg/audit
- [x] #7: Implement pkg/gpg — client, config, key listing
- [x] #8: Implement pkg/gpg — inventory, subkeys, card, publish, ssh
- [x] #9: Validate workdir path in Vault.Seal/Discard before os.RemoveAll
- [x] #10: Wire up CLI subcommands in pkg/gpgsmith

### Round 1 — Bug fixes (from first testing)
- [x] #11: Add passphrase confirmation on first use
- [x] #12: vault create and import should open session after
- [x] #13: GPGSMITH_VAULT_KEY env var for scripted mode
- [x] #14: Filter lock files and temp files during import/tar
- [x] #15: Extract card model from card-status output
- [x] #16: Card discover should prompt for label and description
- [x] #17: Usage display shows cESCA instead of C for master key
- [x] #18: Security + QA review of round 1 fixes
- [x] #19: Security: shell-quote GPGSMITH_VAULT_KEY
- [x] #20: Fix usageLabel case-insensitive comparison

### Round 1.5 — UX bugs (from docs review)
- [x] #21: card discover doesn't save to inventory
- [x] #22: card provision doesn't populate Subkeys in inventory
- [x] #23: card rotate doesn't update inventory subkey refs
- [x] #24: keys to-card ignores --same-keys/--unique-keys flags
- [x] #25: vault restore should support interactive mode
- [x] #26: vault open seal prompt truncates multi-word messages
- [x] #27: Shell-quote GNUPGHOME in scripted output
- [x] #28: vault seal multi-word message (join all args)
- [x] #29: README: note setup and keys create as "(planned)"
- [x] #30: Review of round 1.5 fixes

### Round 2 — Bug fixes (from second testing)
- [x] #31: vault create must prompt passphrase before opening session
- [x] #32: Show (gpgsmith) prompt indicator in interactive subshell
- [x] #33: Review of round 2 fixes

### Round 3 — Bug fixes (from third testing)
- [x] #34: CARD column shows raw OpenPGP app ID instead of serial/label
- [x] #35: CARD column shows "+" for non-card keys
- [x] #36: vault import inside existing session creates nested subshell
- [x] #37: vault open and vault restore also need session guard
- [x] #38: Seal default message "manual-session" → "session-YYYY-MM-DD"
- [x] #39: Review of round 3 fixes

## Open — Bugs

### #59: keys list doesn't show card label for some subkeys
The "red" YubiKey subkeys show empty CARD column because gpg doesn't have card
stubs for them (local private keys exist). Need to cross-reference with
card-status output or inventory data.
**Files:** pkg/gpg/keys.go, pkg/gpgsmith/cmd_keys.go
**Priority:** medium

### #60: card model too generic — "Yubico YubiKey" for all models
Should show specific model (YubiKey 5 NFC, YubiKey 5Ci, YubiKey 5 Nano, etc.).
extractModelFromReader strips too much from gpg --card-status Reader line.
**File:** pkg/gpg/inventory.go
**Priority:** medium

### #63: vault import should create vault dir if it doesn't exist
After `vault config set vault_dir /path`, `vault import` fails if /path doesn't
exist. Should auto-create the directory like `vault create` does.
**File:** pkg/gpgsmith/cmd_vault.go or pkg/vault/vault.go
**Priority:** high (blocks first-time flow)

### #64: keys generate fails — gpgsmith.yaml not saved after auto-discover
`keys config show` auto-discovers master key correctly but doesn't save
gpgsmith.yaml to GNUPGHOME. Then `keys generate` fails with "not found".
Should auto-save config on first use or trigger auto-discover + save.
**File:** pkg/gpgsmith/cmd_keys.go, pkg/gpg/config.go
**Priority:** high (blocks key generation)

## Open — Features

### #61: use ykman for YubiKey model detection and info
When ykman (yubikey-manager CLI) is available, use `ykman info` for:
- Device type: exact model (YubiKey 5Ci, YubiKey 5 NFC, etc.)
- Firmware version, form factor
Requirements:
1. ykman is OPTIONAL — detect via exec.LookPath, fall back to gpg --card-status
2. If ykman not found, print recommendation to install
3. If ykman available and inventory has generic model, auto-update
4. README should mention ykman as optional dependency
**Priority:** medium

### #62: card discover-all — batch discover all connected YubiKeys
Using `ykman list --serials`, discover all connected YubiKeys at once.
Requires ykman. Falls back to single-card gpg --card-status.
**Priority:** low

## Open — Minor / Cosmetic

### #50: vault restore help text should mention "and start session"
### #51: FindByLabel used with serial is semantically confusing
### #32: audit.Append not concurrency-safe (documented, acceptable for single-user CLI)
