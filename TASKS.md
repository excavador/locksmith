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

### Round 4 — Bug fixes & enhancements
- [x] #59: keys list doesn't show card label for some subkeys
- [x] #60: card model too generic — ykman integration for specific model detection
- [x] #61: use ykman for YubiKey model detection and info
- [x] #63: vault import should create vault dir if it doesn't exist
- [x] #64: keys generate fails — gpgsmith.yaml not saved after auto-discover
- [x] #62: card discover-all — dropped (ykman/gpg only see one card at a time)
- [x] #66: keys list STATUS column — show active/expired/revoked per subkey
- [x] #67: keys revoke broken — was using --quick-revoke-sig (UID signatures), fixed to use --edit-key revkey
- [x] #68: MoveToCard used hardcoded indices {1,2,3} — rewritten to use key IDs and dynamic index resolution
- [x] #69: keys lookup — query configured + well-known keyservers for key publish status
- [x] #70: keys publish to GitHub now also uploads SSH public key via gh ssh-key add
- [x] #71: Auto-discover defaults now include keys.openpgp.org, keyserver.ubuntu.com, and github
- [x] #72: card discover updates model on re-discovery when ykman provides more specific info

## Open — Features

### #65: keys install-pubkey — export public key to system keyring
On a new workstation the card has the private key but `~/.gnupg` lacks the public
key, so gpg-agent can't use the card for SSH/signing. `keys install-pubkey` should
run `gpg --export <master_fp> | gpg --homedir ~/.gnupg --import` from inside a
vault session. Could also be offered automatically during `vault open` when a card
is detected but the system keyring is missing the public key.
**Files:** pkg/gpgsmith/cmd_keys.go, pkg/gpg/client.go
**Priority:** medium

### #73: setup — first-time wizard
`gpgsmith setup` should walk through: vault create + keys create + card provision.
Currently stubbed with `notImplemented`.
**Files:** pkg/gpgsmith/cmd_setup.go
**Priority:** medium

### #74: keys create — generate new master key + subkeys
Generate a new master key (Certify-only) and S/E/A subkeys from scratch.
Currently stubbed with `notImplemented`.
**Files:** pkg/gpgsmith/cmd_keys.go, pkg/gpg/subkeys.go
**Priority:** medium

## Open — Minor / Cosmetic

### #50: vault restore help text should mention "and start session"
### #51: FindByLabel used with serial is semantically confusing
### #32: audit.Append not concurrency-safe (documented, acceptable for single-user CLI)
