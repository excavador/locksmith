# Open Bugs and Features

## Bugs (priority order)

### #63: vault import should create vault dir if it doesn't exist
After `vault config set vault_dir /path`, `vault import` fails if `/path` doesn't exist.
Should auto-create like `vault create` does.
File: pkg/gpgsmith/cmd_vault.go or pkg/vault/vault.go

### #64: keys generate fails — gpgsmith.yaml not saved after auto-discover
`keys config show` auto-discovers correctly but doesn't save gpgsmith.yaml.
Then `keys generate` fails with "not found". Should auto-save config on first use.
File: pkg/gpgsmith/cmd_keys.go, pkg/gpg/config.go

### #59: keys list doesn't show card label for some subkeys
The "red" YubiKey subkeys show empty CARD column because gpg doesn't have card
stubs for them (local private keys exist). Need to cross-reference with
card-status or inventory.
File: pkg/gpg/keys.go, pkg/gpgsmith/cmd_keys.go

### #60: card model too generic — "Yubico YubiKey" for all models
Should show specific model (YubiKey 5 NFC, YubiKey 5Ci, etc.).
Parser strips too much from gpg --card-status Reader line.
File: pkg/gpg/inventory.go

## Features

### #61: use ykman for YubiKey model detection
When ykman is available, use `ykman info` for exact model, firmware, form factor.
Fall back to gpg --card-status if not installed.
Recommend install if YubiKey detected but ykman missing.
Auto-update generic inventory entries when ykman becomes available.

### #62: card discover-all — batch discover all connected YubiKeys
Using `ykman list --serials`, discover all at once without swapping.

## Minor / Cosmetic

### #50: vault restore help text should mention "and start session"
### #51: FindByLabel used with serial — semantically confusing
### #32: audit.Append not concurrency-safe (documented, acceptable)
