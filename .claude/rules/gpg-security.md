---
paths:
  - "pkg/gpg/**"
  - "pkg/gpgsmith/**"
---

# GPG security rules

- Always use `exec.CommandContext` with separate args — never shell-concatenate
- Validate fingerprints (40 hex), key IDs (16 hex), serials (numeric) before GPG calls
- Use `--batch --no-tty` flags for non-interactive GPG operations
- Card PIN entry delegated to gpg-agent/pinentry — never handle PINs directly
- Truncate GPG stderr in error messages (may contain key grips)
- Shell-quote all values in scripted mode output (export VAR='escaped')
- Tmpdir must be 0700, prefer /dev/shm on Linux
