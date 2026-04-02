---
paths:
  - "**/*.go"
---

# Go conventions for locksmith

- Use `log/slog` with context: `logger.InfoContext(ctx, "msg", slog.String("key", "val"))`
- Never use global slog functions — pass logger via context or struct field
- Group type/var/const declarations (golangci-lint grouper enforced)
- Wrap errors with context: `fmt.Errorf("operation: %w", err)`
- Validate all external inputs (fingerprints, key IDs, serials) before passing to gpg
- No key material (private keys, passphrases) in log messages or error strings
- Use `context.Context` as first parameter in public functions
