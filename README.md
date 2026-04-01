# locksmith

GPG key lifecycle manager with encrypted vault storage and YubiKey support.

Automates the routine of generating, rotating, provisioning, and revoking GPG
subkeys across multiple YubiKeys — with append-only encrypted snapshots for
history and recovery.

## Prerequisites

- [devbox](https://www.jetify.com/devbox/docs/installing_devbox/) — portable dev environment
- [direnv](https://direnv.net/docs/installation.html) — auto-load environment on `cd`

## Getting Started

```bash
cd locksmith
direnv allow
just build
```

## Usage

```bash
# Create a new vault
gpgsmith vault create

# Import existing GPG keys
gpgsmith vault import ~/.gnupg

# Open vault (interactive session)
gpgsmith vault open

# Inside the session:
gpgsmith keys generate
gpgsmith keys to-card
gpgsmith keys publish

# Exit saves automatically (or discard with gpgsmith vault close)
```

## Development

```bash
just check    # lint + test
just build    # build binary
just fmt      # format code
```
