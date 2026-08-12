# Cargo

Cargo is an open-source, local-first desktop vault for moving AI connection definitions and personal context between Claude, Cursor, Codex, and future clients without creating a hosted credential honeypot.

The current release is a **private preview**. It is usable for a local profile, encrypted connection and memory storage, safe/encrypted transfer, read-only client discovery, Claude Desktop/Cursor JSON imports, and previewed reversible JSON deployments. It is not yet audited for custody of live provider credentials and does not claim provider-wide OAuth revocation.

## What works now

- Accountless local profile protected by the operating-system keychain
- SQLite vault with per-record XChaCha20-Poly1305 authenticated encryption
- Discovery and credential-free import from documented Claude Desktop, Cursor, and Codex configuration locations
- Typed local memory with sensitivity and allowed-host metadata
- Credential-free JSON portable packs with explicit per-record export selection
- Passphrase-encrypted `age` portable packs with previewed, transactional, idempotent merge
- Two-phase install flow for Claude Desktop/Cursor JSON and the official Codex/Claude Code CLIs: exact executable preview, explicit approval, verification, receipt
- Drift-safe removal of only the JSON fragment Cargo installed
- Hash-chained local receipts with an explicit tail-truncation limitation
- Shared Rust core used by the desktop app and CLI
- Strict Tauri CSP and a small explicit command surface

## Explicit limits

- Import discards credential values. A destination must be authorized through its own secure flow.
- Claude remote connectors are managed by Claude's native Connectors UI, not its local JSON configuration.
- Codex and Claude Code registration uses their official `mcp` CLIs with user-visible arguments, a minimal environment, and post-command registration verification.
- Removing a host registration does not revoke an upstream provider token that another app copied.
- Memory allowed-host policy is stored and portable; automatic runtime injection/enforcement is not enabled in this preview.
- A fully compromised operating system can access an unlocked local application. See [SECURITY.md](SECURITY.md).

## Desktop app

The [Apple Silicon private-preview DMG](https://github.com/johnzertuche/cargo-ai/releases/tag/v0.1.0-preview.1) includes SHA-256 checksums and CycloneDX SBOMs. It is ad-hoc signed but not Apple-notarized, so install from source is recommended until the production signing gate is complete.

Source prerequisites: macOS, Node.js 22+, and current stable Rust.

```bash
git clone https://github.com/johnzertuche/cargo-ai.git
cd cargo-ai/apps/desktop
npm install
npm run desktop:dev
```

Create an unsigned local application bundle:

```bash
npm run desktop:build
```

The app calls account creation **Create local profile** because no vendor account is involved. The vault key is stored in macOS Keychain and the encrypted database remains in the normal per-user application-data directory.

## CLI

```bash
cargo run -p cargo-ai-cli -- init --name "Ada"
cargo run -p cargo-ai-cli -- status
cargo run -p cargo-ai-cli -- discover
cargo run -p cargo-ai-cli -- connections
printf 'Prefer concise updates' | cargo run -p cargo-ai-cli -- memory add --title "Working style"
cargo run -p cargo-ai-cli -- export-safe cargo-ai-portable-pack.json
cargo run -p cargo-ai-cli -- export-encrypted cargo-ai-portable-pack.age
cargo run -p cargo-ai-cli -- import-encrypted cargo-ai-portable-pack.age
```

## Repository layout

- `crates/core` — encrypted vault, transfer format, discovery, transaction and removal engine
- `apps/desktop` — Tauri 2 desktop app
- `apps/cli` — command-line interface using the same core
- `app` — public website; it never reads the local vault
- `ARCHITECTURE.md` — trust boundaries, formats, adapter contract, and release gates
- `SECURITY.md` — threat model, reporting, claims, and non-goals

## Verification

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cd apps/desktop && npm run build
cd ../.. && npm test
```

The test suite includes encrypted-at-rest checks, wrong-key and wrong-passphrase rejection, malicious URL/symlink rejection, argument and URL secret redaction, bounded transactional import, stale-plan rejection, unrelated-field preservation, and drift-safe removal.

## Release policy

An unsigned local build is not a production release. A public credential-custody release additionally requires signed and notarized binaries, signed updates, SBOM/provenance, provider-specific connect/logout/revoke conformance tests, clean-device backup restore tests, and an independent security audit with remediation.

## License

Apache-2.0. See [LICENSE](LICENSE).
