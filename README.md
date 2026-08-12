# Cargo

Cargo is an open-source, local-first desktop vault for moving AI connection definitions and personal context between Claude, Cursor, Codex, and future clients without creating a hosted credential honeypot.

The current release is a **private preview**. It is usable for a local profile, encrypted connection and memory storage, safe/encrypted transfer, client discovery/import, previewed reversible deployments, and provider-neutral remote MCP authorization with a user-supplied public OAuth client ID. Named-provider compatibility is not universal, and Cargo never claims that removing a host registration revokes credentials held by another app.

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
- Provider-neutral remote MCP/OAuth flow: bounded HTTPS discovery, issuer/resource binding, PKCE S256, exact one-shot loopback callback, Keychain credential custody, and durable refresh-first revocation/retry states

## Explicit limits

- Import discards credential values. A destination must be authorized through its own secure flow.
- Claude remote connectors are managed by Claude's native Connectors UI, not its local JSON configuration.
- Codex and Claude Code registration uses their official `mcp` CLIs with user-visible arguments, a minimal environment, and post-command registration verification.
- Removing a host registration does not revoke an upstream provider token that another app copied.
- Remote authorization requires a standards-conforming MCP/OAuth server and a public client ID accepted by that server. Named providers remain preview capabilities until their individual conformance tests pass.
- Memory allowed-host policy is stored and portable; automatic runtime injection/enforcement is not enabled in this preview.
- A fully compromised operating system can access an unlocked local application. See [SECURITY.md](SECURITY.md).

## Desktop app

The [Apple Silicon private-preview DMG](https://github.com/johnzertuche/cargo-ai/releases/tag/v0.1.0-preview.5) includes SHA-256 checksums and CycloneDX SBOMs. It is ad-hoc signed but not Apple-notarized, so install from source is recommended until the production signing gate is complete.

Source prerequisites: macOS, Node.js 22+, and current stable Rust.

```bash
git clone https://github.com/johnzertuche/cargo-ai.git
cd cargo-ai/apps/desktop
npm install
npm run desktop:dev
```

Create an explicitly ad-hoc-signed local preview bundle:

```bash
npm run desktop:build:preview
```

The app calls account creation **Create local profile** because no vendor account is involved. The vault key is stored in macOS Keychain and the encrypted database remains in the normal per-user application-data directory.

## CLI

```bash
cargo run -p cargo-ai-cli -- init --name "Ada"
cargo run -p cargo-ai-cli -- status
cargo run -p cargo-ai-cli -- rename-profile --name "Ada Lovelace"
cargo run -p cargo-ai-cli -- discover
cargo run -p cargo-ai-cli -- import-host --host Cursor
cargo run -p cargo-ai-cli -- connections
# Argument-bearing installs require an interactive exact-value review; --yes cannot bypass it:
cargo run -p cargo-ai-cli -- install CONNECTION_UUID --host Cursor --show-values
cargo run -p cargo-ai-cli -- deployments
# Host registration removal does not log out OAuth or revoke provider-side access:
cargo run -p cargo-ai-cli -- remove-deployment DEPLOYMENT_UUID
printf 'Prefer concise updates' | cargo run -p cargo-ai-cli -- memory add --title "Working style"
cargo run -p cargo-ai-cli -- memory list
# Edit and delete use the UUIDs shown by the list commands:
printf 'Prefer short, decisive updates' | cargo run -p cargo-ai-cli -- memory edit MEMORY_UUID --title "Working style"
cargo run -p cargo-ai-cli -- memory delete MEMORY_UUID
cargo run -p cargo-ai-cli -- delete-connection CONNECTION_UUID
cargo run -p cargo-ai-cli -- export-safe cargo-ai-portable-pack.json
cargo run -p cargo-ai-cli -- export-encrypted cargo-ai-portable-pack.age
cargo run -p cargo-ai-cli -- import-encrypted cargo-ai-portable-pack.age
# Remote MCP OAuth (public-client flow; browser approval follows the terminal review):
cargo run -p cargo-ai-cli -- provider authorize CONNECTION_UUID --client-id YOUR_PUBLIC_CLIENT_ID
cargo run -p cargo-ai-cli -- provider list
cargo run -p cargo-ai-cli -- provider disconnect GRANT_UUID
```

## Repository layout

- `crates/core` — encrypted vault, transfer format, discovery, transaction/removal engine, and provider-neutral OAuth lifecycle
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

The test suite includes encrypted-at-rest checks, wrong-key and wrong-passphrase rejection, malicious URL/symlink rejection, argument and URL secret redaction, bounded transactional import, stale-plan rejection, unrelated-field preservation, drift-safe removal, PKCE/resource binding, one-shot OAuth state, a loopback fake-provider conformance flow, refresh rotation/replay handling, cross-process grant ownership, offline revocation persistence, and proof that revocation acceptance is not mislabeled as verification.

The repository also contains a fail-closed production macOS workflow. It accepts only a GitHub-verified signed `vMAJOR.MINOR.PATCH` tag, requires Developer ID and App Store Connect credentials, notarizes and staples, runs Gatekeeper/signature/disk-image checks, emits CycloneDX SBOMs and SHA-256 checksums, creates GitHub provenance attestations, and publishes only after all gates pass. See [docs/PRODUCTION_RELEASE.md](docs/PRODUCTION_RELEASE.md).

## Release policy

An unsigned local build is not a production release. A public credential-custody release additionally requires signed and notarized binaries, signed updates, SBOM/provenance, provider-specific connect/logout/revoke conformance tests, clean-device backup restore tests, and an independent security audit with remediation.

## License

Apache-2.0. See [LICENSE](LICENSE).
