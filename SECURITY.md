# Security policy and threat model

Cargo is a private preview. Please do not use it as the sole custodian of irreplaceable production credentials. Connection imports intentionally discard credential values.

## Reporting

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting for this repository. Include affected version/commit, platform, reproduction steps, impact, and any suggested mitigation. Do not include real secrets or personal memory records.

## Security claims

- Local profile, connection, memory, deployment, and receipt records are encrypted at rest with authenticated per-record encryption.
- The vault key is stored through the platform credential store, not in SQLite or portable packs.
- Imported JSON/TOML definitions do not retain credential values.
- The privileged desktop backend does not load remote web content and the renderer has no generic shell/filesystem capability.
- JSON host writes require an exact executable preview, reject stale plans, atomically replace after a second fingerprint check, preserve unrelated fields, and verify the owned fragment without retaining plaintext host-file backups.
- Removal refuses a changed owned fragment rather than silently erasing user edits.
- Portable packs contain explicitly selected personal data but no imported credential values. Optional passphrase protection uses the published `age` format; it is not full-vault recovery.
- Receipts are hash-chained. The current check detects modification and ordering breaks in the records present, but cannot independently prove the newest tail was not deleted.

## Threats considered

- A malicious AI host requesting excess scope, replaying a grant, or modifying shared configuration
- A compromised renderer/XSS attempting arbitrary filesystem, shell, or secret access
- Malicious MCP definitions, executables, packages, servers, adapters, updates, or dependencies
- Crafted import files, oversized inputs, ambiguous transports, path traversal, symlink and TOCTOU attacks
- A stolen database, backup, laptop, or unlocked session
- OAuth callback interception, token replay, refresh-token reuse, provider outage, and partial revocation
- Audit truncation/rollback, clock rollback, crash inconsistency, and configuration drift
- Operator/cloud compromise of any future optional sync service
- Secrets leaked into exports, logs, command arguments, crash dumps, clipboard, shell history, or backups

## Non-goals and honest limits

- Cargo cannot protect plaintext from malware or an administrator controlling the OS while the vault/app is unlocked.
- Host registration removal cannot invalidate a provider credential copied outside Cargo.
- An encrypted portable pack cannot be recovered if its passphrase is lost.
- The current preview does not transfer live OAuth refresh tokens and does not claim provider-side revocation.
- The current receipt chain detects record modification and ordering breaks when read; a privileged attacker able to replace the entire database and keychain state is outside its protection.

## Required future credential flow

Any provider OAuth adapter must use the system browser, Authorization Code with PKCE S256, exact redirect URIs, one-time state/nonce validation, least privilege and audience restriction, and refresh rotation or sender constraint where available. No token may be returned to the renderer, AI host, logs, configuration export, or command line.

Disconnect must report these outcomes separately:

1. New local grants blocked and active sessions/processes stopped
2. Owned host configuration removed and verified
3. Host-local OAuth credentials logged out and verified
4. Provider revocation requested
5. Provider rejection verified where the provider supports evidence
6. Local encrypted material cryptographically erased

Offline/provider failures remain locally blocked and pending. The UI must not say fully revoked without mandatory evidence.

## Release security

Production release requires signed/notarized binaries, signed updates, pinned lockfiles, dependency/secret/license scanning, SBOM and provenance, malicious-import and crash-consistency testing, clean-device restore testing, real adapter conformance tests, and an independent audit with remediation.
