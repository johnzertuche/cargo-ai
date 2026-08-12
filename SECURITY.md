# Security policy and threat model

Cargo is a private preview. Please do not use it as the sole custodian of irreplaceable production credentials. Connection imports discard known credential fields; arbitrary configuration can still be sensitive and requires review.

## Reporting

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting for this repository. Include affected version/commit, platform, reproduction steps, impact, and any suggested mitigation. Do not include real secrets or personal memory records.

## Security claims

- Local profile, connection, memory, deployment, and receipt records are encrypted at rest with authenticated per-record encryption.
- The vault key is stored through the platform credential store, not in SQLite or portable packs.
- Imported JSON/TOML definitions remove known credential fields and are treated as potentially sensitive untrusted configuration.
- The privileged desktop backend does not load remote web content and the renderer has no generic shell/filesystem capability.
- JSON host writes require an exact executable preview, reject stale plans, atomically replace after a second fingerprint check, preserve unrelated fields, and verify the owned fragment without retaining plaintext host-file backups.
- Removal refuses a changed owned fragment rather than silently erasing user edits.
- Portable packs contain only explicitly selected personal data. Known credential fields are removed, but scanners cannot prove arbitrary configuration is secret-free; every value must be reviewed. Optional passphrase protection uses the published `age` format; it is not full-vault recovery.
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
- Cargo does not claim resistance to a malicious process already running as the same OS user. Trusted host CLI execution reduces risk with canonical release roots, strict macOS signature and Team ID checks, a fixed environment, and executable fingerprints, but an active same-user process may still race local files during an approved operation.
- Host registration removal cannot invalidate a provider credential copied outside Cargo.
- An encrypted portable pack cannot be recovered if its passphrase is lost.
- The current preview does not transfer live OAuth refresh tokens and does not claim provider-side revocation.
- Provider-grant and revocation records now have encrypted schemas and tested state transitions, but no live provider transport is enabled in the released UI. This is security infrastructure, not a claim of provider compatibility.
- The current receipt chain detects record modification and ordering breaks when read; a privileged attacker able to replace the entire database and keychain state is outside its protection.

## Required future credential flow

Any provider OAuth adapter must use the system browser, Authorization Code with PKCE S256, exact redirect URIs, one-time state/nonce validation, least privilege and audience restriction, and refresh rotation or sender constraint where available. No token may be returned to the renderer, AI host, logs, configuration export, or command line.

Disconnect must report these outcomes separately:

1. New local grants blocked and active sessions/processes stopped
2. Owned host configuration removed and verified
3. Host-local OAuth credentials logged out and verified
4. Provider revocation requested
5. Provider rejection verified where the provider supports evidence
6. Local credential references deleted and cleanup verified

Offline/provider failures remain locally blocked and pending. The UI must not say fully revoked without mandatory evidence.

Deletion is currently logical, not a claim of physical or cryptographic erasure. SQLite/WAL pages, filesystem snapshots, and platform credential-store internals may retain encrypted historical bytes. Cargo must not claim cryptographic erasure unless a future per-record key design deletes the only wrapped data-encryption key and verifies the crash-consistent transition.

## Release security

Production release requires signed/notarized binaries, signed updates, pinned lockfiles, dependency/secret/license scanning, SBOM and provenance, malicious-import and crash-consistency testing, clean-device portable-content restore testing, real adapter conformance tests, and an independent audit with remediation.

The production macOS workflow is deliberately fail-closed: missing Apple credentials, an unsigned/lightweight/mismatched tag, ad-hoc signing, failed notarization/stapling, Gatekeeper rejection, or a failed test/audit prevents publication. The existing preview artifacts remain explicitly ad-hoc signed and are not promoted by that workflow.
