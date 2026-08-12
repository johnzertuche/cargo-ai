# Architecture

## Product boundary

Cargo v1 is local software, not a hosted control plane. The signed Tauri interface, shared Rust core, vault, adapter execution, memory, receipts, and transfer operations run on the user's device. The website serves documentation and downloads only.

An optional future sync service may store opaque ciphertext and signed update metadata. It must never receive vault keys, plaintext memory, provider tokens, or a credential that can decrypt a backup.

## Trust model

1. **Operating system:** macOS Keychain protects the local vault key. Cargo does not claim protection from a fully compromised OS while the vault is unlocked.
2. **Rust core:** owns cryptography, schemas, validation, import limits, configuration mutation, receipts, and transfer.
3. **Tauri command boundary:** exposes narrowly typed operations. The renderer has no generic shell or filesystem permission.
4. **AI host configuration:** untrusted shared state. Every mutation is fingerprinted, atomically replaced, verified, and scoped to a Cargo-owned fragment. Cargo does not retain plaintext copies of the host file.
5. **Imported files and MCP definitions:** untrusted input. Size, schema, URL, symlink, and transport invariants are checked before persistence or execution.
6. **MCP processes/providers:** independent security principals. Definitions do not imply trust, and credential authorization is separate from installation.

## Vault

- A random 256-bit vault master key is created once and stored in the OS credential store.
- Profile, connection, memory, deployment, and receipt documents are encrypted independently with XChaCha20-Poly1305.
- Every record uses a unique 192-bit nonce and authenticated data containing the table, record identifier, and envelope version.
- SQLite WAL is enabled. Plaintext document fields from the earlier prototype schema are migrated to encrypted envelopes on open.
- Secret values are never included in `ConnectionDefinition`; imports retain only required environment/header key names.

## Transfer formats

### Portable JSON pack

Canonical JSON carrying a profile, connection definitions, and memory. It contains no vault key or imported credential value. It is still personal data and should be reviewed before sharing.

### Encrypted portable pack

The same validated portable manifest inside the published `age` passphrase format. Input and plaintext are capped at 32 MiB. Unknown format/version values and wrong passphrases fail closed. Imports show an exact local preview, preserve the destination profile, and transactionally skip duplicate records. This is not full-vault recovery: credentials, deployments, receipts, and the OS-wrapped vault key are excluded.

## Adapter contract

Every host adapter must implement these conceptual phases:

1. `detect` — report installation, documented surfaces, and path references without reading secrets.
2. `inspect` — normalize definitions, fingerprint source state, and redact secret values.
3. `plan` — produce a deterministic target and outcome fingerprint without writing.
4. `apply` — require the plan identifier and explicit approval, reject stale state, atomically write or call the official host CLI, then verify and automatically restore the in-memory preimage on verification failure.
5. `verify` — confirm registration and, where safe, MCP initialization/tool discovery without logging secrets.
6. `revoke` — synchronously block local use, remove only owned host state, separately perform host OAuth logout, then provider revocation where supported.
7. `rollback` — restore only owned fields when fingerprints permit; otherwise stop for a merge.

JSON mutation supports Claude Desktop local `mcpServers` and Cursor `mcpServers`. Codex and Claude Code registration/removal use their official `mcp` CLI surfaces because registration removal and OAuth logout are distinct operations. Cargo invokes those executables directly without a shell, displays every argument for approval, and verifies registration presence or absence afterward.

## Configuration transaction

1. Reject missing parents, symlinked directories/files, oversized files, invalid JSON, ambiguous transports, insecure remote URLs, and missing credential references.
2. Refuse to overwrite an existing same-name entry.
3. Save an in-memory plan containing zeroizing preimage/postimage buffers and fingerprints.
4. At apply time, re-read and compare the full-file fingerprint.
5. Write a private sibling temporary file, preserve safe existing permissions, `fsync`, compare the preimage again, rename, and `fsync` the directory.
6. Parse the result and verify the installed fragment fingerprint; restore the in-memory preimage on verification failure.
7. Encrypt and persist deployment ownership plus a receipt.
8. On removal, compare the current fragment to the installed fingerprint. Drift stops the operation and produces a conflict state.

## Revocation states

Host removal is only one stage. The complete model is:

`active → local_blocked → host_removed → provider_pending → provider_revoked_unverified → verified`

Failures remain `partial`, `conflict`, or `failed` with evidence. The current private preview implements verified host-fragment removal for JSON adapters. It does not label that outcome provider-revoked.

## Memory

Memory is typed encrypted data with sensitivity and allowed-host metadata. Explicit per-record selection makes it portable through JSON or encrypted packs. A future renderer may produce `AGENTS.md`, `CLAUDE.md`, Cursor rules, or MCP resources, but host-native formats are views—not the canonical store. Runtime retrieval must enforce allowed host, purpose, session, and sensitivity before it reaches a model.

## Release gates

- Rust unit, property/fuzz, parser, crypto-envelope, path and mutation tests
- Golden cross-platform transfer compatibility
- Real-host clean-VM install, restart, tool discovery, removal, logout, drift and rollback tests
- Disposable-provider OAuth denial, expiry, rotation, reconnect, and revoke verification tests
- Malicious import corpus and renderer-compromise tests
- Logs, backups, crash reports, and exports verified free of secrets
- Pinned dependencies, secret/dependency/license scanning, SBOM, provenance
- Signed Git tags, notarized macOS app, Windows signing, signed replay-protected updates
- Independent security review and remediation before production credential custody
