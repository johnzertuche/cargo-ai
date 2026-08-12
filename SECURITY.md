# Security model

Kord is a prototype. The current web UI demonstrates the intended user experience; it does not yet perform real third-party authorization or write host configuration.

## Trust boundaries

1. The control plane stores identities, manifests, policy, public metadata, and encrypted credential envelopes. It never returns provider refresh tokens to an AI host.
2. The vault broker performs token exchange and provider API calls. Decryption keys are held in a dedicated KMS/HSM boundary, separated from the application database.
3. The signed local agent applies local configuration and launches approved `stdio` MCP processes. It uses the operating-system credential store and requires an explicit diff approval for mutation.
4. Remote AI hosts connect through a scoped gateway. Each host receives a distinct audience-bound credential and cannot reuse another host's session.
5. Memory records are encrypted, typed, provenance-bearing, and evaluated against disclosure policy for every host and session.

## Authorization requirements

- OAuth authorization code flow with PKCE and exact redirect-URI matching.
- `state` and nonce validation; no implicit flow.
- Incremental, least-privilege scopes. Denied scopes disable the corresponding feature.
- Short-lived access tokens. Rotating refresh tokens where the provider supports them.
- Sender-constrained tokens (DPoP or mTLS) where available.
- Secrets encrypted in transit and at rest; never logged, exported in manifests, or committed.
- Remote MCP authorization follows current MCP authorization metadata discovery and protected-resource metadata requirements.
- Local `stdio` credentials are injected at process launch from OS secure storage, never persisted into portable configuration.

## Revocation is a workflow, not a button

Revocation creates a durable operation with an idempotency key and performs these steps:

1. Mark the Kord grant `revoking` so no new sessions can be minted.
2. Invalidate Kord gateway sessions and cached access tokens immediately.
3. Call the provider revocation endpoint when supported; delete the provider grant when a full disconnect is requested.
4. Push removal operations to every linked host adapter and local device.
5. Verify the provider token is rejected and each host no longer advertises the capability.
6. Delete encrypted token material and retain only a non-secret audit receipt.
7. Mark `revoked` only after all mandatory checks pass. Partial failures stay visible and retry with bounded backoff.

The emergency path blocks Kord-issued access immediately even if an upstream provider is unavailable. A reconciler continues provider and host cleanup until verified.

## Memory safety

- Default disclosure posture is `ask`; sensitive records default to `local-only`.
- Records include type, source, author, timestamp, confidence, sensitivity, allowed purposes, allowed hosts, expiry, and supersession lineage.
- Retrieval is policy-filtered before semantic search results reach a model.
- Models cannot silently promote conversation text into durable memory.
- Every read and write generates a user-visible receipt. Users can inspect, correct, export, expire, or delete records.
- Deletion removes indexes and ciphertext and schedules backup tombstoning according to the published retention window.
- Portable exports contain encrypted records or redacted plaintext selected by the user—never vault keys.

## Supply-chain controls

- Signed manifests and adapter packages with pinned digests and provenance attestations.
- Sandboxed adapters, explicit network/filesystem capabilities, resource limits, and egress allowlists.
- Two-person review for publisher verification and security-sensitive adapter changes.
- Dependency scanning, secret scanning, SBOM generation, reproducible builds, and staged rollout with rollback.
- No silent widening of scopes during upgrades.

## Required production validation

- Threat model using STRIDE plus abuse-case review.
- External penetration test before holding real credentials.
- OAuth conformance tests and provider-specific revoke/expiry test suites.
- Adapter contract tests in disposable accounts for connect, denied scope, token rotation, expiry, revoke, reconnect, drift, and rollback.
- Local-agent code signing, auto-update verification, and tamper response.
- Incident response, key rotation, restore drills, and deletion verification.

