# Production architecture

## Core objects

- **Identity**: user, organization, device, and linked AI-host identities.
- **Capability**: a plugin, MCP server, skill, rule, connector, or native tool.
- **Link**: a versioned, signed selection of capabilities plus policy—not credentials.
- **Grant**: provider authorization, scopes, owner, expiry, and encrypted token reference.
- **Deployment**: the desired and observed state of a Link on one AI host.
- **Memory record**: typed personal or workspace context with provenance and disclosure policy.
- **Receipt**: immutable evidence of consent, installation, access, mutation, revocation, or rollback.

## Planes

### Control plane

Identity graph, universal manifest registry, policy engine, deployment coordinator, audit ledger, health reconciler, and adapter registry. This plane never needs plaintext provider credentials.

### Credential plane

Isolated vault broker backed by KMS/HSM. It supports envelope encryption, token rotation, scoped token exchange, provider revocation, and cryptographic deletion. Operators cannot read user secrets through normal application access.

### Data plane

Remote MCP gateway and signed local agent. The gateway authenticates AI hosts, applies policy, exposes only permitted tools, and records calls. The local agent owns OS-level configuration and local process execution.

### Memory plane

Encrypted record store, provenance ledger, policy-filtered retrieval, host-specific renderers, and import/export adapters. A renderer may produce `AGENTS.md`, `CLAUDE.md`, rules, system context, or MCP resources without making any host-specific format canonical.

## Adapter contract

Every host adapter implements:

- `discover()` — enumerate supported surfaces, installed capabilities, and limits.
- `plan(link)` — return a deterministic, human-readable diff.
- `apply(plan, consentReceipt)` — make idempotent mutations.
- `verify()` — prove observed state and exercise non-destructive health checks.
- `revoke(deployment)` — remove config, sessions, and cached credentials.
- `rollback(receipt)` — restore the last verified state.
- `renderMemory(records, policy)` — create the minimum host-native context view.

Adapters return structured evidence and never self-approve. Unsupported capabilities fail visibly.

## Connection sequence

1. Discover host capabilities and current configuration.
2. Resolve the Link to a host-specific desired state.
3. Evaluate organizational and user policy.
4. Display exact capabilities, scopes, processes, endpoints, files, and memory disclosures.
5. Capture a signed consent receipt.
6. Complete OAuth in the system browser or register a local secret reference.
7. Apply an idempotent host mutation.
8. Verify configuration plus a safe provider/API health check.
9. Record observed state, drift fingerprint, and rollback material.

## Availability and correctness

- Durable workflow engine for connect, rotate, sync, revoke, and rollback operations.
- Transactional outbox for all cross-service events.
- Idempotency keys on every mutation; monotonic deployment versions prevent stale writes.
- Per-provider circuit breakers and bounded retries.
- Reconciliation compares desired and observed state continuously without silently overwriting user edits.
- A provider or host outage degrades only that capability; it cannot block unrelated AI hosts.

## Delivery sequence

1. Implement a read-only importer for Claude, Cursor, and Codex local configurations.
2. Define the signed Link manifest and deterministic diff engine.
3. Ship the local agent with OS-keychain integration and reversible config writes.
4. Add one real remote OAuth connector and complete the full revoke test matrix.
5. Add remote MCP gateway and per-host credentials.
6. Add typed memory records, disclosure policies, and three host renderers.
7. Expand adapters only after conformance tests pass for connect, verify, revoke, and rollback.

