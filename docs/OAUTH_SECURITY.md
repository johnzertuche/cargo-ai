# Remote MCP authorization security contract

Cargo is a public native OAuth client. It never embeds or claims a confidential client secret. A remote MCP server is connectable only when it supports a preconfigured public client, Client ID Metadata Document, Dynamic Client Registration, or an explicitly supplied public client registration.

The current implementation includes the security core, a bounded Rust HTTP transport, an exact one-shot native loopback callback receiver, and an in-process OAuth/MCP conformance provider used only by tests. It validates and tests metadata, PKCE, state, resource binding, encrypted grant persistence, refresh rotation/replay, and revocation transitions. The desktop and CLI do not yet launch the user’s browser, expose provider connection controls, persist live tokens, or advertise compatibility with a named provider.

## Discovery and authorization invariants

- The canonical MCP resource and every production metadata/token endpoint use HTTPS, have a host, and contain no user information.
- Protected-resource metadata must return the exact requested resource.
- The selected authorization-server issuer must be one of the resource's advertised issuers, and discovered server metadata must use that exact issuer.
- Authorization Code and PKCE S256 are mandatory. Absence of advertised S256 support fails closed.
- The authorization and token requests both carry the exact resource indicator.
- A native redirect uses `http://127.0.0.1:<ephemeral-port>/...` or the IPv6 loopback literal. `localhost`, wildcard binds, fixed production ports, queries, and fragments are rejected.
- State and PKCE verifier values use 256 bits of operating-system randomness. State is one-shot and compared through a fixed-size digest without an early exit.
- Authorization transactions are non-serializable, redact secrets from `Debug`, and zeroize state/verifier buffers on drop.

Network discovery uses response/time caps, zero redirects, recursive duplicate-key rejection, proxy bypass, conservative public-address validation, and per-request pinned DNS resolution. Additional discovery fallback variants and real-provider conformance remain release gates before the desktop or CLI enables live authorization.

## Token boundary

Future token values are stored only under opaque, grant-scoped operating-system credential references. Provider-grant records may contain issuer, resource, public client ID, scopes, expiry, lifecycle state, and opaque references; they may never contain access/refresh token values. Tokens may be leased only inside the Rust HTTP transport, bound to one resource and required scopes, and sent only in the `Authorization` header. Renderer, CLI, logs, receipts, crash diagnostics, connection definitions, and portable packs never receive them.

Refresh requires single-flight synchronization and atomic rotation. Cargo does not activate or use a refresh token until provider rotation or sender constraint is proven. If an authorization response nevertheless issues one, Cargo retains it in the operating-system credential store only inside a locally blocked, durable provider-cleanup lifecycle; it is never silently discarded or converted into an access-only grant. Active refresh persistence remains disabled and access expiry requires reauthorization.

## Revocation evidence

Provider revocation never reuses the host deployment state. Cargo first commits a local block and durable pending operation. Only then may it call the provider, refresh token first and access token second where supported.

An RFC 7009 success is intentionally recorded as `accepted_unverified`: the RFC uses the same successful response for already-invalid and unknown tokens. `verified_revoked` requires stronger evidence:

- introspection reports every relevant token inactive; or
- an access-only grant receives an authoritative resource rejection; or
- a future provider-specific verifier proves the full grant inactive.

If a refresh token exists, access-token rejection alone leaves `provider_revoked_unverified`. Network and service failures remain locally blocked with a persisted retry time. Error persistence accepts only bounded lowercase safe codes—not provider bodies or token-bearing diagnostics.

Primary specifications: [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009).
