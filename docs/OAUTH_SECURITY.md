# Remote MCP authorization security contract

Cargo is a public native OAuth client. It never embeds or claims a confidential client secret. A remote MCP server is connectable only when it supports a preconfigured public client, Client ID Metadata Document, Dynamic Client Registration, or an explicitly supplied public client registration.

The current implementation is the non-networked security core. It validates and tests metadata, PKCE, state, resource binding, encrypted grant persistence, and revocation transitions. It does not yet launch a browser, receive callbacks, exchange or store live tokens, or advertise compatibility with a named provider.

## Discovery and authorization invariants

- The canonical MCP resource and every production metadata/token endpoint use HTTPS, have a host, and contain no user information.
- Protected-resource metadata must return the exact requested resource.
- The selected authorization-server issuer must be one of the resource's advertised issuers, and discovered server metadata must use that exact issuer.
- Authorization Code and PKCE S256 are mandatory. Absence of advertised S256 support fails closed.
- The authorization and token requests both carry the exact resource indicator.
- A native redirect uses `http://127.0.0.1:<ephemeral-port>/...` or the IPv6 loopback literal. `localhost`, wildcard binds, fixed production ports, queries, and fragments are rejected.
- State and PKCE verifier values use 256 bits of operating-system randomness. State is one-shot and compared through a fixed-size digest without an early exit.
- Authorization transactions are non-serializable, redact secrets from `Debug`, and zeroize state/verifier buffers on drop.

Network discovery must additionally implement response/time/redirect caps, DNS rebinding protection, private/link-local address rejection, exact discovery fallback order, and browser/callback isolation before it can be enabled.

## Token boundary

Future token values are stored only under opaque, grant-scoped operating-system credential references. Provider-grant records may contain issuer, resource, public client ID, scopes, expiry, lifecycle state, and opaque references; they may never contain access/refresh token values. Tokens may be leased only inside the Rust HTTP transport, bound to one resource and required scopes, and sent only in the `Authorization` header. Renderer, CLI, logs, receipts, crash diagnostics, connection definitions, and portable packs never receive them.

Refresh requires single-flight synchronization and atomic rotation. If a public client receives neither sender-constrained nor rotating refresh tokens, Cargo must not persist that refresh token and must require reauthorization after access expiry.

## Revocation evidence

Provider revocation never reuses the host deployment state. Cargo first commits a local block and durable pending operation. Only then may it call the provider, refresh token first and access token second where supported.

An RFC 7009 success is intentionally recorded as `accepted_unverified`: the RFC uses the same successful response for already-invalid and unknown tokens. `verified_revoked` requires stronger evidence:

- introspection reports every relevant token inactive; or
- an access-only grant receives an authoritative resource rejection; or
- a future provider-specific verifier proves the full grant inactive.

If a refresh token exists, access-token rejection alone leaves `provider_revoked_unverified`. Network and service failures remain locally blocked with a persisted retry time. Error persistence accepts only bounded lowercase safe codes—not provider bodies or token-bearing diagnostics.

Primary specifications: [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252), and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009).
