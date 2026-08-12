# Production macOS release

`.github/workflows/release-macos.yml` is the only production publication path. Local preview packaging remains separate and explicit:

```bash
cd apps/desktop
npm run desktop:build:preview
```

The production workflow runs two isolated jobs in the protected `production-release` GitHub Environment and refuses preview/prerelease tags. The build/sign job has read-only repository permission, disables persisted checkout credentials, and cannot publish or mint provenance. It hands a fixed artifact bundle to a publisher that does not check out or execute repository/package code. Only that publisher receives release-write, OIDC, and attestation permissions. The tag must be an annotated OpenPGP signature that GitHub verifies and that Cargo independently validates against a pinned maintainer fingerprint, use exact `vMAJOR.MINOR.PATCH` syntax, and match the Rust workspace, desktop package, and Tauri versions.

## Required GitHub Environment secrets

- `APPLE_CERTIFICATE`: base64 Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`: `.p12` export password
- `APPLE_SIGNING_IDENTITY`: full Developer ID Application identity
- `APPLE_TEAM_ID`: Apple developer team identifier
- `APPLE_API_ISSUER`: App Store Connect API issuer
- `APPLE_API_KEY`: App Store Connect API key identifier
- `APPLE_API_KEY_CONTENT`: one-time-downloaded P8 private-key contents
- `RELEASE_SIGNER_LOGIN`: the GitHub login whose published OpenPGP keys may sign production tags
- `RELEASE_SIGNER_FINGERPRINT`: the full uppercase fingerprint of the one OpenPGP primary or signing key authorized for production

The workflow generates its temporary keychain password, writes credentials only under `RUNNER_TEMP`, imports the allowlisted signer’s public keys into an ephemeral GnuPG home, and removes all temporary keychain and verification material in an unconditional cleanup step. Repository patterns reject common certificate/private-key artifacts. Protect `v*` tags and require an independent reviewer on the `production-release` environment in GitHub settings. The workflow requires both GitHub’s verification and a local `git verify-tag` result matching `RELEASE_SIGNER_FINGERPRINT`; a different key on the same GitHub account is rejected.

## Publication gates

1. Verify signed annotated tag and every version.
2. Install locked dependencies; run Rust tests, strict Clippy, formatting, renderer/site audits.
   The Rust gate includes encrypted export to an empty disposable vault, restart, inventory comparison, idempotence, wrong-passphrase rejection, and plaintext-at-rest checks. The renderer/backend gates prove Restore is available before profile creation and traverses the production staging/apply path.
3. Import Developer ID identity into an ephemeral keychain.
4. Build explicit Apple Silicon and Intel targets with hardened runtime; Tauri submits each for notarization and staples.
5. Verify strict/deep signature, expected Team ID, Gatekeeper assessment, stapling on app and DMG, DMG integrity, and the exact `Cargo.app` payload mounted from each distributed DMG. Ad-hoc signatures fail explicitly.
6. Produce CycloneDX Rust SBOMs and SHA-256 checksums.
7. Upload the verified fixed-name bundle to the isolated publisher with a one-day retention window.
8. Revalidate its checksums and `BUILD_COMMIT` against the still-verified signed tag, then create GitHub/Sigstore build-provenance attestations.
9. Upload an unpublished draft, verify its exact asset inventory, and only then publish it.

This workflow does not yet create signed Tauri updater manifests. Production auto-update remains blocked until the owner explicitly authorizes creation of the long-lived updater signing credential, commits only its public key, stores the private key in the protected environment with an offline recovery copy, and a prior signed build has shipped that trust root. A signed/notarized DMG may be released as a limited manual-update build, but it is not the full credential-custody GA described in the repository release policy and must not advertise automatic updates until that separate gate is complete.

If publication fails after draft creation, rerun the same signed tag. The workflow will reuse only an unpublished draft whose target matches the verified tag commit, replace its assets, recheck the complete inventory, and publish. It refuses to mutate an already-published or mismatched release.

Apple and Tauri setup references: [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/), [Tauri GitHub pipelines](https://v2.tauri.app/distribute/pipelines/github/), and [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
