# Production macOS release

`.github/workflows/release-macos.yml` is the only production publication path. Local preview packaging remains separate and explicit:

```bash
cd apps/desktop
npm run desktop:build:preview
```

The production job runs in the protected `production-release` GitHub Environment and refuses preview/prerelease tags. Its tag must be an annotated signature that GitHub verifies, use exact `vMAJOR.MINOR.PATCH` syntax, and match the Rust workspace, desktop package, and Tauri versions.

## Required GitHub Environment secrets

- `APPLE_CERTIFICATE`: base64 Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`: `.p12` export password
- `APPLE_SIGNING_IDENTITY`: full Developer ID Application identity
- `APPLE_TEAM_ID`: Apple developer team identifier
- `APPLE_API_ISSUER`: App Store Connect API issuer
- `APPLE_API_KEY`: App Store Connect API key identifier
- `APPLE_API_KEY_CONTENT`: one-time-downloaded P8 private-key contents
- `RELEASE_SIGNER_LOGIN`: the single GitHub login allowed to sign production tags

The workflow generates its temporary keychain password, writes credentials only under `RUNNER_TEMP`, and removes the keychain, certificate, and P8 in an unconditional cleanup step. Repository patterns reject common certificate/private-key artifacts. Protect `v*` tags and require an independent reviewer on the `production-release` environment in GitHub settings; the workflow also rejects any verified signature whose signer login is not the allowlisted value.

## Publication gates

1. Verify signed annotated tag and every version.
2. Install locked dependencies; run Rust tests, strict Clippy, formatting, renderer/site audits.
3. Import Developer ID identity into an ephemeral keychain.
4. Build explicit Apple Silicon and Intel targets with hardened runtime; Tauri submits each for notarization and staples.
5. Verify strict/deep signature, expected Team ID, Gatekeeper assessment, stapling on app and DMG, DMG integrity, and the exact `Cargo.app` payload mounted from each distributed DMG. Ad-hoc signatures fail explicitly.
6. Produce CycloneDX Rust SBOMs and SHA-256 checksums.
7. Create GitHub/Sigstore build-provenance attestations.
8. Upload an unpublished draft, verify its exact asset inventory, and only then publish it.

This workflow does not yet create signed Tauri updater manifests. Production auto-update remains blocked until the owner explicitly authorizes creation of the long-lived updater signing credential, commits only its public key, stores the private key in the protected environment with an offline recovery copy, and a prior signed build has shipped that trust root. A signed/notarized DMG may be released as a limited manual-update build, but it is not the full credential-custody GA described in the repository release policy and must not advertise automatic updates until that separate gate is complete.

If publication fails after draft creation, rerun the same signed tag. The workflow will reuse only an unpublished draft whose target matches the verified tag commit, replace its assets, recheck the complete inventory, and publish. It refuses to mutate an already-published or mismatched release.

Apple and Tauri setup references: [Tauri macOS signing](https://v2.tauri.app/distribute/sign/macos/), [Tauri GitHub pipelines](https://v2.tauri.app/distribute/pipelines/github/), and [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
