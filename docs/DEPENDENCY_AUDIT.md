# Dependency audit notes

The macOS private-preview gate runs `cargo audit` against the locked graph and denies known vulnerabilities, yanked crates, and unsoundness.

`RUSTSEC-2024-0429` is explicitly ignored only in that macOS gate. It affects `glib 0.18.5`, pulled by Tauri's Linux GTK3 target. `cargo tree --target aarch64-apple-darwin -i glib@0.18.5` confirms that crate is not present in the shipped Apple Silicon binary. A Linux release remains blocked until its webview stack no longer carries this advisory or the affected path receives a separate risk review and conformance test.

RustSec also reports maintenance warnings in transitive build/UI packages from Tauri and `age`; these are tracked, but are not known vulnerabilities in the current macOS artifact. npm production audits for both the site and renderer report zero vulnerabilities.
