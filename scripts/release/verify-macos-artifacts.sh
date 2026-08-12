#!/bin/bash
set -euo pipefail

app_path="$1"
dmg_path="$2"
expected_team="$3"

test -d "$app_path"
test -f "$dmg_path"
codesign --verify --deep --strict --verbose=2 "$app_path"
actual_team="$(codesign -dv --verbose=4 "$app_path" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
test -n "$actual_team"
test "$actual_team" = "$expected_team"
spctl --assess --type execute --verbose=4 "$app_path"
xcrun stapler validate "$app_path"
xcrun stapler validate "$dmg_path"
hdiutil verify "$dmg_path"
if codesign -dv --verbose=4 "$app_path" 2>&1 | grep -q 'Signature=adhoc'; then
  echo "production artifact is ad-hoc signed" >&2
  exit 1
fi

mount_point="$(mktemp -d)"
cleanup() {
  hdiutil detach "$mount_point" -quiet 2>/dev/null || true
  rmdir "$mount_point" 2>/dev/null || true
}
trap cleanup EXIT
hdiutil attach "$dmg_path" -readonly -nobrowse -mountpoint "$mount_point" -quiet
distributed_app="$mount_point/Cargo.app"
test -d "$distributed_app"
codesign --verify --deep --strict --verbose=2 "$distributed_app"
distributed_team="$(codesign -dv --verbose=4 "$distributed_app" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
test "$distributed_team" = "$expected_team"
spctl --assess --type execute --verbose=4 "$distributed_app"
xcrun stapler validate "$distributed_app"
