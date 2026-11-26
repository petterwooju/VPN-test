#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:?Pass a build output directory}"
mkdir -p "$out"
cache="${TMPDIR:-/tmp}/coreavpn-swift-cache"
sources="$root/plugins/coreavpn-macos/skills/coreavpn-macos/scripts"
swiftc -module-cache-path "$cache" "$sources/offline-ui.swift" -o "$out/offline-ui-quick"
swiftc -parse-as-library -module-cache-path "$cache" "$root/AppleApp/Networking/EndpointResolver.swift" \
    "$root/AppleApp/Tools/QuickResolve.swift" -o "$out/quick-resolve"
