#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
cache="$(mktemp -d "${TMPDIR:-/tmp}/coreavpn-history.XXXXXX")"
trap 'rm -rf "$cache"' EXIT
/usr/bin/xcrun swiftc -swift-version 5 -module-cache-path "${TMPDIR:-/tmp}/coreavpn-swift-cache" Benchmark/BenchmarkModels.swift \
    Benchmark/BenchmarkStore.swift Networking/EndpointResolver.swift App/LocalTerminal.swift App/LocalQuickSearch.swift \
    Tools/ImportLocalHistory.swift -o "$cache/import-local-history"
"$cache/import-local-history" "$@"
