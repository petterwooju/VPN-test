#!/bin/bash
# Offline regression checks. Optional argument: a local FlClash config for import validation.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cache="$root/../.build/checks"
mkdir -p "$cache"
cd "$root"
compile() {
    local name="$1"; shift
    xcrun swiftc -swift-version 5 -module-cache-path "$cache/modules" "$@" -o "$cache/$name"
}
compile benchmark Benchmark/*.swift Networking/EndpointResolver.swift Tests/Benchmark/BenchmarkChecks.swift
"$cache/benchmark" Resources/BeijingOfficeBaseline.csv
compile quick-bridge Benchmark/{BenchmarkModels,BenchmarkStore}.swift Networking/EndpointResolver.swift App/{LocalTerminal,LocalQuickSearch}.swift Tests/Benchmark/QuickBridgeChecks.swift
"$cache/quick-bridge"
compile network -I NativeSpeed/include Benchmark/BenchmarkModels.swift Networking/*.swift Tests/Networking/NetworkChecks.swift
"$cache/network"
compile rules Rules/{RoutingRules,ClashRuleImport}.swift Tests/Rules/RuleChecks.swift
"$cache/rules" "$@"
compile proxy Rules/{RoutingRules,ClashRuleImport}.swift ProxyPrototype/Swift/ExperimentalProxyStore.swift Tests/Proxy/ProxyLeafChecks.swift
"$cache/proxy" "$@"
compile routes Rules/RoutingRules.swift RoutingPrototype/SplitRoutePlanner.swift Tests/RoutingPrototype/RoutePlanChecks.swift
"$cache/routes"
compile provider Rules/RoutingRules.swift Networking/EndpointResolver.swift Benchmark/BenchmarkModels.swift \
    RoutingPrototype/SplitRoutePlanner.swift RoutingPrototype/Extension/*.swift Tests/RoutingPrototype/ProviderInputChecks.swift
"$cache/provider"
python3 -B Tests/Benchmark/NativePilotChecks.py

# A logged-in macOS session is needed for AppKit layout and accessibility cell geometry.
if [[ "${COREAVPN_CHECK_APPKIT_LAYOUT:-0}" == 1 ]]; then
    compile comparison-layout -I NativeSpeed/include Benchmark/*.swift Networking/*.swift \
        App/{Uplink,SessionModel,ServerComparisonTable,HistoryView,LocalTerminal}.swift \
        Tests/Benchmark/ComparisonLayoutChecks.swift
    "$cache/comparison-layout"
fi
