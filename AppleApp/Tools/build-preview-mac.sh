#!/bin/bash
# Local Mac UI/logic build for hosts with Command Line Tools only.
# Xcode supplies the provisioning profile for actual Personal VPN operation.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:?Pass a build output directory}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
bundle="$out/CoreaVPN.app/Contents"
mkdir -p "$bundle/MacOS" "$bundle/Resources"
sdk="$(xcrun --sdk macosx --show-sdk-path)"
swiftc -parse-as-library -swift-version 5 -sdk "$sdk" -target "$(uname -m)-apple-macos14.0" \
    -I "$root/AppleApp/NativeSpeed/include" \
    -module-cache-path "${TMPDIR:-/tmp}/coreavpn-swift-cache" \
    "$root"/AppleApp/{App,Benchmark,Networking,RouteLab,Rules}/*.swift \
    -o "$bundle/MacOS/CoreaVPN"
cp "$root/AppleApp/Resources/BeijingOfficeBaseline.csv" "$bundle/Resources/"
cat > "$bundle/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>CoreaVPN</string>
<key>CFBundleIdentifier</key><string>net.petterwooju.coreavpn.preview</string>
<key>CFBundleName</key><string>CoreaVPN</string>
<key>CFBundleDisplayName</key><string>CoreaVPN Preview</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
</dict></plist>
PLIST
workspace=$(dirname "$root")
runtime="$HOME/Library/Application Support/CoreaVPN/LocalRuntime"
map="${COREAVPN_QUICK_MAP:-$runtime/build/fl-map.json}"
# CI and fresh checkouts can still build the native interface without this Mac's calibration.
if [[ -f "$map" ]]; then
    stage="$out/LocalRuntime"
    skill=plugins/coreavpn-macos/skills/coreavpn-macos
    package="$stage/VPN-test/$skill"
    mkdir -p "$package/scripts" "$package/assets/Puma-DNS" "$stage/build"
    cp "$root/$skill/assets/servers.json" "$package/assets/"
    cp "$root/$skill"/scripts/{quick-search.py,quick_candidates.py,quick_policy.py,offline-pilot.py,https_speed.py,vpn-ping.py} "$package/scripts/"
    cp "$root/$skill"/assets/Puma-DNS/{session.py,relay.py,uplink.py} "$package/assets/Puma-DNS/"
    cp "$root/AppleApp/Tools/run-local-puma.command" "$stage/Run-Puma.command"
    cp "$map" "$stage/build/fl-map.json"
    quick_ui="${COREAVPN_QUICK_UI:-$workspace/build/offline-ui-quick}"
    cp "$quick_ui" "$stage/build/offline-ui-quick"
    cp "$(dirname "$quick_ui")/quick-resolve" "$stage/build/quick-resolve"
    # Older launchers can still request this path. Both must use named VPN operations.
    cp "$quick_ui" "$stage/build/offline-ui-next"
    /usr/bin/plutil -insert CoreaVPNPilotWorkspace -string "$runtime" "$bundle/Info.plist"
    /usr/bin/plutil -insert CoreaVPNQuickUI -string "$runtime/build/offline-ui-quick" "$bundle/Info.plist"
    /usr/bin/plutil -insert CoreaVPNQuickMap -string "$runtime/build/fl-map.json" "$bundle/Info.plist"
fi
codesign --force --sign - "$out/CoreaVPN.app"
codesign --verify --strict "$out/CoreaVPN.app"
echo "$out/CoreaVPN.app"
