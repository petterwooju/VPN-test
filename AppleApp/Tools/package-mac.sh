#!/bin/bash
# Build and notarize a Developer ID disk image for Apple Silicon.
set -euo pipefail
if [[ $# != 3 || ! $1 =~ ^[A-Z0-9]{10}$ || -z $2 ]]; then
    echo "Usage: package-mac.sh TEAM_ID NOTARY_KEYCHAIN_PROFILE NEW_OUTPUT_DIRECTORY" >&2
    exit 2
fi
team=$1
profile=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
if ! /usr/bin/security find-identity -v -p codesigning | /usr/bin/awk -v team="$team" '/Developer ID Application:/ && index($0, "(" team ")") { found=1 } END { exit !found }'; then
    echo "The login keychain needs a Developer ID Application identity and private key for this team." >&2
    exit 1
fi
mkdir "$3"
out=$(cd "$3" && pwd)
core="$out/core"
"$root/AppleApp/TransportPrototype/build-archive.sh" macosx "$core" arm64
/usr/bin/xcodebuild archive -project "$root/CoreaVPN.xcodeproj" -scheme CoreaVPN -configuration Release \
    -destination 'generic/platform=macOS' -archivePath "$out/CoreaVPN.xcarchive" \
    DEVELOPMENT_TEAM="$team" ARCHS=arm64 ONLY_ACTIVE_ARCH=NO COREAVPN_ROUTING_ARTIFACTS="$core" -allowProvisioningUpdates
/usr/bin/python3 - "$team" "$out/ExportOptions.plist" <<'PY'
import plistlib, sys
with open(sys.argv[2], "wb") as out:
    plistlib.dump(dict(method="developer-id", teamID=sys.argv[1], signingStyle="automatic",
                       signingCertificate="Developer ID Application"), out)
PY
/usr/bin/xcodebuild -exportArchive -archivePath "$out/CoreaVPN.xcarchive" \
    -exportOptionsPlist "$out/ExportOptions.plist" -exportPath "$out/export" -allowProvisioningUpdates
app="$out/export/CoreaVPN.app"
provider="$app/Contents/Library/SystemExtensions/net.petterwooju.coreavpn.client.routing.systemextension"
test -x "$provider/Contents/MacOS/net.petterwooju.coreavpn.client.routing"
for item in "$app" "$provider"; do
    /usr/bin/codesign --verify --strict --verbose=2 "$item"
    /usr/bin/codesign -dv --verbose=4 "$item" 2>&1 | /usr/bin/awk -v team="$team" '$0=="TeamIdentifier=" team{t=1} /^Authority=Developer ID Application:/{a=1} END{exit !(a && t)}'
    test -s "$item/Contents/embedded.provisionprofile"
done
/usr/bin/ditto -c -k --keepParent "$app" "$out/CoreaVPN.zip"
/usr/bin/xcrun notarytool submit "$out/CoreaVPN.zip" --keychain-profile "$profile" --wait --output-format plist > "$out/app-notary.plist"
[[ $(/usr/bin/plutil -extract status raw "$out/app-notary.plist") == Accepted ]]
/usr/bin/xcrun stapler staple "$app"
mkdir "$out/disk"
/usr/bin/ditto "$app" "$out/disk/CoreaVPN.app"
ln -s /Applications "$out/disk/Applications"
/usr/bin/hdiutil create -volname CoreaVPN -srcfolder "$out/disk" -format UDZO "$out/CoreaVPN.dmg"
/usr/bin/xcrun notarytool submit "$out/CoreaVPN.dmg" --keychain-profile "$profile" --wait --output-format plist > "$out/dmg-notary.plist"
[[ $(/usr/bin/plutil -extract status raw "$out/dmg-notary.plist") == Accepted ]]
/usr/bin/xcrun stapler staple "$out/CoreaVPN.dmg"
/usr/bin/xcrun stapler validate "$out/CoreaVPN.dmg"
/usr/sbin/spctl --assess --type execute --verbose=2 "$app"
echo "$out/CoreaVPN.dmg"
