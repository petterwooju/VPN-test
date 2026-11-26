#!/bin/sh
# Build one static archive for an Apple SDK and architecture.
set -eu
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: build-archive.sh {macosx|iphoneos|iphonesimulator} OUTPUT_DIRECTORY [arm64|x86_64|universal]" >&2
    exit 2
fi
sdk=$1
output=$2
case "$sdk" in
    macosx|iphonesimulator) default_arch=universal ;;
    *) default_arch=arm64 ;;
esac
arch=${3:-$default_arch}
mkdir -p "$output"
out=$(cd "$output" && pwd)
src=$(cd "$(dirname "$0")" && pwd)
if [ "$arch" = universal ]; then
    case "$sdk" in
        macosx|iphonesimulator) ;;
        *) echo "Universal is available for macOS and iOS Simulator" >&2; exit 2 ;;
    esac
    # Keep the last complete universal archive available to Xcode while both slices build.
    scratch=$(mktemp -d "$out/.slices.XXXXXXXX")
    trap 'rm -rf "$scratch"' EXIT
    "$src/build-archive.sh" "$sdk" "$scratch/arm64" arm64
    "$src/build-archive.sh" "$sdk" "$scratch/x86_64" x86_64
    xcrun lipo -create "$scratch/arm64/libCoreIPSec.a" "$scratch/x86_64/libCoreIPSec.a" -output "$scratch/libCoreIPSec.a"
    mv "$scratch/libCoreIPSec.a" "$out/libCoreIPSec.a"
    cp "$src/include/CoreIPSec.h" "$src/include/module.modulemap" "$src/ThirdPartyNotices.txt" "$out/"
    exit 0
fi
case "$arch" in
    arm64) goarch=arm64 ;;
    x86_64) goarch=amd64 ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 2 ;;
esac
case "$sdk" in
    macosx) goos=darwin; target="$arch-apple-macos13" ;;
    iphoneos) goos=ios; target="$arch-apple-ios16" ;;
    iphonesimulator) goos=ios; target="$arch-apple-ios16-simulator" ;;
    *) echo "Unknown Apple SDK: $sdk" >&2; exit 2 ;;
esac
sdkpath=$(xcrun --sdk "$sdk" --show-sdk-path)
clang=$(xcrun --sdk "$sdk" --find clang)
export CC="\"$clang\""
export CGO_ENABLED=1 GOARCH="$goarch" GOOS="$goos"
export CGO_CFLAGS="-isysroot \"$sdkpath\" -target $target"
export CGO_LDFLAGS="-isysroot \"$sdkpath\" -target $target"
"${GO:-go}" -C "$src" build -mod=readonly -trimpath -buildmode=c-archive -o "$out/libCoreIPSec.a" .
cp "$src/include/CoreIPSec.h" "$src/include/module.modulemap" "$src/ThirdPartyNotices.txt" "$out/"
