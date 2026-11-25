#!/usr/bin/env bash
# Builds MishMailRPGP.xcframework (rust/ over rPGP) for macOS, arm64 +
# x86_64, zips it, and writes the SHA-256 that Package.swift's binaryTarget
# pins.
#
# Reproducibility measures: fixed Rust toolchain (rust/rust-toolchain.toml),
# --locked (Cargo.lock pins every crate by version and checksum), no
# incremental build, local paths remapped out of the binary, ZERO_AR_DATE
# for archive timestamps, fixed file times and sorted entries in the zip.
# The release workflow builds twice in separate directories and refuses to
# publish if the two zips differ. Whether two different Macs produce the same
# zip has NOT been verified yet.
#
# Usage: scripts/build-xcframework.sh [output-dir]   (default: build)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
crate="$root/rust"
out=${1:-"$root/build"}
name=MishMailRPGP

if [ "$(uname -s)" != "Darwin" ]; then
	echo "This builds an Apple xcframework: run it on macOS." >&2
	exit 1
fi
for tool in cargo rustup xcodebuild lipo nm shasum zip; do
	command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 1; }
done

export CARGO_INCREMENTAL=0
export ZERO_AR_DATE=1
export MACOSX_DEPLOYMENT_TARGET=14.0
SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct -- rust)
export SOURCE_DATE_EPOCH
cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
export RUSTFLAGS="--remap-path-prefix=$crate=/dreamail-openpgp --remap-path-prefix=$cargo_home=/cargo"

cd "$crate"
rustup show active-toolchain
# Download once against Cargo.lock, then build offline: nothing fetched
# during the build can differ from what was checked.
cargo fetch --locked
for target in aarch64-apple-darwin x86_64-apple-darwin; do
	cargo build --locked --offline --release --lib --target "$target"
done

rm -rf "$out"
mkdir -p "$out/universal" "$out/headers"
lipo -create \
	target/aarch64-apple-darwin/release/libmishmail_rpgp.a \
	target/x86_64-apple-darwin/release/libmishmail_rpgp.a \
	-output "$out/universal/libmishmail_rpgp.a"

# Every function the header declares must be exported, and nothing else
# named mm_ may be.
expected=$(grep -oE 'mm_pgp_[a-z_]+\(' include/mishmail_rpgp.h | tr -d '(' | LC_ALL=C sort -u)
exported=$(nm -gU "$out/universal/libmishmail_rpgp.a" 2>/dev/null \
	| awk '{print $NF}' | grep -E '^_mm_' | sed 's/^_//' | LC_ALL=C sort -u)
if [ "$expected" != "$exported" ]; then
	echo "Header and exported symbols differ:" >&2
	diff <(echo "$expected") <(echo "$exported") >&2 || true
	exit 1
fi

cp include/mishmail_rpgp.h include/module.modulemap "$out/headers/"
xcodebuild -create-xcframework \
	-library "$out/universal/libmishmail_rpgp.a" -headers "$out/headers" \
	-output "$out/$name.xcframework"

find "$out/$name.xcframework" -exec touch -h -t 198001010000 {} +
(cd "$out" && find "$name.xcframework" -print | LC_ALL=C sort \
	| zip -X -q -@ "$name.xcframework.zip")

sum=$(shasum -a 256 "$out/$name.xcframework.zip" | cut -d' ' -f1)
echo "$sum  $name.xcframework.zip" > "$out/$name.xcframework.zip.sha256"
echo "Built $out/$name.xcframework.zip"
echo "Size: $(du -h "$out/$name.xcframework.zip" | cut -f1) zipped," \
	"$(du -h "$out/universal/libmishmail_rpgp.a" | cut -f1) static library (before linking)"
echo "SHA-256 (binaryTarget checksum): $sum"
