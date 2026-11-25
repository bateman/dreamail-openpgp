#!/usr/bin/env bash
# Builds DreaMailRPGP.xcframework (rust/ over rPGP) for macOS, arm64 +
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
name=DreaMailRPGP

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
	target/aarch64-apple-darwin/release/libdreamail_rpgp.a \
	target/x86_64-apple-darwin/release/libdreamail_rpgp.a \
	-output "$out/universal/libdreamail_rpgp.a"

# Every function the header declares must be exported, and nothing else
# named dm_ (or mm_, the prefix before v0.2.0) may be.
# A step that finds nothing must say so, not end the script silently
# (grep exits 1 on no match, which `set -e -o pipefail` turns into an exit).
expected=$(grep -oE 'dm_pgp_[a-z_]+\(' include/dreamail_rpgp.h | tr -d '(' | LC_ALL=C sort -u || true)
# Xcode's nm exits non-zero on this library: the Rust standard library's
# objects carry LLVM bitcode from a newer LLVM than Xcode's, which nm tries
# to read and cannot ("Unknown attribute kind"). The machine code and the
# symbol table next to it are fine, so the exit status is not used: the
# comparison below decides, and nm's messages are shown only if it fails.
nm -gU "$out/universal/libdreamail_rpgp.a" > "$out/symbols.txt" 2> "$out/nm-errors.txt" || true
exported=$(awk '{print $NF}' "$out/symbols.txt" | grep -E '^_(dm|mm)_' | sed 's/^_//' | LC_ALL=C sort -u || true)
if [ -z "$expected" ] || [ "$expected" != "$exported" ]; then
	echo "Header and exported symbols differ (header on the left, library on the right):" >&2
	diff <(echo "$expected") <(echo "$exported") >&2 || true
	echo "nm reported $(wc -l < "$out/symbols.txt" | tr -d ' ') lines; the first of its messages:" >&2
	head -20 "$out/nm-errors.txt" >&2
	echo "Members of the library:" >&2
	lipo -info "$out/universal/libdreamail_rpgp.a" >&2 || true
	ar -t target/aarch64-apple-darwin/release/libdreamail_rpgp.a | head -20 >&2 || true
	exit 1
fi
rm -f "$out/symbols.txt" "$out/nm-errors.txt"

cp include/dreamail_rpgp.h include/module.modulemap "$out/headers/"
xcodebuild -create-xcframework \
	-library "$out/universal/libdreamail_rpgp.a" -headers "$out/headers" \
	-output "$out/$name.xcframework"

find "$out/$name.xcframework" -exec touch -h -t 198001010000 {} +
(cd "$out" && find "$name.xcframework" -print | LC_ALL=C sort \
	| zip -X -q -@ "$name.xcframework.zip")

sum=$(shasum -a 256 "$out/$name.xcframework.zip" | cut -d' ' -f1)
echo "$sum  $name.xcframework.zip" > "$out/$name.xcframework.zip.sha256"
echo "Built $out/$name.xcframework.zip"
echo "Size: $(du -h "$out/$name.xcframework.zip" | cut -f1) zipped," \
	"$(du -h "$out/universal/libdreamail_rpgp.a" | cut -f1) static library (before linking)"
echo "SHA-256 (binaryTarget checksum): $sum"
