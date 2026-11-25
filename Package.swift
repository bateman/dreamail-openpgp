// swift-tools-version:5.9
// The OpenPGP engine of DreaMail (rPGP behind a C interface) as a prebuilt,
// checksummed binary. Consumers pin this repository by commit; SwiftPM checks
// the zip against `checksum` on download.
//
// Release order (README, "Releasing"): the release workflow builds and
// publishes the zip and its SHA-256 under tag v<version>; then a commit sets
// `version` and `checksum` below to that release. Consumers pin that commit.
import PackageDescription

let version = "0.2.0"
let checksum = "bcde125bcc1d97e89562a771ea85b6e9a6f3e2ca16204396f8838223edda5839"

let package = Package(
    name: "dreamail-openpgp",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "DreaMailRPGP", targets: ["DreaMailRPGP"]),
    ],
    targets: [
        .binaryTarget(
            name: "DreaMailRPGP",
            url: "https://github.com/bateman/dreamail-openpgp/releases/download/v\(version)/DreaMailRPGP.xcframework.zip",
            checksum: checksum),
    ]
)
