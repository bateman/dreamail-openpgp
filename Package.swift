// swift-tools-version:5.9
// The OpenPGP engine of MishMail (rPGP behind a C interface) as a prebuilt,
// checksummed binary. Consumers pin this repository by commit; SwiftPM checks
// the zip against `checksum` on download.
//
// Release order (README, "Releasing"): the release workflow builds and
// publishes the zip and its SHA-256 under tag v<version>; then a commit sets
// `version` and `checksum` below to that release. Consumers pin that commit.
import PackageDescription

let version = "0.0.0"  // no release yet
let checksum = "0000000000000000000000000000000000000000000000000000000000000000"  // no release yet

let package = Package(
    name: "dreamail-openpgp",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "MishMailRPGP", targets: ["MishMailRPGP"]),
    ],
    targets: [
        .binaryTarget(
            name: "MishMailRPGP",
            url: "https://github.com/bateman/dreamail-openpgp/releases/download/v\(version)/MishMailRPGP.xcframework.zip",
            checksum: checksum),
    ]
)
