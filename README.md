# dreamail-openpgp

The OpenPGP engine of DreaMail: [rPGP](https://github.com/rpgp/rpgp) behind a
small C interface, shipped as a prebuilt, checksummed `DreaMailRPGP.xcframework`
for macOS (arm64 and x86_64) that SwiftPM fetches as a `binaryTarget`.

Scope B (owner's decision): verify signatures (PGP/MIME detached and
cleartext), decrypt, read and import keys. Nothing here signs, encrypts or
generates keys. The Swift side (`RPGPEngine`, conforming to DreaMail's
`OpenPGPEngine`) and the `DREAMAIL_PGP` build switch live in DreaMail.

Releases up to v0.1.1 were published under the app's former name, MishMail:
`MishMailRPGP.xcframework.zip`, header `mishmail_rpgp.h`, symbols `mm_pgp_*`
and types `MMResult`/`MMBuffer`. From v0.2.0 they are `DreaMailRPGP`,
`dreamail_rpgp.h`, `dm_pgp_*` and `DMResult`/`DMBuffer` (an ABI break).

## Why rPGP

No ready-made Swift or Objective-C library is adequate (survey of 25 November
2026, PR #56 in the app repository, then named MishMail):

- ObjectivePGP is free only for non-commercial use, is RFC 4880 only, and
  vendors OpenSSL 1.1.1h, which has been out of support since 2023.
- The pure-Swift packages are months old, unaudited and have a single author.
- Sequoia is LGPL and its C API is deprecated.
- GopenPGP puts the Go runtime in the app.

rPGP is MIT or Apache-2.0, implements RFC 9580 and 4880, and has been audited
(Radically Open Security 2024, ETH 2024, Include Security 2019; see its
[SECURITY_STATUS](https://github.com/rpgp/rpgp/blob/56a40045e1d7516e5ec02244ea2884c92bece45f/docs/SECURITY_STATUS.md)).

## What is pinned

| | |
|---|---|
| rPGP | crate `pgp` `=0.21.1` (crates.io, 11 November 2026), MIT OR Apache-2.0 |
| rPGP crate checksum (crates.io, also in `rust/Cargo.lock`) | `c7275cbf21850789239e1be05d9a887e6bba6aa8085a81be09ca021c8379baef` |
| rPGP git tag `v0.21.1` | tag object `953a14294011e564ff2444f8b8574cdfba8d19de`, commit `56a40045e1d7516e5ec02244ea2884c92bece45f` |
| Every other crate | `rust/Cargo.lock` (152 packages including test-only ones; 145 linked into the macOS library), fetched with `--locked`, built `--offline`; all under permissive licences; no C code is compiled |
| Rust compiler | `rust/rust-toolchain.toml`: 1.97.0 |
| Default features | off (`default-features = false`: no bzip2) |
| GitHub Actions | pinned by full commit SHA |
| cargo-deny (advisory check) | 0.20.2, installed with `--locked` |

## Policy (`rust/src/engine.rs`)

Everything cryptographic is rPGP's. What this crate decides is policy, which
rPGP leaves to the application.

**Certificates**
- Only self-signatures count. Each must verify with an accepted hash, and at
  least one user ID must be bound; otherwise the key is `broken`.
- Third-party certifications are ignored. rPGP's own `verify_bindings` would
  reject a key that carries one.
- A user ID revoked by its owner is not listed.
- Every key revocation is tried against the primary key, whatever issuer it
  names.
- Expiry is the earliest among the newest self-signature of each bound user
  ID and the newest direct-key signature.

**Signing keys**
- The primary key signs data only if its newest self-signature carries the
  sign flag.
- A subkey signs data only if its newest verifying binding carries the sign
  flag, it is not revoked, and its own expiry has not passed.
- A signature by a revoked or expired key or subkey, or an expired signature,
  is `key_not_valid`.
- A signature created before its key, or more than 10 minutes in the future,
  is `bad`.

**Hashes**
- Data signatures with MD5, RIPEMD-160 or SHA-1 are `unsupported`.
- Self-signatures and bindings with MD5 or RIPEMD-160 make the key `broken`.
- SHA-1 is accepted in self-signatures and bindings: many long-lived keys
  still carry SHA-1 self-signatures, and rPGP checks them with
  collision-detecting SHA-1 (`sha1-checked`).

**Algorithms**
- Ed448 and X448 are refused (`unsupported`; keys are not imported, messages
  only to such keys are not decrypted). rPGP implements them with `cx448`,
  whose README says it has not been audited or reviewed and which ships no
  licence text. It is a mandatory dependency of rPGP 0.21.1: no feature flag
  removes it from the build, so the refusal is policy only. Reversible
  decision of the owner.

**Decryption**
- Legacy SED (no integrity check) is refused before decrypting:
  `not_integrity_protected`.
- A failed MDC (SEIPD v1, checked before any plaintext is released) or AEAD
  tag (SEIPD v2, GnuPG OCB) is `not_integrity_protected` too.
- GnuPG's OCB Encrypted Data packet (type 20, LibrePGP), which GnuPG 2.4
  sends by default to keys it generated, is decrypted through rPGP's
  `DecryptionOptions::enable_gnupg_aead`. It is authenticated encryption, and
  rPGP bounds it: OCB only (EAX does not parse: `malformed`), AES only (other
  ciphers: `unsupported`), chunks of 64 B to 4 MiB, each chunk's tag checked
  before its plaintext is read and a final tag over the length, so a
  truncated message fails. The whole plaintext is read before anything is
  returned: a failure releases nothing, not even chunks that authenticated.
  GnuPG's default chunk is 4 MiB, so rPGP buffers about 8 MiB per such
  decryption, whatever the message size.
  The option also enables GnuPG's v5 password packet (SKESK), which is unused:
  decryption here takes no message password.
- Well-formed features rPGP does not implement are `unsupported` when rPGP
  says so with a typed error. BZip2 content (rPGP is built without it) and
  GnuPG EAX are reported by rPGP with untyped errors and read `malformed`.
- Every AEAD error in SEIPD v2 is `not_integrity_protected`, including an
  "unsupported AEAD algorithm": v2's cipher and AEAD octets are not
  authenticated before rPGP uses them, so that error may come from an edited
  header. Only in GnuPG's packet 20 is an AEAD cipher rPGP lacks (Camellia,
  Twofish) `unsupported`: there rPGP first checks the cipher against the one
  sealed in the public-key-encrypted session key.
- **`unsupported` and `malformed` are unauthenticated verdicts.** The bytes
  that produce them are not integrity-protected, so anyone on the path can
  turn an authentic message into either. A caller must not present them as
  more benign than `not_integrity_protected`, and must never suggest that
  the sender resend the message unencrypted.
- Compressed, and signed-then-compressed, content is decompressed.

**Limits**
- Input: 48 MiB.
- Plaintext after decompression: 64 MiB, which stops compression bombs.
- 16 signatures per message, with duplicates removed.
- 32 session-key packets.

**Import**
- Public import stores only certificates the engine parsed and checked,
  re-serialized; never the bytes handed in, and never secret material.
- Secret import is a separate call: valid, supported keys only, still under
  their own passphrase.

## Memory, logging, threads

- **Wiping.** Result buffers are zeroed when freed (`dm_pgp_free`, `zeroize`);
  plaintext is held in `Zeroizing` buffers inside the crate. Copies the caller
  makes (Swift `Data` of the passphrase, secret keys or plaintext) cannot be
  wiped reliably; keep them short-lived.
- **Logging.** Nothing logs. rPGP logs packet details at debug level through
  the `log` crate: never install a `log` logger in a process that links this
  library.
- **Panics.** A panic is caught at the boundary, reported as `internal`, and
  not printed: the library replaces the default panic hook with a silent one.
- **Threads.** Calls are synchronous and can take a while. Call them off the
  main thread, and off Swift's cooperative pool.
- **Clock.** `now_unix` comes from the caller; zero or negative is refused,
  rather than read as 1970, which would hide every expiry.

## Known limits

- **Timing side channels:**
  - `rsa` 0.9.10, RUSTSEC-2023-0071 (Marvin): needs a timing oracle on RSA
    decryption. No fixed 0.9 release exists.
  - `crypto-bigint` 0.5.5, RUSTSEC-2026-0387: the fix is only in 0.7.6, and
    rPGP's `elliptic-curve` 0.13 needs 0.5. Exploiting it needs local timing or
    microarchitectural observation of secret-key operations.

  Both are allow-listed in `rust/deny.toml` with their reason. Every other
  advisory fails CI.
- **Legacy algorithms** compiled into rPGP, with no feature to remove them,
  are refused by the policy above.
- **Not evaluated:** designated revokers, third-party certifications (no web
  of trust), and signature creation time against a key's past validity
  windows. An old message signed by a key that has since expired reads
  `key_not_valid`.
- **Reproducibility.** The release workflow builds twice on one runner and
  refuses to publish if the zips differ. Whether two different Macs produce
  the same zip has not been verified. The checksum is committed with each
  release, and SwiftPM verifies it on download.

## Licences

- This repository: MIT (`LICENSE`).
- Linked crates: `THIRD_PARTY_LICENSES.md` lists every crate linked into the
  library and its licence texts. It is generated by
  `scripts/third_party_licenses.py` from `rust/Cargo.lock`, checked in CI, and
  attached to every release.
- Crates that publish no licence file: their texts come from upstream, see
  `licenses/README.md`. `cx448` has none anywhere.
- MIT, Apache-2.0 and BSD require their notices in redistributed binaries; how
  a public DreaMail release ships them is decided at distribution time.

## Build and test

```sh
(cd rust && cargo fetch --locked && cargo test --locked --offline)   # any platform; needs gpg 2.4 on PATH
(cd rust && cargo deny check advisories)                            # needs cargo-deny 0.20.2
scripts/third_party_licenses.py --check                             # licences match Cargo.lock
scripts/build-xcframework.sh                                        # macOS: build/DreaMailRPGP.xcframework.zip and .sha256
```

The GnuPG interoperability tests need a Unix system and GnuPG 2.4.x on
`PATH` (CI uses the one on the Ubuntu 24.04 runner image). They run it in
throwaway homes under `/tmp`, with keys generated at run time. Without it
they fail; they are never skipped. In tests rPGP is built without overflow
checks, as in release, so that they exercise the shipped arithmetic: rPGP
0.21.1 underflows (debug panic, release wrap then a bounds-check error) on
an unknown AEAD octet in a SEIPD v2 header.

`make check` runs the same checks; `make licences` regenerates the licence file.

## Upgrading rPGP

The **Upgrade rPGP** workflow runs every Monday (or by hand, with an
optional version). When crates.io has a newer stable `pgp`, it runs
`scripts/upgrade_rpgp.py` on `main`, pushes `deps/rpgp-<version>` and opens a
pull request, as a draft if a check failed. Locally the same is
`make upgrade-rpgp [VERSION=X.Y.Z]`, which leaves the changes uncommitted.

The script does the mechanical part:

- checks the release on crates.io: not yanked, MSRV within the pinned
  toolchain (otherwise it stops: raising the toolchain is a separate change);
- sets the exact pin and runs `cargo update -p pgp --precise`, so only what
  rPGP requires moves in `Cargo.lock`, and checks the lockfile checksum
  against crates.io;
- reads the tag object and commit of git tag `v<version>`;
- regenerates `THIRD_PARTY_LICENSES.md` and updates "What is pinned";
- runs tests, clippy, the licence check and cargo-deny;
- writes the report `build/rpgp-upgrade-<version>.md`, which is the pull
  request's body: lockfile changes, check results, and the remaining
  mentions of the old version.

The rest is review, and stays human: the rPGP changelog; the policy in
`rust/src/engine.rs` (error mapping, `enable_gnupg_aead`, refused
algorithms); whether `cx448` is still mandatory and the SEIPD v2 underflow
still there; the `rust/deny.toml` ignores and the known limits; licence files
of new crates. Merging the pull request starts the release by itself (below);
then, in DreaMail, the new `revision` in `project.yml` and the version in
`docs/DEPENDENCIES.md`.

Pull requests opened with `GITHUB_TOKEN` do not trigger CI by themselves:
the workflow dispatches CI on the branch. It needs "Allow GitHub Actions to
create and approve pull requests" (Settings, Actions, General).

## Releasing

1. The **Release** workflow runs by itself when an rPGP upgrade pull request
   (`deps/rpgp-*`) is merged, or by hand. With no version it takes the
   latest release tag and raises the patch number (`v0.2.0` → `0.2.1`); give
   one by hand for a minor or major release, e.g. when the C interface
   changes. It checks licences and advisories, builds the zip twice, refuses
   to publish if the two differ, and creates release `v<version>` with the
   zip, its `.sha256` and `THIRD_PARTY_LICENSES.md`.
2. The same workflow then downloads the published zip, checks it against
   the checksum, and opens the pull request `release/package-v<version>`
   that sets `version` and `checksum` in `Package.swift`. Merging it is the
   reviewed commit. Cross-check the checksum with a local
   `scripts/build-xcframework.sh` on another Mac.
3. DreaMail pins **that commit** in `project.yml`, the same way as GRDB:
   ```yaml
   packages:
     DreaMailRPGP:
       url: https://github.com/bateman/dreamail-openpgp
       revision: <40-hex commit from step 2>
   ```
   SwiftPM refuses a downloaded zip whose SHA-256 differs from `checksum`.
