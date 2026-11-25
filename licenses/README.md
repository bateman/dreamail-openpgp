# Licence texts missing from published crates

Some crates on crates.io ship no licence file. Their texts are taken from the
upstream repository named in the crate's `Cargo.toml`, at the commit below,
and `scripts/third_party_licenses.py` uses them for the crates listed.

| Directory | Used for | Source |
|---|---|---|
| `bitfields/` | bitfields, bitfields-impl | <https://github.com/gregorygaines/bitfields-rs>, commit `e2c815c35a798d11a4184dc60589e8fc1c6a027d` |
| `crc24/` | crc24 | <https://github.com/sellibitze/crc24-rs>, commit `f565288a93806a0202a9c5d194db80dc1dc5a7fd` |

**cx448** (BSD-3-Clause, <https://github.com/dignifiedquire/cx448>, commit
`58785c9ea154f646d03ccec4185f0a1ffa1c67e5`) ships no licence text, and its
repository has none either: there is no copyright notice to reproduce. It is
listed in the script as acknowledged. Its README also says "THIS CODE HAS NOT
BEEN AUDITED OR REVIEWED"; rPGP uses it for Ed448 and X448 keys only.

Recorded 25 November 2026.
