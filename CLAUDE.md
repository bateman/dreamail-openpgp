# Project instructions

This repository is part of DreaMail (https://github.com/bateman/dreamail): the
OpenPGP engine it links as a prebuilt `binaryTarget`. DreaMail's `CLAUDE.md`
applies here too: communication style, review tiers, the owner writes in
Italian (answer in Italian; code, commits and documents stay in English).

Rules specific to this repository:

- Scope B only (verify, decrypt, read and import keys). Do not add signing,
  encryption or key generation without the owner's decision.
- Never write cryptography by hand: everything cryptographic is rPGP's. The
  policy in `rust/src/engine.rs` (algorithms, hashes, validity, limits) is
  ours and is reviewed as security-critical code.
- Dependencies are pinned: `rust/Cargo.lock` is committed and every build
  uses `--locked`; GitHub Actions are pinned by full commit SHA. Run
  `scripts/third_party_licenses.py` after any change to `Cargo.lock`.
- No key material in the repository: tests generate keys at run time.
- Nothing logs. Never install a `log` logger in a process that links this
  library.
- Releases only through the Release workflow, then a reviewed commit that
  sets `version` and `checksum` in `Package.swift`. Never push to `main`
  directly; branch names never contain "claude".
