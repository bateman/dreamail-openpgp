# Project instructions

This repository is part of DreaMail (https://github.com/bateman/dreamail): the
OpenPGP engine it links as a prebuilt `binaryTarget`. DreaMail's `CLAUDE.md`
applies here too: communication style, review tiers, the owner writes in
Italian (answer in Italian; code, commits and documents stay in English).

Reviews follow DreaMail's tiers, before the merge, with the skills in
`.claude/skills` (copied from DreaMail): `ponytail-review` in `full` mode,
and for a Standard change the `security-audit` in parallel. Almost every
change here is Standard (CI, dependencies, release, `engine.rs`).

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
- Releases only through the Release workflow, then the commit that sets
  `version` and `checksum` in `Package.swift`. Never push to `main`
  directly; branch names never contain "claude".
- rPGP upgrades and their release are automatic (owner's decision, 26
  November 2026): the Upgrade rPGP workflow merges an upgrade that passes
  every check without review, and the Release workflow merges the
  `Package.swift` pull request once CI passes. Any other change, `engine.rs`
  included, is still reviewed.
