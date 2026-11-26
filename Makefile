# Shortcuts for the commands in README ("Build and test", "Upgrading rPGP").
# CI and the Release workflow run the same commands directly.

.PHONY: check licences upgrade-rpgp

# The CI checks, locally (tests need gpg 2.4; advisories need cargo-deny 0.20.2).
check:
	cd rust && cargo fetch --locked
	cd rust && cargo test --locked --offline
	cd rust && cargo clippy --locked --offline --all-targets -- -D warnings
	scripts/third_party_licenses.py --check
	cd rust && cargo deny check advisories

licences:
	cd rust && cargo fetch --locked
	scripts/third_party_licenses.py

# make upgrade-rpgp               newest stable rPGP on crates.io
# make upgrade-rpgp VERSION=0.22.0
upgrade-rpgp:
	scripts/upgrade_rpgp.py $(VERSION)
