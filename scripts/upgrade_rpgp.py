#!/usr/bin/env python3
"""Upgrades rPGP (crate `pgp`) to a new release: the mechanical part of the
procedure in README, "Upgrading rPGP". Nothing is committed: the result is a
working tree for review.

Steps:
  1. Checks a clean tree, then asks crates.io for the release (the newest
     stable one if no version is given): not yanked, MSRV within the pinned
     toolchain.
  2. Switches to branch deps/rpgp-<version> if on main.
  3. Sets the exact pin in rust/Cargo.toml, runs `cargo update -p pgp
     --precise`, and checks the lockfile checksum against crates.io.
  4. Reads the git tag v<version> from the rPGP repository (tag object and
     commit).
  5. Regenerates THIRD_PARTY_LICENSES.md and updates README's "What is
     pinned" rows.
  6. Runs the CI checks: tests, clippy, licences, advisories.
  7. Writes build/rpgp-upgrade-<version>.md: lockfile changes, check
     results, and what needs human review (changelog, policy in engine.rs,
     remaining mentions of the old version).

Usage: scripts/upgrade_rpgp.py [VERSION] [--allow-dirty]
Exit status: 0 if every check passed (or rPGP is already at that version),
1 if the upgrade was made but a check failed (the tree is left as is, to be
fixed on the branch), 2 if it could not be made (yanked, MSRV, no tag...).
The Upgrade rPGP workflow runs this weekly and opens a pull request.
Standard library only.
"""
import datetime
import json
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "rust"
CARGO_TOML = CRATE / "Cargo.toml"
CARGO_LOCK = CRATE / "Cargo.lock"
TOOLCHAIN = CRATE / "rust-toolchain.toml"
README = ROOT / "README.md"
REPO = "https://github.com/rpgp/rpgp"
CRATES_API = "https://crates.io/api/v1/crates/pgp"
# crates.io asks automated clients for a User-Agent; a generic one.
USER_AGENT = "rpgp-upgrade-script"
DENY_VERSION = "0.20.2"
PIN = re.compile(r'^(pgp = \{ version = "=)([^"]+)(")', re.M)
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def run(cmd: list[str], cwd: Path = ROOT, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=capture)


def out(cmd: list[str], cwd: Path = ROOT) -> str:
    result = run(cmd, cwd)
    if result.returncode:
        fail(f"{' '.join(cmd)} failed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def crates_io(path: str = "") -> dict:
    request = urllib.request.Request(CRATES_API + path, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def lock_packages(text: str) -> dict[str, set[str]]:
    packages: dict[str, set[str]] = {}
    for package in tomllib.loads(text).get("package", []):
        packages.setdefault(package["name"], set()).add(package["version"])
    return packages


def lock_diff(old: str, new: str) -> list[str]:
    before, after = lock_packages(old), lock_packages(new)
    lines = []
    for name in sorted(before.keys() | after.keys()):
        was, now = before.get(name, set()), after.get(name, set())
        if was == now:
            continue
        if not was:
            lines.append(f"- added `{name}` {', '.join(sorted(now))}")
        elif not now:
            lines.append(f"- removed `{name}` {', '.join(sorted(was))}")
        else:
            lines.append(f"- `{name}` {', '.join(sorted(was))} -> {', '.join(sorted(now))}")
    return lines


def git_tag(version: str) -> tuple[str, str]:
    tag = f"refs/tags/v{version}"
    refs = dict(reversed(line.split("\t")) for line in
                out(["git", "ls-remote", REPO, tag, tag + "^{}"]).splitlines())
    if tag not in refs:
        fail(f"rPGP has no git tag v{version}")
    # A lightweight tag has no peeled entry: the tag names the commit itself.
    return refs[tag], refs.get(tag + "^{}", refs[tag])


def replace_once(text: str, pattern: str, replacement: str, what: str) -> str:
    new, count = re.subn(pattern, replacement, text, flags=re.M)
    if count != 1:
        fail(f"README: expected one {what}, found {count}; update the script or the README")
    return new


def update_readme(version: str, date: str, licence: str, checksum: str,
                  tag_object: str, commit: str, locked: int, linked: int) -> None:
    text = README.read_text(encoding="utf-8")
    text = replace_once(
        text, r"^\| rPGP \| crate `pgp` `=[^`]+` \(crates\.io, [^)]+\), .+ \|$",
        f"| rPGP | crate `pgp` `={version}` (crates.io, {date}), {licence} |", "rPGP row")
    text = replace_once(
        text, r"^(\| rPGP crate checksum .+\| )`[0-9a-f]{64}`( \|)$",
        rf"\g<1>`{checksum}`\g<2>", "checksum row")
    text = replace_once(
        text, r"^\| rPGP git tag `v[^`]+` \| .+ \|$",
        f"| rPGP git tag `v{version}` | tag object `{tag_object}`, commit `{commit}` |", "git tag row")
    text = replace_once(
        text, r"rpgp/rpgp/blob/[0-9a-f]{40}/docs/SECURITY_STATUS\.md",
        f"rpgp/rpgp/blob/{commit}/docs/SECURITY_STATUS.md", "SECURITY_STATUS link")
    text = replace_once(
        text, r"\(\d+ packages including test-only ones; \d+ linked into the macOS library\)",
        f"({locked} packages including test-only ones; {linked} linked into the macOS library)",
        "package counts")
    README.write_text(text, encoding="utf-8")


def check(name: str, cmd: list[str], cwd: Path = CRATE) -> tuple[str, bool]:
    print(f"==> {name}: {' '.join(cmd)}", flush=True)
    ok = run(cmd, cwd, capture=False).returncode == 0
    return name, ok


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    allow_dirty = "--allow-dirty" in argv
    if len(args) > 1 or set(argv) - set(args) - {"--allow-dirty"}:
        fail("usage: scripts/upgrade_rpgp.py [VERSION] [--allow-dirty]")

    for tool in ("git", "cargo", "gpg"):
        if not shutil.which(tool):
            fail(f"{tool} is not on PATH")
    # 1. The release, as crates.io describes it.
    manifest = CARGO_TOML.read_text(encoding="utf-8")
    pin = PIN.search(manifest)
    if not pin:
        fail("no exact `pgp` pin found in rust/Cargo.toml")
    old = pin.group(2)
    version = args[0] if args else crates_io()["crate"]["max_stable_version"]
    if not SEMVER.match(version):
        fail(f"not a stable MAJOR.MINOR.PATCH version: {version}")
    if version == old:
        print(f"rPGP is already at {old}: nothing to do.")
        return 0
    if not allow_dirty and out(["git", "status", "--porcelain"]):
        fail("the working tree has changes; commit or stash them first")
    info = crates_io(f"/{version}")["version"]
    if info["yanked"]:
        fail(f"pgp {version} is yanked on crates.io")
    toolchain = tomllib.loads(TOOLCHAIN.read_text(encoding="utf-8"))["toolchain"]["channel"]
    if info.get("rust_version") and version_tuple(info["rust_version"]) > version_tuple(toolchain):
        fail(f"pgp {version} needs Rust {info['rust_version']}, the pinned toolchain is "
             f"{toolchain}: raise rust/rust-toolchain.toml (and rust-version) first")
    date = datetime.date.fromisoformat(info["created_at"][:10])
    date_text = f"{date.day} {date:%B %Y}"
    tag_object, commit = git_tag(version)
    print(f"Upgrading rPGP {old} -> {version} (crates.io {date_text}, commit {commit})")

    # 2. A branch for the change, never main.
    branch = out(["git", "branch", "--show-current"])
    if branch in ("main", "master", ""):
        branch = f"deps/rpgp-{version}"
        out(["git", "switch", "-c", branch])
        print(f"Switched to new branch {branch}")

    # 3. Pin and lockfile.
    old_lock = CARGO_LOCK.read_text(encoding="utf-8")
    CARGO_TOML.write_text(PIN.sub(rf"\g<1>{version}\g<3>", manifest, count=1), encoding="utf-8")
    out(["cargo", "update", "-p", "pgp", "--precise", version], CRATE)
    new_lock = CARGO_LOCK.read_text(encoding="utf-8")
    lock = tomllib.loads(new_lock)["package"]
    pgp = [p for p in lock if p["name"] == "pgp"]
    if len(pgp) != 1 or pgp[0]["version"] != version:
        fail(f"Cargo.lock does not hold exactly pgp {version}")
    if pgp[0].get("checksum") != info["checksum"]:
        fail(f"Cargo.lock checksum {pgp[0].get('checksum')} differs from crates.io {info['checksum']}")

    # 5. Licences and README.
    out(["cargo", "fetch", "--locked"], CRATE)
    licences = out([sys.executable, str(ROOT / "scripts" / "third_party_licenses.py")])
    print(licences)
    linked = int(re.search(r"(\d+) crates", licences).group(1))
    update_readme(version, date_text, info.get("license") or "?", info["checksum"],
                  tag_object, commit, len(lock) - 1, linked)

    # 6. The CI checks.
    results = [
        check("tests", ["cargo", "test", "--locked", "--offline"]),
        check("clippy", ["cargo", "clippy", "--locked", "--offline", "--all-targets", "--", "-D", "warnings"]),
        check("licences", [sys.executable, str(ROOT / "scripts" / "third_party_licenses.py"), "--check"]),
    ]
    deny = run(["cargo", "deny", "--version"])
    if deny.returncode == 0 and DENY_VERSION in deny.stdout:
        results.append(check("advisories", ["cargo", "deny", "check", "advisories"]))
    else:
        print(f"==> advisories: cargo-deny {DENY_VERSION} not installed, not run "
              f"(cargo install cargo-deny --locked --version {DENY_VERSION})")
        results.append(("advisories (not run: cargo-deny missing)", False))

    # 7. Report.
    mentions = []
    for path in (README, CARGO_TOML, CRATE / "deny.toml", *sorted((CRATE / "src").rglob("*.rs")),
                 *sorted((CRATE / "tests").rglob("*.rs"))):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if old in line:
                mentions.append(f"- `{path.relative_to(ROOT)}:{number}`: {line.strip()}")
    report = [
        f"# rPGP {old} -> {version}",
        "",
        f"- crates.io: {date_text}, checksum `{info['checksum']}`, licence {info.get('license')}",
        f"- git tag `v{version}`: tag object `{tag_object}`, commit `{commit}`",
        f"- changes: {REPO}/compare/v{old}...v{version} and {REPO}/blob/{commit}/CHANGELOG.md",
        "",
        "## Checks",
        "",
        *[f"- [{'x' if ok else ' '}] {name}" for name, ok in results],
        "",
        "## Cargo.lock",
        "",
        *(lock_diff(old_lock, new_lock) or ["- only `pgp` changed"]),
        "",
        "## Needs human review",
        "",
        "- [ ] rPGP changelog: API changes, security fixes, new or removed dependencies",
        "- [ ] `rust/src/engine.rs` policy still holds (algorithms, hashes, validity, limits, "
        "error mapping: typed vs untyped errors, `enable_gnupg_aead`)",
        "- [ ] `cx448` still mandatory? Ed448/X448 refusal unchanged",
        "- [ ] SEIPD v2 AEAD-octet underflow (`rust/Cargo.toml` comment, README) fixed or not",
        "- [ ] `rust/deny.toml` ignores still needed (rsa, crypto-bigint); README known limits",
        "- [ ] new crates: licence files, licences/README.md if supplied from upstream",
        "- [ ] SECURITY_STATUS at the new commit: audits unchanged",
        "",
        "### Remaining mentions of the old version",
        "",
        *(mentions or ["- none"]),
        "",
    ]
    report_path = ROOT / "build" / f"rpgp-upgrade-{version}.md"
    report_path.parent.mkdir(exist_ok=True)
    report_path.write_text("\n".join(report), encoding="utf-8")

    failed = [name for name, ok in results if not ok]
    print(f"\nReport: {report_path.relative_to(ROOT)} (branch {branch}, nothing committed)")
    if failed:
        print("Failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("All checks passed. Review the report, then commit and open a PR.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
