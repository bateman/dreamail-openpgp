"""Tests for the supply-chain checks of upgrade_rpgp.py: the gate that
decides whether an rPGP upgrade may merge by itself.

Run: python3 -m unittest discover -s scripts -p 'test_*.py' -v
"""
import datetime
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("upgrade_rpgp", HERE / "upgrade_rpgp.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def days_ago(days: float) -> str:
    when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    return when.isoformat().replace("+00:00", "Z")


def lock(*packages: tuple[str, str]) -> str:
    return "version = 4\n" + "".join(
        f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n' for name, version in packages)


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(upgrade.time, "sleep")
        patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, old, new, ages):
        def crates_io(path):
            name, version = path.strip("/").split("/")
            return {"version": {"created_at": days_ago(ages[(name, version)])}}
        with mock.patch.object(upgrade, "crates_io", side_effect=crates_io):
            return upgrade.young_or_new_crates(old, new)

    def test_settled_change_passes(self):
        old = lock(("pgp", "0.21.1"), ("aes", "0.8.4"))
        new = lock(("pgp", "0.22.0"), ("aes", "0.8.4"))
        self.assertEqual(self.check(old, new, {("pgp", "0.22.0"): 10}), [])

    def test_young_changed_crate_is_flagged(self):
        old = lock(("pgp", "0.21.1"), ("aes", "0.8.4"))
        new = lock(("pgp", "0.22.0"), ("aes", "0.8.5"))
        problems = self.check(old, new, {("pgp", "0.22.0"): 10, ("aes", "0.8.5"): 2})
        self.assertEqual(problems, [f"`aes` 0.8.5 is younger than {upgrade.COOLDOWN_DAYS} days"])

    def test_new_crate_name_is_flagged_without_a_lookup(self):
        old = lock(("pgp", "0.21.1"))
        new = lock(("pgp", "0.22.0"), ("evil", "1.0.0"))
        self.assertEqual(self.check(old, new, {("pgp", "0.22.0"): 10}), ["`evil` is a new crate"])

    def test_a_second_version_of_a_known_crate_is_checked(self):
        old = lock(("pgp", "0.21.1"), ("rand", "0.8.6"))
        new = lock(("pgp", "0.21.1"), ("rand", "0.8.6"), ("rand", "0.9.0"))
        self.assertEqual(len(self.check(old, new, {("rand", "0.9.0"): 1})), 1)

    def test_newest_settled_version(self):
        versions = [
            {"num": "0.23.0", "yanked": False, "created_at": days_ago(1)},
            {"num": "0.22.1", "yanked": True, "created_at": days_ago(20)},
            {"num": "0.22.0", "yanked": False, "created_at": days_ago(10)},
            {"num": "0.23.0-rc.1", "yanked": False, "created_at": days_ago(30)},
            {"num": "0.21.1", "yanked": False, "created_at": days_ago(40)},
        ]
        with mock.patch.object(upgrade, "crates_io", return_value={"versions": versions}):
            self.assertEqual(upgrade.newest_settled_version(), "0.22.0")


if __name__ == "__main__":
    unittest.main()
