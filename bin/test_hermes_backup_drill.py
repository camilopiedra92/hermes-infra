"""The restore drill proves a snapshot can be opened: databases pass the integrity check and no secret is inside."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "infra" / "ansible" / "roles" / "backup" / "files" / "hermes-backup"
STATE = Path("/home/agent/.hermes")


def load(work: Path):
    os.environ["HERMES_BACKUP_STATES"] = str(STATE)
    os.environ["HERMES_BACKUP_WORK"] = str(work)
    loader = importlib.machinery.SourceFileLoader("hermes_backup", str(SCRIPT))
    spec = importlib.util.spec_from_loader("hermes_backup", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def restore_into(extra: dict[str, bytes], with_database: bool = True):
    def fake(env, *args, capture=False):  # noqa: ANN001, ARG001
        target = Path(args[args.index("--target") + 1])
        root = target / str(STATE).lstrip("/")
        root.mkdir(parents=True)
        if with_database:
            db = sqlite3.connect(root / "state.db")
            db.execute("create table t (x)")
            db.commit()
            db.close()
        for name, data in extra.items():
            (root / name).write_bytes(data)
        return ""

    return fake


class RestoreDrillTests(unittest.TestCase):
    def run_drill(self, fake) -> tuple[int, dict]:
        with tempfile.TemporaryDirectory() as tmp:
            module = load(Path(tmp))
            with mock.patch.object(module, "restic", fake), mock.patch.object(module, "load_env", return_value={}):
                code = module.run_drill()
            self.assertEqual(list(Path(tmp).glob("drill-*")), [], "the scratch directory must be removed")
            return code, json.loads((Path(tmp) / "drill.json").read_text(encoding="utf-8"))

    def test_a_clean_snapshot_passes(self) -> None:
        code, status = self.run_drill(restore_into({"config.yaml": b"x: 1\n"}))
        self.assertEqual(code, 0)
        self.assertTrue(status["ok"])
        self.assertEqual(status["databases"], 1)

    def test_a_secret_file_in_the_snapshot_fails(self) -> None:
        code, status = self.run_drill(restore_into({".env": b"TELEGRAM_BOT_TOKEN=x\n"}))
        self.assertEqual(code, 1)
        self.assertIn("secret file", status["problems"][0])

    def test_a_corrupt_database_fails(self) -> None:
        code, status = self.run_drill(restore_into({"broken.db": b"not a database" * 100}))
        self.assertEqual(code, 1)
        self.assertTrue(any("integrity check failed" in p for p in status["problems"]))

    def test_a_snapshot_without_databases_fails(self) -> None:
        code, status = self.run_drill(restore_into({}, with_database=False))
        self.assertEqual(code, 1)
        self.assertIn("no database", " ".join(status["problems"]))

    def test_a_restore_error_is_reported_not_raised(self) -> None:
        def broken(env, *args, capture=False):  # noqa: ANN001, ARG001
            raise RuntimeError("repository unreachable")

        code, status = self.run_drill(broken)
        self.assertEqual(code, 1)
        self.assertIn("repository unreachable", status["problems"][0])


if __name__ == "__main__":
    unittest.main()
