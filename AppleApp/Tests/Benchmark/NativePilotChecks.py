"""Offline fault tests; no calls to the real macOS VPN, AX, network, or network settings."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

module = Path(__file__).resolve().parents[2] / "Tools/native-puma-pilot.py"
spec = importlib.util.spec_from_file_location("native_pilot", module)
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


class NativePilotChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.run_dir = Path(temporary.name)
        self.plan = dict(route="utun4", device="en6", service="USB LAN", dns="automatic")
        self.commands = []
        self.physical = False

        def native(plan, command, *args, **kwargs):
            self.commands.append(command)
            if command == "--pilot-puma":
                return {"ok": True, "sent": 20, "received": 18}
            return {"ok": True}

        def ui(plan, command):
            if command == "fl-engine-stop":
                self.physical = True

        def restore(run, plan):
            self.physical = False
            self.commands.append("fl-restore")
            return True

        for obj, name, replacement in (
            (pilot, "app_command", native), (pilot.legacy, "ui", ui),
            (pilot.legacy, "route", lambda: "en6" if self.physical else "utun4"),
            (pilot.legacy, "dns", lambda _: "automatic"),
            (pilot.legacy, "verify_fl", lambda _: None),
            (pilot.legacy, "fl_proxy_listening", lambda _: not self.physical),
            (pilot.legacy, "proxies_off", lambda: self.physical),
            (pilot.legacy, "recover", restore),
            (pilot.legacy, "verify_proxy_internet", lambda _: self.commands.append("https-ok")),
        ):
            active = patch.object(obj, name, replacement)
            active.start()
            self.addCleanup(active.stop)

    def test_normal(self):
        pilot.worker(self.run_dir, self.plan)
        self.assertTrue(pilot.recover(self.run_dir, self.plan))
        self.assertEqual(self.commands, ["--pilot-ready", "--pilot-puma", "fl-restore", "--pilot-ready", "https-ok"])
        self.assertEqual(json.loads((self.run_dir / "native-ping.json").read_text())["received"], 18)

    def test_worker_dies_before_restoration(self):
        for marker in ("engine-stop-sent", "native-vpn-touched"):
            (self.run_dir / marker).touch()
        self.physical = True
        self.assertTrue(pilot.recover(self.run_dir, self.plan))
        self.assertEqual(self.commands, ["--pilot-disconnect", "fl-restore", "--pilot-ready", "https-ok"])

    def test_native_failure_does_not_skip_flclash(self):
        for marker in ("engine-stop-sent", "native-vpn-touched"):
            (self.run_dir / marker).touch()
        self.physical = True
        with patch.object(pilot, "app_command", side_effect=ValueError("simulated access failure")):
            self.assertFalse(pilot.recover(self.run_dir, self.plan))
        self.assertIn("fl-restore", self.commands)
        self.assertFalse((self.run_dir / "native-restored").exists())

    def test_early_failure_keeps_engine_running(self):
        with patch.object(pilot, "app_command", side_effect=ValueError("preflight")):
            with self.assertRaisesRegex(ValueError, "preflight"):
                pilot.worker(self.run_dir, self.plan)
        self.assertFalse((self.run_dir / "engine-stop-sent").exists())
        self.assertFalse(self.physical)


if __name__ == "__main__":
    unittest.main()
