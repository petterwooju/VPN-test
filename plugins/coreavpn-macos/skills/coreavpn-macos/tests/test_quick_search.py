"""Exercise the real multiprocess watchdog using an isolated loopback-free adapter."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/quick-search.py"

FAKE = '''
from pathlib import Path
import json
import time
PROFILE = "CoreaVPN_TEST"

def prepare(run, ui, fl_map, hosts, measurement, operation, expected_device, expected_prefix):
    return {"run": str(run), "mode": str(ui), "measurement": measurement, "operation": operation}

def verify_baseline(plan):
    return

def search(run, plan, cancelled):
    (run / "engine-stop-sent").touch()
    if plan["operation"] == "select":
        return dict(measurement="connection", valid=True, server="leo.coreavpn.net",
                    target="168.126.63.1", tunnel="ipsec4", interface_index=4)
    if plan["operation"] == "all" or plan["mode"] == "empty":
        return None
    if plan["mode"] == "exception":
        raise RuntimeError("Fixture connection failed")
    if plan["mode"] == "probe-in-progress":
        time.sleep(60)
    if plan["mode"] == "editing":
        pending = run / "profile-edit-in-progress"
        pending.touch()
        while not cancelled():
            time.sleep(0.02)
        time.sleep(0.4)
        (run / "sheet-dismissed").touch()
        pending.unlink()
        return None
    if plan["mode"] == "stall":
        while not cancelled():
            time.sleep(0.05)
        return None
    received = 17 if plan["mode"] == "excess-failures" else 18
    if plan["measurement"] == "icmp" and plan["mode"] != "wrong-method":
        return {"valid": True, "measurement": "icmp", "server": "leo.coreavpn.net",
                "target": "168.126.63.1", "tunnel": "ipsec4",
                "ping": {"sent": 20, "received": received, "average_ms": 100, "minimum_ms": 80,
                         "maximum_ms": 125, "loss_pct": 100 * (20 - received) / 20}}
    rate = 9.99 if plan["mode"] == "invalid" else 123
    return {"valid": True, "measurement": "https", "server": "leo.coreavpn.net", "target": "speed.cloudflare.com",
            "peer_ipv4": "104.16.44.99", "tunnel": "ipsec4",
            "speed": {"sent": 20, "received": received, "average_ms": 100.001 if plan["mode"] == "invalid" else 100.0,
                      "download_mbps": rate, "download_seconds": 8 * 400 / (rate * 1000000), "upload_mbps": 24, "download_bytes": 400, "upload_bytes": 500}}

def still_connected(plan, host, tunnel, destination):
    assert destination == ("168.126.63.1" if plan["measurement"] == "icmp" or plan["operation"] == "select" else "104.16.44.99")
    return not (Path(plan["run"]) / "lost-route").exists()

def recover(run, plan):
    (run / "recovered.json").write_text(json.dumps({"ok":True,"errors":[]}))
    return True
'''


class QuickWatchdogChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.run_dir = self.base / "run"
        self.wrapper = self.base / "quick-search.py"
        self.wrapper.write_text(f'''
import importlib.util, sys
from pathlib import Path
sys.path.append({str(SCRIPT.parent)!r})
spec=importlib.util.spec_from_file_location("real_runner", {str(SCRIPT)!r})
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner.SCRIPT=Path(__file__).resolve()
runner.GLOBAL_LOCK=runner.SCRIPT.parent / "fixture.lock"
sys.exit(runner.main())
''')
        (self.base / "quick_candidates.py").write_text(FAKE)
        self.output = (self.base / "test-output").open("w")
        self.addCleanup(self.output.close)

    def start(self, mode, measurement=None, operation="quick"):
        selection = [] if measurement is None else ["--measurement", measurement]
        return subprocess.Popen([sys.executable, "-B", str(self.wrapper), "--log-dir", str(self.run_dir),
                                 "--ui", mode, "--fl-map", "fixture-map", "--hosts", "leo.coreavpn.net",
                                 "--operation", operation, *selection, "--run"],
                                stdin=subprocess.DEVNULL, stdout=self.output, stderr=self.output)

    def state(self):
        return json.loads((self.run_dir / "quick-state.json").read_text())

    def wait_for(self, check):
        end = time.monotonic() + 12
        while time.monotonic() < end:
            if check():
                return
            time.sleep(0.05)
        self.fail("State transition timed out")

    def test_keep_and_release_after_launcher_exits(self):
        self.assertEqual(self.start("win").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "retained")
        self.assertEqual(self.state()["sample"]["speed"]["received"], 18)
        self.assertFalse((self.run_dir / "recovered.json").exists())
        (self.run_dir / "release").touch()
        self.wait_for(lambda: self.state()["phase"] == "released")
        self.assertEqual(self.state()["sample"]["speed"]["average_ms"], 100)
        self.assertTrue(self.state()["recovered"])

    def test_explicit_icmp_method_keeps_and_releases_ping_result(self):
        self.assertEqual(self.start("win", "icmp").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "retained")
        self.assertEqual(self.state()["sample"]["ping"]["loss_pct"], 10)
        plan = json.loads((self.run_dir / "plan.json").read_text())
        self.assertEqual(plan["measurement"], "icmp")
        (self.run_dir / "release").touch()
        self.wait_for(lambda: self.state()["phase"] == "released")
        self.assertTrue(self.state()["recovered"])

    def test_watchdog_does_not_keep_a_result_for_the_other_method(self):
        self.assertNotEqual(self.start("wrong-method", "icmp").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "failed")
        self.assertFalse((self.run_dir / "winner.json").exists())
        self.assertTrue(self.state()["recovered"])

    def test_no_match_restores(self):
        self.assertEqual(self.start("empty").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "no-match")
        self.assertTrue(self.state()["recovered"])

    def test_connection_failure_restores(self):
        self.assertNotEqual(self.start("exception").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "failed")
        self.assertTrue(self.state()["recovered"])

    def test_over_threshold_winner_rejected(self):
        self.assertNotEqual(self.start("invalid").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "failed")
        self.assertFalse((self.run_dir / "winner.json").exists())
        self.assertTrue(self.state()["recovered"])

    def test_fast_retains_valid_download_independently_of_idle_failures(self):
        self.assertEqual(self.start("excess-failures").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "retained")
        (self.run_dir / "release").touch()
        self.wait_for(lambda: self.state()["phase"] == "released")

    def test_all_returns_to_baseline_without_selecting(self):
        self.assertEqual(self.start("batch", operation="all").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "completed")
        self.assertTrue(self.state()["recovered"])
        self.assertFalse((self.run_dir / "winner.json").exists())

    def test_manual_selection_retains_a_connection_without_false_metrics(self):
        self.assertEqual(self.start("manual", operation="select").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "retained")
        self.assertEqual(self.state()["sample"]["measurement"], "connection")
        self.assertNotIn("speed", self.state()["sample"])
        (self.run_dir / "release").touch()
        self.wait_for(lambda: self.state()["phase"] == "released")
        self.assertTrue(self.state()["recovered"])

    def test_release_before_run(self):
        self.run_dir.with_name("run.release").touch()
        self.assertEqual(self.start("stall").wait(timeout=12), 0)
        self.assertEqual(self.state()["phase"], "released")
        self.assertFalse((self.run_dir / "engine-stop-sent").exists())

    def test_stop_while_probe_is_blocked(self):
        for measurement in ("https", "icmp"):
            with self.subTest(measurement=measurement):
                self.run_dir = self.base / ("run-" + measurement)
                proc = self.start("probe-in-progress", measurement)
                self.wait_for(lambda: (self.run_dir / "engine-stop-sent").exists())
                self.run_dir.with_name(self.run_dir.name + ".release").touch()
                self.assertEqual(proc.wait(timeout=8), 0)
                self.assertEqual(self.state()["phase"], "released")
                self.assertTrue(self.state()["recovered"])
                self.assertFalse((self.run_dir / "winner.json").exists())

    def test_stop_allows_already_open_endpoint_edit_to_settle(self):
        proc = self.start("editing")
        self.wait_for(lambda: (self.run_dir / "profile-edit-in-progress").exists())
        self.run_dir.with_name("run.release").touch()
        self.assertEqual(proc.wait(timeout=8), 0)
        self.assertTrue((self.run_dir / "sheet-dismissed").exists())
        self.assertEqual(self.state()["phase"], "released")
        self.assertTrue(self.state()["recovered"])

    def test_search_owner_dies(self):
        proc = self.start("stall")
        self.wait_for(lambda: (self.run_dir / "engine-stop-sent").exists())
        proc.kill()
        proc.wait(timeout=5)
        self.wait_for(lambda: self.state()["phase"] == "failed")
        self.assertTrue(self.state()["recovered"])

    def test_worker_dies_while_retained(self):
        import os
        self.assertEqual(self.start("win").wait(timeout=12), 0)
        worker = json.loads((self.run_dir / "worker-group.json").read_text())["pid"]
        os.kill(worker, signal.SIGKILL)
        self.wait_for(lambda: self.state()["phase"] == "failed")
        self.assertTrue(self.state()["recovered"])

    def test_guardian_dies_while_retained(self):
        import os
        self.assertEqual(self.start("win").wait(timeout=12), 0)
        guardian = int((self.run_dir / "watchdog-ready").read_text())
        os.kill(guardian, signal.SIGKILL)
        self.wait_for(lambda: self.state()["phase"] == "failed")
        self.assertTrue(self.state()["recovered"])

    def test_route_loss_after_handoff(self):
        self.assertEqual(self.start("win").wait(timeout=12), 0)
        (self.run_dir / "lost-route").touch()
        self.wait_for(lambda: self.state()["phase"] == "failed")
        self.assertTrue(self.state()["recovered"])


if __name__ == "__main__":
    unittest.main()
