"""Failure/recovery tests use fake UI/network calls; never alter the host network."""
import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch, Mock

SPEC = importlib.util.spec_from_file_location(
    "offline_pilot", Path(__file__).resolve().parents[1] / "scripts/offline-pilot.py")
pilot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run = Path(self.tmp.name)
        self.plan = dict(ui="/fake/helper", vpn_index=0, vpn_count=2,
                         dns="223.5.5.5", flclash=dict(tun=True, proxy=False))
        self.fl = dict(tun=False, proxy=False)
        self.connected = True
        self.calls = []

    def ui(self, plan, action, *args):
        self.calls.append((action, *args))
        if action == "fl-state":
            return dict(self.fl)
        if action == "fl-set":
            self.fl[args[0]] = args[1] == "on"
            return dict(self.fl)
        raise AssertionError(action)

    def vpn(self, plan, action, *args):
        self.calls.append(("vpn-" + action, *args))
        if action == "set":
            self.connected = args[0] == "on"
        return dict(on=self.connected)

    def recovered(self, vpn=None, dns=None):
        with patch.object(pilot, "ui", side_effect=self.ui), \
             patch.object(pilot, "vpn", side_effect=vpn or self.vpn), \
             patch.object(pilot, "route", side_effect=lambda: "ipsec0" if self.connected else "en0"), \
             patch.object(pilot, "dns", return_value=dns or self.plan["dns"]):
            return pilot.recover(self.run, self.plan)

    def test_restores_saved_states_not_unconditionally_both_on(self):
        (self.run / "vpn-touched").touch()
        (self.run / "relay-touched").touch()
        self.assertTrue(self.recovered())
        self.assertFalse(self.connected)
        self.assertEqual(self.fl, self.plan["flclash"])
        self.assertTrue((self.run / "relay-state/stop").exists())

    def test_vpn_cleanup_failure_does_not_skip_flclash_or_dns(self):
        (self.run / "vpn-touched").touch()
        (self.run / "relay-touched").touch()
        self.assertFalse(self.recovered(vpn=Mock(side_effect=RuntimeError("UI unavailable"))))
        self.assertEqual(self.fl, self.plan["flclash"])
        self.assertTrue((self.run / "relay-state/stop").exists())
        self.assertEqual(json.loads((self.run / "recovered.json").read_text())["errors"],
                         ["disconnect-test-vpn"])

    def test_failed_recovery_can_be_retried_after_ui_recovers(self):
        (self.run / "vpn-touched").touch()
        self.assertFalse(self.recovered(vpn=Mock(side_effect=RuntimeError("locked"))))
        self.assertTrue(self.recovered())
        self.assertFalse(self.connected)

    def test_successful_recovery_is_idempotent(self):
        self.assertTrue(self.recovered())
        calls = len(self.calls)
        self.assertTrue(self.recovered())
        self.assertEqual(len(self.calls), calls)

    def test_never_disconnects_untouched_vpn(self):
        self.assertTrue(self.recovered())
        self.assertFalse(any(c[0].startswith("vpn-") for c in self.calls))

    def test_dns_failure_still_restores_flclash_and_reports_failure(self):
        self.assertFalse(self.recovered(dns="127.0.0.1"))
        self.assertEqual(self.fl, self.plan["flclash"])

    def test_flclash_dns_change_after_verified_relay_cleanup(self):
        (self.run / "relay-touched").touch()
        with patch.object(pilot, "dns", side_effect=[self.plan["dns"], "1.1.1.1"]), \
             patch.object(pilot, "ui", side_effect=self.ui), \
             patch.object(pilot, "route", return_value="utun4"):
            self.assertTrue(pilot.recover(self.run, self.plan))
        self.assertTrue((self.run / "dns-restored").exists())

    def test_engine_restarted_before_tun_and_proxy(self):
        self.plan["cycle_fl_engine"] = True
        (self.run / "engine-stop-sent").touch()
        def start(*args):
            self.calls.append(("start-engine",))

        with patch.object(pilot, "restore_engine", side_effect=start), \
             patch.object(pilot, "verify_proxy_internet") as verify_internet:
            self.assertTrue(self.recovered())

        self.assertEqual(self.calls[:3], [
            ("start-engine",), ("fl-set", "tun", "on"), ("fl-set", "proxy", "off")
        ])
        verify_internet.assert_called_once_with(self.plan)

    def test_engine_cycle_stops_engine_without_toggling_settings(self):
        self.plan.update(cycle_fl_engine=True, device="en6", service="Ethernet", proxy_port=7890)
        relay = Mock()
        relay.poll.return_value = None
        commands = Mock(side_effect=lambda args, **kwargs: {
            "/usr/bin/dig": "1.2.3.4",
            pilot.sys.executable: "{}",
        }.get(args[0], ""))

        def set_ui(plan, action):
            self.calls.append((action,))

        with patch.object(pilot, "command", commands), \
             patch.object(pilot.subprocess, "Popen", return_value=relay), \
             patch.object(pilot, "dns", return_value="127.0.0.1"), \
             patch.object(pilot, "fl_proxy_listening", side_effect=[True, False]), \
             patch.object(pilot, "proxies_off", return_value=True), \
             patch.object(pilot, "route", side_effect=["en6", "en6", "ipsec0", "ipsec0"]), \
             patch.object(pilot, "ui", side_effect=set_ui), \
             patch.object(pilot, "vpn", side_effect=self.vpn), \
             patch.object(pilot, "recover", return_value=True):
            pilot.pilot(self.run, self.plan)

        self.assertEqual(self.calls[:2], [("fl-engine-stop",), ("vpn-set", "on")])
        self.assertTrue((self.run / "engine-stop-sent").exists())

    def test_pilot_cleans_up_after_flclash_toggle_fails(self):
        # Relay readiness succeeds, first proxy mutation fails.
        fake_relay = Mock()
        fake_relay.poll.return_value = None
        commands = lambda args, **kw: "1.2.3.4" if args[0] == "/usr/bin/dig" else ""
        with patch.object(pilot, "command", side_effect=commands), \
             patch.object(pilot.subprocess, "Popen", return_value=fake_relay), \
             patch.object(pilot, "dns", return_value="127.0.0.1"), \
             patch.object(pilot, "ui", side_effect=RuntimeError("toggle failed")), \
             patch.object(pilot, "recover", return_value=True) as recovery:
            with self.assertRaisesRegex(RuntimeError, "toggle failed"):
                pilot.pilot(self.run, self.plan)
        recovery.assert_called_once_with(self.run, self.plan)
        self.assertFalse((self.run / "vpn-touched").exists())

    def test_no_ping_when_puma_never_establishes(self):
        fake_relay = Mock()
        fake_relay.poll.return_value = None
        commands = Mock(side_effect=lambda args, **kw: "1.2.3.4" if args[0] == "/usr/bin/dig" else "")
        def wait(predicate, timeout, message):
            if timeout == 30:
                raise RuntimeError("Puma unavailable; ping unmeasured")
        with patch.object(pilot, "command", commands), \
             patch.object(pilot.subprocess, "Popen", return_value=fake_relay), \
             patch.object(pilot, "wait_for", side_effect=wait), \
             patch.object(pilot, "ui", side_effect=self.ui), \
             patch.object(pilot, "vpn", side_effect=self.vpn), \
             patch.object(pilot, "recover", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "ping unmeasured"):
                pilot.pilot(self.run, self.plan)
        self.assertFalse(any("vpn-ping.py" in str(c) for c in commands.call_args_list))

    def test_watchdog_terminates_worker_before_recovery(self):
        pilot.save(self.run / "plan.json", self.plan)
        order = []
        with patch.object(pilot.os, "kill", side_effect=lambda pid, sig: order.append((pid, sig))), \
             patch.object(pilot.time, "sleep"), \
             patch.object(pilot, "recover", side_effect=lambda *a: order.append("recover")):
            pilot.watchdog(self.run, 12345, 0)
        self.assertEqual(order, [(12345, signal.SIGTERM), (12345, signal.SIGKILL), "recover"])

    def test_watchdog_recovers_when_worker_disappears(self):
        pilot.save(self.run / "plan.json", self.plan)
        with patch.object(pilot.os, "kill", side_effect=ProcessLookupError), \
             patch.object(pilot, "recover", return_value=True) as recovery:
            pilot.watchdog(self.run, 12345, float("inf"))
        recovery.assert_called_once_with(self.run, self.plan)


if __name__ == "__main__":
    unittest.main()
