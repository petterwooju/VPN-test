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

    def test_named_operations_follow_moves_and_only_send_the_expected_name(self):
        name = pilot.TEST_PROFILE
        def inspect(plan, action, *args):
            if action == "vpn-locate":
                self.assertEqual(args, ("0", name))
                return dict(index=4, count=5, on=False)
            if action == "vpn-name-set":
                self.assertEqual(args, ("4", "5", name, "on"))
                return dict(index=2, count=4, on=True)
            self.assertEqual((action, args), ("vpn-name-state", ("2", "4", name)))
            return dict(index=2, count=4, on=True)
        with patch.object(pilot, "ui", side_effect=inspect):
            pilot.resolve_named_slots(self.plan, name)
            pilot.vpn(self.plan, "set", "on")
            self.assertTrue(pilot.vpn(self.plan, "state")["on"])
        self.assertEqual(self.plan["vpn_index"], 2)

    def test_other_names_are_rejected_before_any_click(self):
        with patch.object(pilot, "ui") as ui:
            with self.assertRaises(ValueError):
                pilot.resolve_named_slots(self.plan, "Other")
            with self.assertRaises(RuntimeError):
                pilot.vpn(dict(self.plan, test_profile="Other"), "set", "off")
            ui.assert_not_called()

    def test_batch_manifest_uses_hostnames_only(self):
        host = "hawk.coreavpn.net"
        self.assertEqual(pilot.batch_hosts([{"server": host, "index": 99}]), [{"server": host}])
        self.assertEqual(pilot.batch_hosts([host]), [{"server": host}])
        for invalid in ([host, host], [None], ["other.example"], [], [{}], [False]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                pilot.batch_hosts(invalid)

    def test_connection_change_while_waiting_for_password_stops_before_clicks(self):
        with patch.object(pilot, "route", return_value="ipsec1"), patch.object(pilot, "ui") as ui:
            with self.assertRaisesRegex(RuntimeError, "Network baseline changed"):
                pilot.verify_named_baseline(dict(self.plan, route="utun4", puma_name="Puma"))
            ui.assert_not_called()

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

    def test_retargeted_profile_restores_both_original_fields(self):
        plan = dict(self.plan, test_profile="Test", original_endpoints={
            "server": "lynx.coreavpn.com", "remote_id": "puma.coreavpn.com",
        })
        marker = self.run / "profile-edited"
        marker.touch()
        with patch.object(pilot, "vpn", side_effect=[{}, plan["original_endpoints"]]) as vpn:
            with self.assertRaisesRegex(RuntimeError, "did not match"):
                pilot.restore_test_profile(self.run, plan)
            self.assertTrue(marker.exists())
            pilot.restore_test_profile(self.run, plan)
        vpn.assert_called_with(plan, "retarget", "Test", "lynx.coreavpn.com", "puma.coreavpn.com")
        self.assertFalse(marker.exists())

    def test_batch_recovery_ignores_old_row_numbers(self):
        self.plan.update(test_profile=pilot.TEST_PROFILE, profiles=[{"server": pilot.SERVER}], device="en6")
        active = self.run / "active-profile.json"
        pilot.save(active, {"index": 99, "server": pilot.SERVER})
        with patch.object(pilot, "ui", return_value=dict(index=3, count=5, on=False)) as ui, \
             patch.object(pilot, "route", return_value="en6"):
            pilot.disconnect_batch_profile(self.run, self.plan)
        self.assertEqual([c.args[1:] for c in ui.call_args_list], [
            ("vpn-name-set", "0", "2", pilot.TEST_PROFILE, "off"),
            ("vpn-name-state", "3", "5", pilot.TEST_PROFILE)])
        self.assertFalse(active.exists())

    def test_puma_retargets_the_dedicated_profile_then_restores_on_stop(self):
        name = pilot.TEST_PROFILE
        original = {"server": "lynx.coreavpn.com", "remote_id": "lynx.coreavpn.com"}
        plan = dict(self.plan, test_profile=name, puma_name=name, original_endpoints=original, measurement="icmp",
                    device="en6", service="Ethernet", proxy_port=7890, cycle_fl_engine=True,
                    flclash={"tun": True, "proxy": True})
        endpoints = dict(original)
        engine = True
        self.connected = False
        changes = []
        def ui(_, action, *args):
            nonlocal engine
            if action == "vpn-retarget":
                self.assertEqual(args[2], name)
                self.assertFalse(self.connected)
                endpoints.update(server=args[3], remote_id=args[4])
                changes.append(dict(endpoints))
                return dict(endpoints)
            if action in ("vpn-name-set", "vpn-name-state"):
                self.assertEqual(args[2], name)
                if action == "vpn-name-set":
                    self.connected = args[3] == "on"
                return dict(index=1, count=2, on=self.connected)
            if action in ("fl-engine-stop", "fl-engine-start"):
                engine = action.endswith("start")
                return {}
            if action == "vpn-close-clean":
                self.assertEqual(args, (name,))
                return {}
            return self.ui(plan, action, *args)
        relay = Mock()
        relay.poll.return_value = None
        def route(_=pilot.TARGET):
            return "ipsec3" if self.connected else ("utun2" if engine else "en6")
        def dns(_):
            relay_live = (self.run / "relay-touched").exists() and not (self.run / "relay-state/stop").exists()
            return "127.0.0.1" if relay_live else plan["dns"]
        def stop_measurement(argv, check_stop, timeout):
            self.assertEqual(argv, pilot.ping_probe_args(pilot.SERVER, "ipsec3", self.run))
            self.assertEqual(timeout, pilot.PING_TIMEOUT)
            (self.run / "stop-measurement").touch()
            check_stop()
        with patch.object(pilot, "ui", side_effect=ui), patch.object(pilot, "route", side_effect=route), \
             patch.object(pilot, "dns", side_effect=dns), patch.object(pilot, "command"), \
             patch.object(pilot, "lookup_ipv4", return_value=["1.2.3.4"]), \
             patch.object(pilot, "fl_proxy_listening", side_effect=lambda _: engine), \
             patch.object(pilot, "proxies_off", return_value=True), patch.object(pilot.subprocess, "Popen", return_value=relay), \
             patch.object(pilot, "cancellable_measurement", side_effect=stop_measurement), \
             patch.object(pilot, "speed_peer") as resolve, patch.object(pilot, "verify_stable_proxy") as stable:
            with self.assertRaises(pilot.MeasurementStopped):
                pilot.pilot(self.run, plan)
        self.assertEqual(changes, [{"server": pilot.SERVER, "remote_id": pilot.SERVER}, original])
        self.assertFalse(self.connected)
        self.assertTrue(engine)
        self.assertEqual(self.fl, {"tun": True, "proxy": True})
        self.assertTrue(json.loads((self.run / "recovered.json").read_text())["ok"])
        resolve.assert_not_called()
        stable.assert_called_once()

    def test_system_proxy_has_to_stay_on_after_it_is_reapplied(self):
        self.plan["proxy_port"] = 7890
        now = [0]
        on = "\n".join(f"{kind}{field} : {value}"
                       for kind in ("HTTP", "HTTPS", "SOCKS")
                       for field, value in (("Enable", 1), ("Proxy", "127.0.0.1"), ("Port", 7890)))
        def settings(_):
            return "HTTPEnable : 0" if now[0] == 8 else on

        def advance(seconds):
            now[0] += seconds

        with patch.object(pilot.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(pilot.time, "sleep", side_effect=advance), \
             patch.object(pilot, "command", side_effect=settings), \
             patch.object(pilot, "ui") as change, \
             patch.object(pilot, "verify_fl"), patch.object(pilot, "verify_proxy_internet"):
            pilot.verify_stable_proxy(self.run, self.plan)
        change.assert_called_once_with(self.plan, "fl-set", "proxy", "on")
        self.assertEqual(now[0], 38)

    def test_engine_restarted_before_tun_and_proxy(self):
        self.plan["cycle_fl_engine"] = True
        (self.run / "engine-stop-sent").touch()
        def start(*args):
            self.calls.append(("start-engine",))

        with patch.object(pilot, "restore_engine", side_effect=start), \
             patch.object(pilot, "verify_stable_proxy") as verify_internet:
            self.assertTrue(self.recovered())

        self.assertEqual(self.calls[:3], [
            ("start-engine",), ("fl-set", "tun", "on"), ("fl-set", "proxy", "off")
        ])
        verify_internet.assert_called_once_with(self.run, self.plan)

    def test_engine_click_retried_only_when_no_event_was_sent(self):
        focus_error = RuntimeError("FlClash did not become frontmost; no click sent")
        with patch.object(pilot, "fl_proxy_listening", return_value=False), patch.object(pilot, "wait_for"), \
             patch.object(pilot, "ui", side_effect=[focus_error, RuntimeError("unknown state")]) as ui:
            with self.assertRaisesRegex(RuntimeError, "unknown state"):
                pilot.restore_engine(self.run, self.plan)
            self.assertEqual(ui.call_count, 2)
            pilot.restore_engine(self.run, self.plan)
            self.assertEqual(ui.call_count, 2)

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
             patch.object(pilot, "recover", return_value=True), \
             patch.object(pilot, "measure_speed") as measure:
            pilot.pilot(self.run, self.plan)

        self.assertEqual(self.calls[:2], [("fl-engine-stop",), ("vpn-set", "on")])
        self.assertTrue((self.run / "engine-stop-sent").exists())
        self.assertEqual(measure.call_args.args[:3], (self.run, pilot.SERVER, "ipsec0"))

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

    def test_no_https_measurement_when_puma_never_establishes(self):
        fake_relay = Mock()
        fake_relay.poll.return_value = None
        commands = Mock(side_effect=lambda args, **kw: "1.2.3.4" if args[0] == "/usr/bin/dig" else "")
        def wait(predicate, timeout, message):
            if timeout == 30:
                raise RuntimeError(message)
        with patch.object(pilot, "command", commands), \
             patch.object(pilot.subprocess, "Popen", return_value=fake_relay), \
             patch.object(pilot, "wait_for", side_effect=wait), \
             patch.object(pilot, "ui", side_effect=self.ui), \
             patch.object(pilot, "vpn", side_effect=self.vpn), \
             patch.object(pilot, "recover", return_value=True), \
             patch.object(pilot, "measure_speed") as measure:
            with self.assertRaisesRegex(RuntimeError, "HTTPS measurement unavailable"):
                pilot.pilot(self.run, self.plan)
        measure.assert_not_called()

    def test_https_helper_uses_pinned_peer_and_only_starts_over_correct_route(self):
        peer = "1.2.3.4"
        with patch.object(pilot, "speed_peer", return_value=peer), \
             patch.object(pilot, "route", side_effect=["en6", "ipsec3"]) as route, \
             patch.object(pilot, "command", return_value='{"measurement":"https"}') as execute:
            with self.assertRaisesRegex(RuntimeError, "no route"):
                pilot.measure_speed(self.run, pilot.SERVER, "ipsec3")
            execute.assert_not_called()
            pilot.measure_speed(self.run, pilot.SERVER, "ipsec3")
        self.assertEqual([call.args for call in route.call_args_list], [(peer,), (peer,)])
        args = execute.call_args.args[0]
        self.assertEqual(args[2], str(pilot.SPEED_SCRIPT))
        self.assertEqual(args[3:], ["--server", pilot.SERVER, "--peer-ip", peer,
                                    "--tunnel", "ipsec3", "--log-dir", str(self.run)])
        self.assertEqual(execute.call_args.kwargs["timeout"], pilot.SPEED_TIMEOUT)
        events = [json.loads(s) for s in (self.run / "events.jsonl").read_text().splitlines()]
        self.assertEqual([event["stage"] for event in events], ["https-start", "https-complete"])
        self.assertEqual(events[0]["peer_ipv4"], peer)

    def test_icmp_uses_the_existing_ping_helper_only_on_the_verified_tunnel(self):
        result = {"valid": True, "target": pilot.TARGET, "ping": {"sent": 20, "received": 18}}
        with patch.object(pilot, "route", side_effect=["en6", "ipsec3"]) as route, \
             patch.object(pilot, "speed_peer") as resolve, \
             patch.object(pilot, "cancellable_measurement", return_value=json.dumps(result)) as execute:
            with self.assertRaisesRegex(RuntimeError, "ICMP ping unmeasured"):
                pilot.measure(self.run, pilot.SERVER, "ipsec3", "icmp")
            execute.assert_not_called()
            pilot.measure(self.run, pilot.SERVER, "ipsec3", "icmp")
        self.assertEqual([call.args for call in route.call_args_list], [(pilot.TARGET,), (pilot.TARGET,)])
        resolve.assert_not_called()
        execute.assert_called_once_with(pilot.ping_probe_args(pilot.SERVER, "ipsec3", self.run),
                                        None, pilot.PING_TIMEOUT)
        events = [json.loads(line) for line in (self.run / "events.jsonl").read_text().splitlines()]
        self.assertEqual([event["stage"] for event in events], ["ping-start", "ping-complete"])
        self.assertEqual(events[-1]["result"], result)

    def test_batch_dispatches_to_the_selected_method_for_each_server(self):
        plan = dict(self.plan, device="en6", measurement="icmp",
                    profiles=[{"server": pilot.SERVER}, {"server": "leo.coreavpn.net"}])
        self.connected = False
        with patch.object(pilot, "route", side_effect=lambda: "ipsec3" if self.connected else "en6"), \
             patch.object(pilot, "vpn", side_effect=self.vpn), \
             patch.object(pilot, "retarget_profile"), patch.object(pilot, "lookup_ipv4", return_value=["1.2.3.4"]), \
             patch.object(pilot, "measure") as measure:
            pilot.measure_profiles(self.run, plan)
        self.assertEqual([c.args for c in measure.call_args_list], [
            (self.run, pilot.SERVER, "ipsec3", "icmp"), (self.run, "leo.coreavpn.net", "ipsec3", "icmp")
        ])
        self.assertFalse(self.connected)
        self.assertFalse((self.run / "active-profile.json").exists())

    def test_speed_peer_rejects_synthetic_or_non_public_addresses(self):
        with patch.object(pilot, "command", side_effect=["198.18.1.2", "192.168.1.2", "224.0.0.1", "1.2.3.4"]) as execute:
            for _ in range(3):
                with self.assertRaisesRegex(RuntimeError, "No public IPv4"):
                    pilot.speed_peer()
            self.assertEqual(pilot.speed_peer(), "1.2.3.4")
        self.assertEqual(execute.call_args.args[0][-1], "--resolve-peer")
        self.assertLess(execute.call_args.kwargs["timeout"], pilot.SPEED_TIMEOUT)

    def test_user_stop_enters_recovery_once_and_never_starts_transfer(self):
        self.plan["puma_name"] = "02_B_Puma_KT"
        (self.run / "stop-measurement").touch()
        with patch.object(pilot, "command"), patch.object(pilot, "ui") as ui, \
             patch.object(pilot, "measure_speed") as measure, \
             patch.object(pilot, "recover", return_value=True) as recover:
            with self.assertRaises(pilot.MeasurementStopped):
                pilot.pilot(self.run, self.plan)
        ui.assert_not_called()
        measure.assert_not_called()
        recover.assert_called_once_with(self.run, self.plan)
        events = [json.loads(s)["stage"] for s in (self.run / "events.jsonl").read_text().splitlines()]
        self.assertIn("measurement-stopped", events)

    def test_user_stop_terminates_only_the_measurement_process_group(self):
        checks = Mock(side_effect=[None, pilot.MeasurementStopped()])
        with patch.object(pilot.os, "killpg", wraps=pilot.os.killpg) as kill:
            with self.assertRaises(pilot.MeasurementStopped):
                pilot.cancellable_measurement(["/bin/sleep", "15"], checks, 10)
        pid, sig = kill.call_args.args
        self.assertGreater(pid, 0)
        self.assertEqual(sig, signal.SIGKILL)
        self.assertNotEqual(pid, pilot.os.getpgrp())
        with self.assertRaises(ProcessLookupError):
            pilot.os.kill(pid, 0)

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
