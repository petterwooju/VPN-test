import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import quick_candidates as quick


PEER = "104.16.44.99"


def result(host, mean=100, received=20, rate=12.3):
    return dict(valid=True, measurement="https", server=host, target="speed.cloudflare.com",
                peer_ipv4=PEER, tunnel="ipsec4",
                speed=dict(sent=20, received=received, average_ms=mean, download_mbps=rate, download_seconds=8 * 400 / (1_000_000 * rate), upload_mbps=5.6,
                           download_loaded_ms=115, upload_loaded_ms=212, download_bytes=400, upload_bytes=300))


def ping_result(host, mean=100, received=20):
    return dict(valid=True, server=host, target=quick.pilot.TARGET, tunnel="ipsec4",
                ping=dict(sent=20, received=received, average_ms=mean, minimum_ms=50, maximum_ms=120,
                          loss_pct=100 * (20 - received) / 20))


class QuickCandidatesTests(unittest.TestCase):
    def test_d_and_e_use_their_official_hostnames_without_the_net_resolver(self):
        direct = [host for host in quick.CATALOG if not host.endswith(".net")]
        self.assertEqual(sum(host.endswith(".com") for host in direct), 4)
        self.assertEqual(sum(host.endswith(".kr") for host in direct), 2)
        self.assertEqual(quick.candidate_order(direct), direct)
        with patch.object(quick.pilot, "command", side_effect=AssertionError("Unexpected .net lookup")):
            for host in direct:
                with self.subTest(host=host):
                    self.assertEqual(quick.endpoint({}, host), host)

    def test_non_ui_health_and_reused_tunnel_name(self):
        plan = dict(device="en6", service="Ethernet", physical_address="10.0.1.2", tunnel_index=7)
        with patch.object(quick.pilot, "route", return_value="ipsec4") as route, \
             patch.object(quick.socket, "if_nametoindex", return_value=7) as index, \
             patch.dict(quick.uplink, active_device=Mock(return_value="en6")), \
             patch.object(quick, "uplink_address", return_value="10.0.1.2") as uplink, \
             patch.object(quick.pilot, "ui", side_effect=AssertionError("Settings must not be opened")), \
             patch.object(quick.pilot, "fl_proxy_listening", return_value=False):
            self.assertTrue(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))
            route.assert_called_once_with(PEER)
            index.return_value = 11
            self.assertFalse(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))
            index.return_value = 7
            quick.uplink["active_device"].return_value = "en0"
            self.assertFalse(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))
            quick.uplink["active_device"].return_value = None
            self.assertTrue(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))
            uplink.return_value = "10.0.2.3"
            self.assertFalse(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))
            uplink.return_value = "10.0.1.2"
            route.return_value = "en6"
            self.assertFalse(quick.still_connected(plan, quick.LEO, "ipsec4", PEER))

    def test_profile_preparation_only_reads_current_name_and_keeps_validated_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run = base / "first"
            ui, resolver, fl_map = (base / name for name in ("ui", "quick-resolve", "fl-map.json"))
            for file in (ui, resolver, fl_map):
                file.touch(mode=0o700)
            hints = []
            def locate(plan, name, excluded):
                self.assertEqual(name, "CoreaVPN_TEST")
                self.assertIsNone(excluded)
                hints.append(plan["vpn_index"])
                plan.update(vpn_index=3, vpn_count=6)
            with patch.object(quick.pilot, "resolve_named_slots", side_effect=locate), \
                 patch.object(quick.pilot, "ui", return_value={"named_profiles": True}), \
                 patch.dict(quick.uplink, active_link=lambda: ("en6", "Ethernet")), \
                 patch.object(quick, "uplink_address", return_value="10.0.1.2"), \
                 patch.object(quick.pilot, "route", return_value="utun3"), \
                 patch.object(quick.pilot, "dns", return_value="DHCP"), \
                 patch.object(quick.pilot, "verify_fl"), patch.object(quick.pilot, "verify_proxy_internet"), \
                 patch.object(quick.pilot, "vpn", return_value={"server": quick.LEO, "remote_id": quick.LEO}) as vpn:
                with self.assertRaisesRegex(RuntimeError, "physical subnet changed"):
                    quick.prepare(run, ui, fl_map, [quick.LEO], expected_prefix="192.168.5.0/24")
                plan = quick.prepare(run, ui, fl_map, [quick.LEO], expected_prefix="10.0.1.0/24")
                vpn.assert_called_once_with(plan, "endpoints", "CoreaVPN_TEST")
                self.assertEqual(plan["measurement"], "https")
                self.assertNotIn("verify_off_vpn", plan)
                second = quick.prepare(base / "second", ui, fl_map, [quick.LEO], "icmp")
                self.assertEqual(second["measurement"], "icmp")
                self.assertEqual(hints, [9, 3])

    def test_recovery_keeps_flclash_independent_of_an_unverifiable_historical_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            for marker in ("active-profile.json", "profile-edited", "engine-stop-sent"):
                (run / marker).touch()
            legacy = dict(test_profile="CoraVPN_TEST", quick_search=True, verify_off_vpn=["10", "E_VENUS"],
                          profiles=[{"server": quick.LEO}], original_endpoints={"server": quick.LEO, "remote_id": quick.LEO},
                          cycle_fl_engine=True, flclash={"tun": True, "proxy": True})
            with patch.object(quick.pilot, "restore_engine") as engine, \
                 patch.object(quick.pilot, "ui", return_value=legacy["flclash"]) as ui, \
                 patch.object(quick.pilot, "verify_stable_proxy") as internet, \
                 patch.object(quick.pilot, "verify_dns"), patch.object(quick.pilot, "route", return_value="utun2"), \
                 patch.object(quick.pilot, "fl_proxy_listening", return_value=True):
                self.assertFalse(quick.recover(run, legacy))
            self.assertEqual(engine.call_count, 1)
            self.assertEqual(internet.call_count, 1)
            self.assertEqual([c.args[1:] for c in ui.call_args_list],
                             [("fl-set", "tun", "on"), ("fl-set", "proxy", "on"), ("fl-state",)])
            self.assertTrue((run / "profile-edited").exists())
            self.assertIn("disconnect-test-vpn", json.loads((run / "recovered.json").read_text())["errors"])

    def test_eligible_hosts_and_cutoff(self):
        other = "puma.coreavpn.net"
        self.assertEqual(quick.candidate_order([other, quick.LEO]), [quick.LEO, other])
        self.assertEqual(quick.candidate_order([other]), [other])
        with self.assertRaises(ValueError):
            quick.candidate_order(["unknown.coreavpn.net"])
        for rate, eligible in ((10, True), (9.99, False), (12, True)):
            with self.subTest(rate=rate):
                sample = result(other, mean=150, received=1, rate=rate)
                sample["speed"].update(upload_mbps=None, upload_bytes=0)
                self.assertEqual(quick.qualifies(sample, [other], "ipsec4"), eligible)
        self.assertFalse(quick.qualifies(result(other), [quick.LEO], "ipsec4"))
        self.assertFalse(quick.qualifies(result(other), [other], "ipsec5"))

    def test_incomplete_or_inconsistent_sample_does_not_qualify(self):
        for speed in ({"download_bytes": 0}, {"download_mbps": -1}, {"download_mbps": float("inf")},
                      {"download_mbps": 21}, {"download_seconds": 0}, {"download_seconds": None}):
            with self.subTest(speed=speed):
                sample = result(quick.LEO, received=18)
                sample["speed"].update(speed)
                self.assertFalse(quick.qualifies(sample, [quick.LEO]))
        self.assertFalse(quick.qualifies(dict(result(quick.LEO), peer_ipv4="198.18.0.1"), [quick.LEO]))

    def test_icmp_requires_matching_target_counts_loss_and_latency(self):
        for mean, received, eligible in ((100, 18, True), (100.001, 18, False), (80, 17, False)):
            with self.subTest(mean=mean, received=received):
                sample = ping_result(quick.LEO, mean, received)
                self.assertEqual(quick.qualifies(sample, [quick.LEO], "ipsec4", measurement="icmp"), eligible)
        sample = ping_result(quick.LEO, received=18)
        self.assertFalse(quick.qualifies(sample, [quick.LEO], measurement="https"))
        self.assertFalse(quick.qualifies(result(quick.LEO), [quick.LEO], measurement="icmp"))
        self.assertFalse(quick.qualifies(dict(sample, target=PEER), [quick.LEO], measurement="icmp"))
        self.assertFalse(quick.qualifies(dict(sample, measurement="https"), [quick.LEO], measurement="icmp"))
        sample["ping"]["loss_pct"] = 5
        self.assertFalse(quick.qualifies(sample, [quick.LEO], measurement="icmp"))

    def test_stop_while_claiming_edit_prevents_any_profile_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            plan = {"device": "en6", "profiles": [{"server": quick.LEO}]}
            pending = run / "profile-edit-in-progress"
            with patch.object(quick.pilot, "ui"), patch.object(quick.pilot, "route", return_value="en6"), \
                 patch.object(quick.pilot, "fl_proxy_listening", return_value=False), \
                 patch.object(quick.pilot, "proxies_off", return_value=True), \
                 patch.object(quick, "same_uplink", return_value=True), \
                 patch.object(quick, "endpoint", return_value="8.8.8.8"), \
                 patch.object(quick.pilot, "retarget_profile") as edit:
                self.assertIsNone(quick.search(run, plan, cancelled=pending.exists))
            edit.assert_not_called()
            self.assertFalse(pending.exists())
            self.assertFalse((run / "profile-edited").exists())

    def test_failed_requests_advance_but_winning_tunnel_stays_up(self):
        for measurement in ("https", "icmp"):
            with self.subTest(measurement=measurement):
                self.check_failed_measurement_and_retained_tunnel(measurement)

    def paired_fixture(self, ping_payload, fast_payload):
        host = quick.LEO
        connected = False
        calls = []
        def vpn(plan, action, *args):
            nonlocal connected
            if action == "set":
                connected = args[0] == "on"
                calls.append(args[0])
            return {"on": connected}
        def ping_cmd(argv, timeout, check=True):
            calls.append("ping")
            return json.dumps(ping_payload)
        def https(server, peer, tunnel, download_checkpoint, idle_checkpoint):
            calls.append("https")
            if fast_payload["valid"]:
                partial = dict(fast_payload, speed=dict(fast_payload["speed"], upload_mbps=None))
                idle_checkpoint(dict(fast_payload, speed=dict(partial["speed"], download_mbps=None)))
                download_checkpoint(partial)
            return fast_payload
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            plan = dict(operation="all", device="en6", profiles=[dict(server=host)])
            with patch.object(quick.pilot, "ui"), patch.object(quick.pilot, "vpn", side_effect=vpn), \
                 patch.object(quick, "same_uplink", return_value=True), \
                 patch.object(quick.socket, "if_nametoindex", return_value=7), \
                 patch.object(quick.pilot, "route", side_effect=lambda *_: "ipsec4" if connected else "en6"), \
                 patch.object(quick.pilot, "speed_peer", return_value=PEER), \
                 patch.object(quick.pilot, "fl_proxy_listening", return_value=False), \
                 patch.object(quick.pilot, "proxies_off", return_value=True), \
                 patch.object(quick, "endpoint", return_value="8.8.8.8"), \
                 patch.object(quick.pilot, "retarget_profile"), \
                 patch.object(quick.pilot, "command", side_effect=ping_cmd), \
                 patch.object(quick.https_speed, "measure", side_effect=https):
                self.assertIsNone(quick.search(run, plan))
            self.assertFalse(connected)
            self.assertEqual(calls, ["on", "ping", "https", "off"])
            return [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]

    def test_paired_probes_share_one_connection_and_zero_icmp_does_not_skip_fast(self):
        ping = ping_result(quick.LEO, None, 0)
        ping["ping"].update(minimum_ms=None, maximum_ms=None)
        stages = [event["stage"] for event in self.paired_fixture(ping, result(quick.LEO))]
        self.assertLess(stages.index("ping-complete"), stages.index("https-idle-complete"))
        self.assertLess(stages.index("https-idle-complete"), stages.index("https-download-complete"))
        self.assertLess(stages.index("https-download-complete"), stages.index("https-complete"))
        self.assertEqual(stages.count("server-connected"), 1)
        self.assertEqual(stages.count("server-finished"), 1)

    def test_paired_scan_preserves_independent_failures_and_rejects_cross_host_evidence(self):
        for ping, fast, failed, succeeded in (
                (ping_result("titan.coreavpn.net"), result(quick.LEO), "icmp", "https-complete"),
                (ping_result(quick.LEO), {"valid": False, "error": "HTTPS unavailable"}, "https", "ping-complete")):
            with self.subTest(failed=failed):
                events = self.paired_fixture(ping, fast)
                self.assertIn(succeeded, [event["stage"] for event in events])
                self.assertEqual([event["step"] for event in events if event["stage"] == "probe-failed"], [failed])

    def check_failed_measurement_and_retained_tunnel(self, measurement):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            connected = False
            host = None
            switches = []
            def vpn(plan, action, *args):
                nonlocal connected
                if action == "set":
                    connected = args[0] == "on"
                    switches.append((host, args[0]))
                return {"on": connected}
            def retarget(plan, address):
                nonlocal host
                host = address["remote_id"]
                self.assertEqual(address["server"], "8.8.8.8")
            def command(argv, timeout, check=True):
                expected_script = "vpn-ping.py" if measurement == "icmp" else "https_speed.py"
                self.assertTrue(any(Path(argument).name == expected_script for argument in argv))
                fixture = ping_result if measurement == "icmp" else result
                if measurement == "https":
                    return json.dumps(fixture(host, rate=9.99 if host == quick.LEO else 10))
                return json.dumps(fixture(host, 68, 17 if host == quick.LEO else 18))
            hosts = [quick.LEO, "puma.coreavpn.net"]
            plan = dict(device="en6", service="Ethernet", physical_address="10.0.1.2", quick_search=True,
                        measurement=measurement,
                        test_profile=quick.PROFILE, vpn_index=4, vpn_count=15, profiles=[dict(server=h,index=4) for h in hosts])
            with patch.object(quick.pilot, "ui", return_value={"on":True}), patch.object(quick.pilot,"vpn",side_effect=vpn), \
                 patch.object(quick.socket, "if_nametoindex", return_value=7), \
                 patch.dict(quick.uplink, active_device=lambda: "en6"), \
                 patch.object(quick,"uplink_address",return_value="10.0.1.2"), \
                 patch.object(quick.pilot,"route",side_effect=lambda *_: "ipsec4" if connected else "en6") as route, \
                 patch.object(quick.pilot,"speed_peer",return_value=PEER) as speed_peer, \
                 patch.object(quick.pilot,"fl_proxy_listening",return_value=False), \
                 patch.object(quick.pilot,"proxies_off",return_value=True), \
                 patch.object(quick,"endpoint",return_value="8.8.8.8"), \
                 patch.object(quick.pilot,"retarget_profile",side_effect=retarget), \
                 patch.object(quick.pilot,"command",side_effect=command):
                winner = quick.search(run,plan)
                self.assertEqual(winner["server"],hosts[1])
                self.assertEqual(winner["measurement"], measurement)
                route.assert_called_with(quick.pilot.TARGET if measurement == "icmp" else PEER)
                self.assertEqual(speed_peer.call_count, 0 if measurement == "icmp" else 2)
                self.assertEqual(switches,[(hosts[0],"on"),(hosts[0],"off"),(hosts[1],"on")])
                self.assertTrue(connected)
                self.assertTrue((run/"engine-stop-sent").exists())
                self.assertTrue((run/"profile-edited").exists())
                self.assertEqual(json.loads((run/"active-profile.json").read_text())["server"],hosts[1])
