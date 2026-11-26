"""Operate only the user's dedicated CoreaVPN_TEST profile for a retained search."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import runpy
import socket
import subprocess
import sys

import https_speed
from quick_policy import DEFAULT_MEASUREMENT, MEASUREMENTS, OPERATIONS, destination_for_sample, qualifies

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coreavpn_pilot", SCRIPTS / "offline-pilot.py")
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)
uplink = runpy.run_path(str(pilot.SKILL / "assets/Puma-DNS/uplink.py"))
PROFILE = pilot.TEST_PROFILE
LEO = "leo.coreavpn.net"
HOSTS = set(json.loads((SCRIPTS.parent / "assets/servers.json").read_text()))


def candidate_order(hosts):
    if not hosts or len(hosts) != len(set(hosts)) or any(h not in HOSTS for h in hosts):
        raise ValueError("Expected a nonempty ordered list of distinct supported CoreaVPN servers")
    return ([LEO] if LEO in hosts else []) + [h for h in hosts if h != LEO]


def uplink_address(device):
    return str(ipaddress.IPv4Address(pilot.command(["/usr/sbin/ipconfig", "getifaddr", device])))


def endpoint(plan, host):
    if not host.endswith(".net"):
        return host
    address = pilot.command([plan["resolver"], plan["device"], host], timeout=30)
    ip = ipaddress.IPv4Address(address)
    if not ip.is_global or ip.is_multicast:
        raise RuntimeError("No public IPv4 answer for " + host)
    return str(ip)


def profile_hint(run):
    try:
        value = json.loads((run.parent / "quick-profile-hint.json").read_text())
        if value["name"] == PROFILE and type(value["index"]) is int and value["index"] >= 0:
            return value["index"]
    except (OSError, KeyError, TypeError, ValueError):
        pass
    return 9


def prepare(run, ui, fl_map, hosts, measurement=DEFAULT_MEASUREMENT, operation="quick",
            expected_device=None, expected_prefix=None):
    if measurement not in MEASUREMENTS:
        raise ValueError(f"Unsupported VPN measurement: {measurement}")
    order = candidate_order(hosts)
    if operation not in OPERATIONS or (operation == "select" and len(hosts) != 1):
        raise ValueError("Manual connection requires exactly one chosen CoreaVPN server")
    if operation == "all":
        order = hosts
    ui = Path(ui).resolve()
    resolver = ui.with_name("quick-resolve")
    probes = [pilot.PING_SCRIPT if measurement == "icmp" else pilot.SPEED_SCRIPT]
    if operation == "all":
        probes = [pilot.PING_SCRIPT, pilot.SPEED_SCRIPT]
    if not all(os.access(tool, os.X_OK) for tool in (ui, resolver)) or not all(
            path.is_file() for path in (Path(fl_map), *probes)):
        raise RuntimeError("Missing local helpers or FlClash calibration")
    if pilot.ui({"ui": str(ui)}, "quick-capabilities").get("named_profiles") is not True:
        raise RuntimeError("Update the VPN helper to the version that verifies the exact profile name")
    device, service = uplink["active_link"]()
    if expected_device and device != expected_device:
        raise RuntimeError("The physical interface changed since this request was created")
    address = uplink_address(device)
    if expected_prefix and ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(expected_prefix, strict=False):
        raise RuntimeError("The physical subnet changed since this request was created")
    plan = dict(ui=str(ui), resolver=str(resolver), operation=operation, fl_map=str(Path(fl_map).resolve()), measurement=measurement,
                vpn_index=profile_hint(run), test_profile=PROFILE, quick_search=True,
                cycle_fl_engine=True, proxy_port=7890, device=device, service=service,
                physical_address=address, route=pilot.route(), dns=pilot.dns(service),
                flclash={"tun": True, "proxy": True})
    if not re.fullmatch(r"utun\d+", plan["route"]):
        raise RuntimeError("Start with FlClash TUN on and other VPNs disconnected")
    pilot.resolve_named_slots(plan, PROFILE, None)
    plan["original_endpoints"] = pilot.vpn(plan, "endpoints", PROFILE)
    plan["profiles"] = [{"server": host} for host in order]
    try:
        pilot.save(run.parent / "quick-profile-hint.json", {"name": PROFILE, "index": plan["vpn_index"]})
    except OSError:
        pass  # A row hint only speeds up discovery. All actions still verify the name.
    pilot.ui(plan, "fl-engine-check")
    pilot.verify_fl(plan)
    pilot.verify_proxy_internet(plan)
    return plan


def same_uplink(plan):
    # A full tunnel can hide its underlay in NWI. Even then the original
    # physical interface must still have the exact captured IPv4 address.
    return (uplink["active_device"]() in (None, plan["device"]) and
            uplink_address(plan["device"]) == plan["physical_address"])


def verify_baseline(plan):
    if pilot.route() != plan["route"] or not same_uplink(plan):
        raise RuntimeError("Physical uplink or FlClash route changed")
    if pilot.dns(plan["service"]) != plan["dns"] or not pilot.fl_proxy_listening(plan):
        raise RuntimeError("DNS or FlClash engine changed")
    pilot.verify_fl(plan)
    if pilot.vpn(plan, "endpoints", PROFILE) != plan["original_endpoints"]:
        raise RuntimeError("Dedicated VPN profile changed")


def still_connected(plan, host, tunnel, destination):
    # The named switch was verified before measuring. Track that kernel interface,
    # including reuse of its ipsecN name, without consulting System Settings.
    return (host in HOSTS and re.fullmatch(r"ipsec\d+", tunnel) is not None and
            pilot.route(destination) == tunnel and socket.if_nametoindex(tunnel) == plan["tunnel_index"] and
            same_uplink(plan) and not pilot.fl_proxy_listening(plan))


def probe(run, plan, host, tunnel, method, paired):
    destination = pilot.TARGET if method == "icmp" else pilot.speed_peer()
    if not still_connected(plan, host, tunnel, destination):
        raise RuntimeError("The measurement destination is outside the verified IKEv2 tunnel")

    if paired and method == "https":
        # Run under the watchdog's killable worker process. Persist the download
        # before the upload so stopping during upload keeps the confirmed bytes.
        def checkpoint(stage, result):
            if not still_connected(plan, host, tunnel, destination):
                raise RuntimeError("VPN or uplink changed before the HTTPS checkpoint")
            pilot.event(run, stage, server=host, result=result)
        result = https_speed.measure(host, destination, tunnel,
                                     idle_checkpoint=lambda result: checkpoint("https-idle-complete", result),
                                     download_checkpoint=lambda result: checkpoint("https-download-complete", result))
    elif method == "icmp":
        result = json.loads(pilot.command(pilot.ping_probe_args(host, tunnel, run),
                                          timeout=pilot.PING_TIMEOUT, check=False))
        result.setdefault("measurement", "icmp")
    else:
        result = json.loads(pilot.command(pilot.speed_probe_args(host, destination, tunnel, run),
                                          timeout=pilot.SPEED_TIMEOUT, check=False))

    if result.get("valid") is not True:
        raise RuntimeError(result.get("error") or "Measurement did not complete")
    if (result.get("server") != host or result.get("tunnel") != tunnel
            or destination_for_sample(result, method) != destination
            or not still_connected(plan, host, tunnel, destination)):
        raise RuntimeError("Measurement evidence does not match the active VPN or uplink")
    if paired and method == "https":
        with (run / "https-results.jsonl").open("a") as log:
            log.write(json.dumps(result, allow_nan=False) + "\n")
    stage = "ping-complete" if method == "icmp" else "https-complete"
    pilot.event(run, stage, server=host, result=result)
    return result


def search(run, plan, cancelled=lambda: False):
    # The supervisor must own the global pilot lock and have armed its watchdog.
    measurement = plan.get("measurement", DEFAULT_MEASUREMENT)
    if measurement not in MEASUREMENTS:
        raise ValueError(f"Unsupported VPN measurement: {measurement}")
    operation = plan.get("operation", "quick")
    if operation not in OPERATIONS or (operation == "select" and len(plan["profiles"]) != 1):
        raise ValueError("Invalid search operation or selected host count")
    if cancelled():
        return None
    (run / "engine-stop-sent").touch()
    pilot.event(run, "stopping-flclash-engine")
    pilot.ui(plan, "fl-engine-stop")
    pilot.wait_for(lambda: not pilot.fl_proxy_listening(plan) and pilot.proxies_off()
                   and pilot.route() == plan["device"], 15, "FlClash did not yield the physical route")
    pilot.event(run, "physical-route-confirmed", interface=plan["device"])
    for profile in plan["profiles"]:
        if cancelled():
            return None
        if pilot.route() != plan["device"] or not same_uplink(plan):
            raise RuntimeError("Physical route changed during the search")
        host = profile["server"]
        pilot.event(run, "server-start", server=host)
        stage = "dns"
        selected = False
        try:
            address = endpoint(plan, host)
            pilot.event(run, "server-endpoint", server=host, address=address, remote_id=host)
            stage = "profile-update"
            if cancelled():
                return None
            pending = run / "profile-edit-in-progress"
            pending.touch()
            try:
                if cancelled():
                    return None
                (run / "profile-edited").touch()
                pilot.retarget_profile(plan, {"server": address, "remote_id": host})
            finally:
                pending.unlink(missing_ok=True)
            if cancelled():
                return None
            stage = "connect"
            pilot.save(run / "active-profile.json", profile)
            pilot.vpn(plan, "set", "on")
            pilot.wait_for(lambda: re.fullmatch(r"ipsec\d+", pilot.route()),
                           30, "Dedicated profile did not establish an IKEv2 route")
            if not pilot.vpn(plan, "state")["on"]:
                raise RuntimeError("The named profile is not connected to the measured IKEv2 route")
            tunnel = pilot.route()
            if not re.fullmatch(r"ipsec\d+", tunnel):
                raise RuntimeError("IKEv2 route changed before measurement")
            plan["tunnel_index"] = socket.if_nametoindex(tunnel)
            if not still_connected(plan, host, tunnel, pilot.TARGET):
                raise RuntimeError("The VPN connection or underlying network changed")
            pilot.event(run, "server-connected", server=host, tunnel=tunnel,
                        interface_index=plan["tunnel_index"])
            if operation == "select":
                if cancelled():
                    return None
                selected = True
                return dict(valid=True, measurement="connection", server=host, target=pilot.TARGET,
                            tunnel=tunnel, interface_index=plan["tunnel_index"])

            methods = ("icmp", "https") if operation == "all" else (measurement,)
            for method in methods:
                if cancelled():
                    return None
                stage = method
                pilot.event(run, "probe-start", server=host, step=method)
                try:
                    result = probe(run, plan, host, tunnel, method, paired=operation == "all")
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    pilot.event(run, "probe-failed", server=host, step=stage, error=str(error))
                    if operation != "all":
                        raise
                    continue
                if operation == "quick" and not cancelled() and qualifies(result, [host], tunnel, measurement=method):
                    selected = True
                    return result
            pilot.event(run, "server-finished", server=host)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            pilot.event(run, "server-failed", server=host, step=stage, error=str(error))
            if operation == "select":
                raise
        finally:
            if not selected:
                pilot.disconnect_batch_profile(run, plan)
    return None


def recover(run, plan):
    # A retry can load a plan from before the profile rename. Do not check the
    # removed exclusion or replay the old name as an alias for a different VPN.
    # Shared recovery verifies the name on each VPN action and restores FlClash
    # independently even if it cannot restore the recorded profile.
    current = plan.copy()
    current.pop("verify_off_vpn", None)
    return pilot.recover(run, current)
