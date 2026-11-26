#!/usr/bin/env python3
"""Bounded Puma pilot with local UI control and an independent recovery watchdog.

Prepare/compile/authorize everything while FlClash still provides Codex connectivity.
All commands after disabling FlClash run locally, without model/tool round trips.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

SCRIPTS = Path(__file__).resolve().parent
SKILL = SCRIPTS.parent
SERVER = "puma.coreavpn.net"
TARGET = "168.126.63.1"  # ICMP destination and VPN/FlClash route check.
SPEED_HOST = "speed.cloudflare.com"
SPEED_SCRIPT = SCRIPTS / "https_speed.py"
SPEED_TIMEOUT = 45
PING_SCRIPT = SCRIPTS / "vpn-ping.py"
PING_TIMEOUT = 35  # 25 seconds for ping and up to 5 seconds per route lookup.
MEASUREMENTS = ("https", "icmp")
DEFAULT_MEASUREMENT = "https"
TEST_PROFILE = "CoreaVPN_TEST"


def command(argv, timeout=12, check=True):
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                            timeout=timeout, stdin=subprocess.DEVNULL)
    if check and result.returncode:
        # Commands here never read passwords; still avoid dumping arbitrary app output.
        raise RuntimeError(f"Command failed ({result.returncode}): {argv[0]}")
    return result.stdout.strip()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def event(run, stage, **data):
    with (run / "events.jsonl").open("a") as file:
        file.write(json.dumps(dict(time=datetime.now().astimezone().isoformat(),
                                   stage=stage, **data)) + "\n")


def ui(plan, *args):
    calibration = ["--fl-map", plan["fl_map"]] if plan.get("fl_map") else []
    # Initial discovery may need to inspect rows whose AX labels omit their names.
    timeout = 90 if args[0] == "vpn-locate" else 18
    r = subprocess.run([plan["ui"], *calibration, *args], capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, timeout=timeout)
    if r.returncode:
        raise RuntimeError(f"offline-ui {' '.join(args[:3] if args[0] == 'fl-set' else args[:1])} failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout)


def vpn(plan, action, *args):
    # An index is only a hint, including when recovering an interrupted run.
    if plan.get("test_profile") != TEST_PROFILE:
        raise RuntimeError(f"Cannot verify this run belongs to {TEST_PROFILE}")
    slot = (str(plan["vpn_index"]), str(plan["vpn_count"]))
    if action in {"endpoints", "retarget"} and args and args[0] == TEST_PROFILE:
        return ui(plan, "vpn-" + action, *slot, *args)
    if action == "verify-name" and args == (TEST_PROFILE,):
        action, args = "state", ()
    if action not in {"state", "set"}:
        raise ValueError("Unexpected dedicated VPN operation")
    row = ui(plan, "vpn-name-" + action, *slot, TEST_PROFILE, *args)
    plan.update(vpn_index=row["index"], vpn_count=row["count"])
    return row


def fl_proxy_listening(plan):
    import socket
    try:
        with socket.create_connection(("127.0.0.1", plan["proxy_port"]), timeout=1):
            return True
    except OSError:
        return False


def restore_engine(run, plan):
    if not fl_proxy_listening(plan):
        # A retry must not send another toggle while the first start is pending.
        marker = run / "engine-start-sent"
        for attempt in range(2):
            if marker.exists() or fl_proxy_listening(plan):
                break
            marker.touch()
            try:
                ui(plan, "fl-engine-start")
            except RuntimeError as error:
                if "no click sent" not in str(error):
                    raise
                # The UI helper explicitly confirmed focus failed before posting
                # an event. Allow this attempt (and later recovery) to retry.
                marker.unlink()
                if attempt:
                    raise
            else:
                break
        wait_for(lambda: fl_proxy_listening(plan), 12, "FlClash proxy port did not open")


def verify_proxy_internet(plan):
    response = command(["/usr/bin/curl", "--silent", "--show-error", "--max-time", "10",
                        "--proxy", f"http://127.0.0.1:{plan['proxy_port']}", "--noproxy", "",
                        "--output", "/dev/null", "--write-out", "%{http_code}",
                        "https://api.openai.com/v1/models"])
    if response != "401":
        raise RuntimeError(f"Unexpected response from OpenAI over FlClash: {response}")


def verify_stable_proxy(run, plan):
    # A successful explicit curl can coexist with disabled macOS proxy flags.
    port = str(plan["proxy_port"])
    stable_since = time.monotonic()
    deadline = stable_since + 65
    while time.monotonic() < deadline:
        settings = dict(re.findall(r"^[ \t]*(\w+)[ \t]*:[ \t]*(\S+)[ \t]*$",
                                   command(["/usr/sbin/scutil", "--proxy"]), re.M))
        if not any(settings.get(kind + "Enable") == "1" for kind in ("HTTP", "HTTPS", "SOCKS")):
            ui(plan, "fl-set", "proxy", "on")
            event(run, "reapplied-system-proxy")
            stable_since = time.monotonic()
        else:
            for kind in ("HTTP", "HTTPS", "SOCKS"):
                if (settings.get(kind + "Enable") != "1"
                        or settings.get(kind + "Proxy") not in ("127.0.0.1", "localhost", "::1")
                        or settings.get(kind + "Port") != port):
                    raise RuntimeError("Unexpected macOS proxy settings for " + kind)
            if time.monotonic() - stable_since >= 30:
                verify_fl(plan)
                verify_proxy_internet(plan)
                event(run, "system-proxy-stable", seconds=30)
                return
        time.sleep(2)
    raise RuntimeError("System proxy did not remain enabled for 30 seconds")


def dns(service="Wi-Fi"):
    value = command(["/usr/sbin/networksetup", "-getdnsservers", service])
    if "AuthorizationCreate" in value or not value:
        raise RuntimeError("DNS baseline unavailable")
    return value


def route(destination=TARGET):
    value = command(["/sbin/route", "-n", "get", "-inet", str(ipaddress.IPv4Address(destination))], timeout=3)
    match = re.search(r"^\s*interface:\s*(\S+)", value, re.M)
    if not match:
        raise RuntimeError("Target route unavailable")
    return match[1]


def speed_peer():
    # Resolve under the active VPN's DNS. Before the VPN, a resolver used
    # by FlClash may instead return an address from its synthetic pool.
    address = ipaddress.IPv4Address(
        command([sys.executable, "-I", SPEED_SCRIPT, "--resolve-peer"], timeout=8))
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise RuntimeError(f"No public IPv4 answer for {SPEED_HOST}")
    return str(address)


def speed_probe_args(server, peer, tunnel, run):
    return [sys.executable, "-I", str(SPEED_SCRIPT), "--server", server, "--peer-ip", peer,
            "--tunnel", tunnel, "--log-dir", str(run)]


def ping_probe_args(server, tunnel, run):
    return [sys.executable, "-I", str(PING_SCRIPT), "--server", server,
            "--tunnel", tunnel, "--log-dir", str(run)]


def proxies_off():
    value = command(["/usr/sbin/scutil", "--proxy"])
    return not re.search(r"(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1", value)


def wait_for(predicate, timeout, message):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.4)
    raise RuntimeError(message)


@contextmanager
def locked(path, blocking=True):
    with path.open("a") as file:
        fcntl.flock(file, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        yield file


def disconnect_batch_profile(run, plan):
    active = run / "active-profile.json"
    if not active.exists():
        return
    vpn(plan, "set", "off")
    wait_for(lambda: not vpn(plan, "state")["on"] and not route().startswith("ipsec"),
             12, "Batch VPN profile did not disconnect")
    active.unlink()


def retarget_profile(plan, endpoints):
    result = vpn(plan, "retarget", plan["test_profile"], endpoints["server"], endpoints["remote_id"])
    if result != endpoints:
        raise RuntimeError("Saved VPN endpoints did not match the requested values")


def restore_test_profile(run, plan):
    if (run / "profile-edited").exists():
        retarget_profile(plan, plan["original_endpoints"])
        (run / "profile-edited").unlink()


def measure_profiles(run, plan):
    measurement = plan.get("measurement", DEFAULT_MEASUREMENT)
    for profile in plan["profiles"]:
        server = profile["server"]
        if route() != plan["device"]:
            raise RuntimeError("Physical route is required before switching profiles")
        if vpn(plan, "state")["on"]:
            raise RuntimeError(f"VPN was already connected: {server}")
        event(run, "server-start", server=server)
        stage = "dns"
        try:
            addresses = lookup_ipv4(server)
            if not addresses:
                addresses = lookup_ipv4(server)
            if not addresses:
                raise RuntimeError("No public IPv4 answer")
            event(run, "server-dns", server=server, addresses=addresses)
            stage = "profile-update"
            (run / "profile-edited").touch()
            retarget_profile(plan, {"server": server, "remote_id": server})
            stage = "connect"
            save(run / "active-profile.json", profile)
            vpn(plan, "set", "on")
            wait_for(lambda: re.fullmatch(r"ipsec[0-9]+", route()) and vpn(plan, "state")["on"],
                     30, "VPN connection or tunnel route not established")
            tunnel = route()
            stage = measurement
            measure(run, server, tunnel, measurement)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            event(run, "server-failed", server=server, step=stage, error=str(error))
        finally:
            disconnect_batch_profile(run, plan)


def recover(run, plan):
    """Idempotent, serialized recovery. Try every step even if another step fails."""
    with locked(run / "recovery.lock"):
        if (run / "recovered.json").exists():
            if json.loads((run / "recovered.json").read_text())["ok"]:
                return True
        errors = []

        def attempt(name, fn):
            try:
                fn()
                event(run, name, ok=True)
            except Exception as error:
                errors.append(name)
                event(run, name, ok=False, error=str(error))

        def disconnect():
            if plan.get("profiles"):
                disconnect_batch_profile(run, plan)
                return
            # Mark intent BEFORE changing the switch, including a timed-out AX call.
            if (run / "vpn-touched").exists():
                vpn(plan, "set", "off")
                wait_for(lambda: not vpn(plan, "state")["on"] and not route().startswith("ipsec"),
                         12, "Test VPN did not disconnect")

        def stop_relay():
            state = run / "relay-state"
            if (run / "relay-touched").exists():
                state.mkdir(mode=0o700, exist_ok=True)
                (state / "stop").touch()
                restored = run / "dns-restored"
                if not restored.exists():
                    saved = run / "relay-baseline.json"
                    baseline = json.loads(saved.read_text()) if saved.exists() else plan["dns"]
                    wait_for(lambda: dns(plan.get("service", "Wi-Fi")) == baseline, 18,
                             "DNS restoration could not be verified")
                    restored.touch()

        if plan.get("test_profile") == TEST_PROFILE and any(
                (run / marker).exists() for marker in ("vpn-touched", "active-profile.json", "profile-edited")):
            # A details sheet can be left open by an interrupted UI helper.
            # Other profiles and unsaved edits belong to the user.
            try:
                ui(plan, "vpn-close-clean", TEST_PROFILE)
            except (RuntimeError, OSError, subprocess.SubprocessError) as error:
                event(run, "profile-sheet-preserved", reason=str(error))
        attempt("disconnect-test-vpn", disconnect)
        if plan.get("test_profile"):
            attempt("restore-test-profile", lambda: restore_test_profile(run, plan))
        attempt("restore-dns", stop_relay)
        replaced_vpn = plan.get("prior_name") and (run / "prior-vpn-touched").exists()
        if replaced_vpn or (run / "engine-stop-sent").exists():
            attempt("start-flclash-engine", lambda: restore_engine(run, plan))
        # Do not skip connectivity recovery when disconnect/DNS checks fail.
        if not plan.get("prior_name") or replaced_vpn:
            for key in ("tun", "proxy"):
                attempt("restore-flclash-" + key,
                        lambda key=key: ui(plan, "fl-set", key, "on" if plan["flclash"][key] else "off"))
            attempt("verify-flclash", lambda: verify_fl(plan))
        if replaced_vpn or plan.get("cycle_fl_engine"):
            attempt("verify-stable-flclash-proxy", lambda: verify_stable_proxy(run, plan))
        attempt("verify-final-dns", lambda: verify_dns(run, plan))
        def verify_final_route():
            final = route()
            event(run, "final-route", interface=final)
            if plan.get("quick_search") and not re.fullmatch(r"utun\d+", final):
                raise RuntimeError("FlClash TUN is not carrying the final route")
        attempt("record-final-route", verify_final_route)
        if plan.get("quick_search"):
            def verify_restored_profile():
                # The named endpoint reader requires the exact profile to be off.
                if vpn(plan, "endpoints", plan["test_profile"]) != plan["original_endpoints"]:
                    raise RuntimeError("Test profile endpoints differ from the saved original values")
            attempt("verify-original-test-profile", verify_restored_profile)
            def verify_engine():
                if not fl_proxy_listening(plan):
                    raise RuntimeError("FlClash engine is not listening after recovery")
            attempt("verify-final-engine", verify_engine)
        result = dict(ok=not errors, errors=errors)
        save(run / "recovered.json", result)
        event(run, "recovery-complete", **result)
        return not errors


def verify_fl(plan):
    if ui(plan, "fl-state") != plan["flclash"]:
        raise RuntimeError("FlClash restoration mismatch")


def verify_dns(run, plan):
    current = dns(plan.get("service", "Wi-Fi"))
    if current == "127.0.0.1":
        raise RuntimeError("The temporary relay is still configured")
    # Starting FlClash may apply its own DNS configuration after relay cleanup.
    if not (run / "dns-restored").exists() and current != plan["dns"]:
        raise RuntimeError("DNS restoration to baseline was not verified")


def watchdog(run, owner, deadline):
    plan = json.loads((run / "plan.json").read_text())
    (run / "watchdog-ready").touch()
    while time.time() < deadline:
        if (run / "finished").exists():
            return
        try:
            os.kill(owner, 0)
        except ProcessLookupError:
            break
        time.sleep(0.5)
    event(run, "watchdog-recovery")
    # Stop the worker before restoring settings so it cannot resume toggling them.
    try:
        os.kill(owner, signal.SIGTERM)
        # Allow finally/subprocess cancellation, then prevent a stalled worker from
        # resuming UI actions after the guardian has started restoring settings.
        time.sleep(2)
        os.kill(owner, signal.SIGKILL)
    except ProcessLookupError:
        pass
    recover(run, plan)


def resolve_named_slots(plan, selected_name, excluded=None):
    if selected_name != TEST_PROFILE or excluded:
        raise ValueError(f"Only the dedicated {TEST_PROFILE} profile can be selected")
    row = ui(plan, "vpn-locate", str(plan.get("vpn_index", 0)), selected_name)
    plan.update(vpn_index=row["index"], vpn_count=row["count"], test_profile=selected_name)
    if row["on"]:
        raise RuntimeError(f"{TEST_PROFILE} is already connected")


def batch_hosts(raw):
    # Older local manifests contain stale System Settings row numbers.
    if not isinstance(raw, list) or not 1 <= len(raw) <= 23:
        raise ValueError("Expected 1 to 23 server hostnames")
    hosts = [item.get("server") if isinstance(item, dict) else item for item in raw]
    if (any(not isinstance(host, str) or not re.fullmatch(r"[a-z0-9-]+\.coreavpn\.(net|com|kr)", host)
            for host in hosts) or len(set(hosts)) != len(hosts)):
        raise ValueError("Expected unique CoreaVPN server hostnames")
    return [{"server": host} for host in hosts]


def prepare(args):
    plan = dict(ui=str(args.ui.resolve()), vpn_index=args.vpn_index, measurement=args.measurement)
    if args.fl_map:
        plan["fl_map"] = str(args.fl_map.resolve())
    if not Path(plan["ui"]).is_file():
        raise RuntimeError("Compile the local UI helper before preparation")
    helper = PING_SCRIPT if args.measurement == "icmp" else SPEED_SCRIPT
    if not helper.is_file():
        raise RuntimeError(f"Install the {helper.name} measurement helper before preparation")
    plan["route"] = route()
    if plan["route"].startswith("ipsec"):
        raise RuntimeError(f"이미 IKEv2 VPN({plan['route']})이 연결되어 있습니다. 시스템 설정 → VPN에서 현재 프로필을 확인하세요.")
    resolve_named_slots(plan, args.test_profile)
    plan["original_endpoints"] = vpn(plan, "endpoints", TEST_PROFILE)
    plan["flclash"] = ui(plan, "fl-state")
    if args.cycle_fl_engine:
        plan.update(cycle_fl_engine=True, proxy_port=args.fl_proxy_port)
        ui(plan, "fl-engine-check")
        if plan["flclash"] != {"tun": True, "proxy": True} or not fl_proxy_listening(plan):
            raise RuntimeError("Start with the FlClash engine, TUN and system proxy all enabled")
        verify_proxy_internet(plan)
    if args.batch:
        plan["profiles"] = batch_hosts(json.loads(args.batch.read_text()))
    else:
        plan["puma_name"] = TEST_PROFILE
    import runpy
    uplink = runpy.run_path(str(SKILL / "assets/Puma-DNS/uplink.py"))
    plan["device"], plan["service"] = uplink["active_link"]()
    plan["dns"] = dns(plan["service"])
    uplink["resolver_settings"](plan["service"], plan["device"], plan["dns"])
    listeners = command(["/usr/sbin/lsof", "-nP", "-iUDP:53", "-iTCP:53"], check=False)
    if listeners:
        raise RuntimeError("An existing DNS listener must be identified before running")
    plan["proxy_baseline"] = command(["/usr/sbin/scutil", "--proxy"])
    return plan


def verify_named_baseline(plan):
    # The user may have left the Terminal password prompt open and changed
    # networks or profiles in the meantime. Fail before arming any cleanup.
    if route() != plan["route"] or dns(plan["service"]) != plan["dns"]:
        raise RuntimeError("Network baseline changed while waiting for administrator authentication")
    verify_fl(plan)
    if plan.get("cycle_fl_engine") and not fl_proxy_listening(plan):
        raise RuntimeError("FlClash engine stopped while waiting for administrator authentication")
    if vpn(plan, "endpoints", TEST_PROFILE) != plan["original_endpoints"]:
        raise RuntimeError("Dedicated VPN profile changed while waiting for administrator authentication")


def lookup_ipv4(host):
    answers = command(["/usr/bin/dig", "@127.0.0.1", host, "A", "+short", "+time=8", "+tries=1"])
    addresses = []
    for line in answers.splitlines():
        try:
            address = ipaddress.ip_address(line)
            if address.version == 4 and address.is_global:
                addresses.append(str(address))
        except ValueError:
            pass
    return addresses


class MeasurementStopped(Exception):
    """The user stopped this specific Puma measurement."""


def cancellable_measurement(argv, check_stop, timeout):
    # The measurement has a private group so cancellation leaves the DNS
    # relay and independent recovery watchdog running.
    if check_stop is not None:
        check_stop()
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, text=True, start_new_session=True) as proc:
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                try:
                    output, diagnostic = proc.communicate(timeout=min(remaining, 0.35))
                    break
                except subprocess.TimeoutExpired:
                    if check_stop is not None:
                        check_stop()
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            raise
    if proc.returncode:
        raise RuntimeError(f"Measurement helper exited with status {proc.returncode}: {diagnostic.strip()[:300]}")
    return output


def measure_speed(run, server, tunnel, check_stop=None):
    if not re.fullmatch(r"ipsec[0-9]+", tunnel):
        raise RuntimeError("VPN tunnel was lost before HTTPS measurement")
    if check_stop is not None:
        check_stop()
    peer = speed_peer()
    if route(peer) != tunnel:
        raise RuntimeError(f"The VPN has no route to {SPEED_HOST}; HTTPS speed unmeasured")
    argv = speed_probe_args(server, peer, tunnel, run)
    event(run, "https-start", server=server, target=SPEED_HOST, peer_ipv4=peer, tunnel=tunnel)
    output = (cancellable_measurement(argv, check_stop, SPEED_TIMEOUT) if check_stop is not None
              else command(argv, timeout=SPEED_TIMEOUT))
    event(run, "https-complete", server=server, result=json.loads(output))


def measure(run, server, tunnel, measurement, check_stop=None):
    if measurement == "https":
        return measure_speed(run, server, tunnel, check_stop)
    if measurement != "icmp":
        raise ValueError(f"Unsupported measurement method: {measurement}")
    if not re.fullmatch(r"ipsec[0-9]+", tunnel) or route(TARGET) != tunnel:
        raise RuntimeError(f"The VPN has no route to {TARGET}; ICMP ping unmeasured")
    event(run, "ping-start", server=server, target=TARGET, tunnel=tunnel)
    # The ping helper has a child process. Use a private group for batch runs as
    # well, so a watchdog stop or timeout also terminates the child.
    output = cancellable_measurement(ping_probe_args(server, tunnel, run), check_stop, PING_TIMEOUT)
    event(run, "ping-complete", server=server, result=json.loads(output))


def pilot(run, plan):
    def check_stop():
        if plan.get("puma_name") and (run / "stop-measurement").exists():
            raise MeasurementStopped("Puma measurement stopped by user")

    def measurement_wait(predicate, timeout, message):
        def checked():
            check_stop()
            return predicate()
        return wait_for(checked, timeout, message)

    relay = None
    try:
        # Never ask for an admin password after connectivity is removed.
        command(["/usr/bin/sudo", "-n", "-v"])
        check_stop()
        if plan.get("cycle_fl_engine"):
            if not fl_proxy_listening(plan):
                raise RuntimeError("FlClash engine stopped unexpectedly before the test")
            (run / "engine-stop-sent").touch()
            event(run, "stopping-flclash-engine")
            ui(plan, "fl-engine-stop")
            measurement_wait(lambda: not fl_proxy_listening(plan), 8, "FlClash engine did not stop")
            event(run, "flclash-engine-stopped")
            measurement_wait(lambda: proxies_off() and route() == plan["device"], 10,
                     "FlClash route/proxies did not clear to physical uplink")
            save(run / "relay-baseline.json", dns(plan["service"]))
        check_stop()
        (run / "relay-touched").touch()
        with (run / "relay-console.txt").open("w") as file:
            relay = subprocess.Popen(["/usr/bin/python3", "-I",
                str(SKILL / "assets/Puma-DNS/session.py"), "--state-dir", str(run / "relay-state"),
                "--expected-interface", plan.get("device", "en0")],
                stdin=subprocess.DEVNULL, stdout=file, stderr=subprocess.STDOUT)
        def ready():
            if relay.poll() is not None:
                raise RuntimeError("Relay exited before readiness; see relay-console.txt")
            return dns(plan.get("service", "Wi-Fi")) == "127.0.0.1"
        measurement_wait(ready, 45, "Relay readiness timeout")
        addresses = lookup_ipv4(SERVER)
        if not addresses:
            raise RuntimeError("Relay returned no public Puma IPv4 answer")
        event(run, "relay-ready", addresses=addresses)
        # All artifacts, permissions and recovery are ready. No model calls below.
        if not plan.get("cycle_fl_engine"):
            ui(plan, "fl-set", "proxy", "off")
            ui(plan, "fl-set", "tun", "off")
        measurement_wait(lambda: proxies_off() and route() == plan.get("device", "en0"), 10,
                 "FlClash route/proxies did not clear to physical uplink")
        if plan.get("cycle_fl_engine") and dns(plan.get("service", "Wi-Fi")) != "127.0.0.1":
            raise RuntimeError("Temporary DNS changed before connecting Puma")
        event(run, "offline-window-start")
        if plan.get("profiles"):
            measure_profiles(run, plan)
            return
        if plan.get("puma_name"):
            # Keep both original values durable before the first temporary edit.
            # The local relay already resolves the hostname to its public address.
            endpoints = {"server": SERVER, "remote_id": SERVER}
            if endpoints != plan["original_endpoints"]:
                (run / "profile-edited").touch()
                retarget_profile(plan, endpoints)
        check_stop()
        (run / "vpn-touched").touch()
        vpn(plan, "set", "on")
        measurement = plan.get("measurement", DEFAULT_MEASUREMENT)
        measurement_wait(lambda: re.fullmatch(r"ipsec[0-9]+", route()) and vpn(plan, "state")["on"],
                         30, f"Puma connection/route not established; {measurement.upper()} measurement unavailable")
        tunnel = route()
        event(run, "puma-connected", tunnel=tunnel)
        measure(run, SERVER, tunnel, measurement, check_stop)
    except MeasurementStopped:
        event(run, "measurement-stopped")
        raise
    except (Exception, KeyboardInterrupt) as error:
        event(run, "measurement-interrupted", error=str(error))
        raise
    finally:
        recovered = recover(run, plan)
        if relay:
            try:
                relay.wait(timeout=8)
            except subprocess.TimeoutExpired:
                event(run, "relay-parent-still-running")
        if not recovered:
            raise RuntimeError("Recovery incomplete; inspect recovered.json and recovery.txt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ui", type=Path)
    parser.add_argument("--fl-map", type=Path, help="Optional calibration from a live FlClash screenshot")
    parser.add_argument("--vpn-index", type=int, default=0, help="Optional last-known VPN row hint")
    parser.add_argument("--vpn-count", type=int, help=argparse.SUPPRESS)  # Old launcher hint; read the live count.
    parser.add_argument("--batch", type=Path, help="JSON list of official CoreaVPN hostnames")
    parser.add_argument("--measurement", choices=MEASUREMENTS, default=DEFAULT_MEASUREMENT,
                        help="FAST-style Cloudflare HTTPS transfer or ICMP ping to 168.126.63.1 (default: https)")
    parser.add_argument("--test-profile", choices=[TEST_PROFILE], default=TEST_PROFILE)
    parser.add_argument("--cycle-fl-engine", action="store_true",
                        help="Stop and restart the originally active FlClash engine")
    parser.add_argument("--fl-proxy-port", type=int, default=7890)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="Actually run; default only checks readiness")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--watchdog", type=int, metavar="OWNER_PID", help=argparse.SUPPRESS)
    parser.add_argument("--deadline", type=float, help=argparse.SUPPRESS)
    args = parser.parse_args()
    run = args.log_dir.resolve()
    if args.watchdog:
        watchdog(run, args.watchdog, args.deadline)
        return 0
    if args.recover:
        return 0 if recover(run, json.loads((run / "plan.json").read_text())) else 1
    if args.ui is None or args.vpn_index < 0:
        parser.error("--ui and a non-negative row hint are required")
    if args.batch and not args.cycle_fl_engine:
        parser.error("--batch requires --cycle-fl-engine")
    if args.cycle_fl_engine and (not args.fl_map or not 1 <= args.fl_proxy_port <= 65535):
        parser.error("Engine recovery requires a current --fl-map and valid local proxy port")
    # One pilot per user, including its final recovery. Watchdog has its own recovery lock.
    lock = Path("/private/tmp") / f"coreavpn-offline-{os.getuid()}.lock"
    with locked(lock, blocking=False) as lock_file:
        run.mkdir(mode=0o700, parents=True, exist_ok=False)
        try:
            plan = prepare(args)
        except Exception as error:
            event(run, "preparation-failed", error=str(error), network_changes=False)
            raise
        save(run / "plan.json", plan)
        (run / "recovery.txt").write_text(
            "This run restores the original CoreaVPN_TEST server address and remote ID, "
            "the physical network DNS, and the saved FlClash settings.\n"
            "Manual fallback: disconnect CoreaVPN_TEST and stop this run's relay\n"
            "by creating relay-state/stop, verify DNS against plan.json, restore saved FlClash switches.\n"
            "Retry automatic cleanup with offline-pilot.py --recover --log-dir <this directory>.\n"
            "If Accessibility is unavailable, restore those switches directly in FlClash.\n")
        event(run, "prepared", run_requested=args.run, measurement=plan["measurement"])
        if not args.run:
            print(json.dumps(dict(prepared=True, network_changes=False, run=str(run))))
            return 0
        if sys.stdin.isatty():
            subprocess.run(["/usr/bin/sudo", "-v"], check=True)
        # Recheck sudo BEFORE launching a watchdog or changing DNS.
        command(["/usr/bin/sudo", "-n", "-v"])
        verify_named_baseline(plan)
        def stop(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGHUP, stop)
        # Budget a bounded connection, measurement and cleanup per profile.
        maximum_seconds = 225 + 140 * len(plan.get("profiles", []))
        with (run / "watchdog-console.txt").open("w") as file:
            guardian = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--log-dir", str(run),
                              "--watchdog", str(os.getpid()), "--deadline", str(time.time() + maximum_seconds)],
                             stdin=subprocess.DEVNULL, stdout=file, stderr=subprocess.STDOUT,
                             pass_fds=(lock_file.fileno(),),
                             start_new_session=True)
        ok = False
        try:
            wait_for(lambda: guardian.poll() is None and (run / "watchdog-ready").exists(),
                     5, "Watchdog did not arm; no network changes made")
            pilot(run, plan)
            ok = True
        except MeasurementStopped:
            print(json.dumps(dict(stopped=True, run=str(run))))
            return 0
        except (Exception, KeyboardInterrupt) as error:
            event(run, "pilot-failed", error=str(error), measurement=plan["measurement"])
            raise
        finally:
            # The guardian also covers worker death; this flag is written only after cleanup.
            if ((run / "recovered.json").exists()
                    and json.loads((run / "recovered.json").read_text())["ok"]):
                (run / "finished").touch()
            event(run, "worker-finished", ok=ok)
        print(json.dumps(dict(ok=ok, run=str(run))))
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(f"Pilot stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
