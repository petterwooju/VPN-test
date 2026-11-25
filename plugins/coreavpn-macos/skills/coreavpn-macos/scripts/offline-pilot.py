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
TARGET = "168.126.63.1"


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
    r = subprocess.run([plan["ui"], *calibration, *args], capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, timeout=18)
    if r.returncode:
        raise RuntimeError(f"offline-ui {' '.join(args[:3] if args[0] == 'fl-set' else args[:1])} failed: {r.stderr.strip()[:400]}")
    return json.loads(r.stdout)


def vpn(plan, action, *args):
    return ui(plan, "vpn-" + action, str(plan["vpn_index"]), str(plan["vpn_count"]), *args)


def prior_vpn(plan, action, *args):
    return ui(plan, "vpn-" + action, str(plan["prior_index"]), str(plan["vpn_count"]), *args)


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
        if not (run / "engine-start-sent").exists():
            (run / "engine-start-sent").touch()
            ui(plan, "fl-engine-start")
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


def route():
    value = command(["/sbin/route", "-n", "get", "-inet", TARGET])
    match = re.search(r"^\s*interface:\s*(\S+)", value, re.M)
    if not match:
        raise RuntimeError("Target route unavailable")
    return match[1]


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

        attempt("disconnect-test-vpn", disconnect)
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
        if replaced_vpn:
            def verify_prior_off():
                if prior_vpn(plan, "verify-name", plan["prior_name"])["on"]:
                    raise RuntimeError("Previous VPN is still connected")
            attempt("verify-previous-vpn-off", verify_prior_off)
        if plan.get("verify_off_vpn"):
            attempt("verify-excluded-vpn-off", lambda: verify_excluded_vpn(plan))
        if replaced_vpn or plan.get("cycle_fl_engine"):
            attempt("verify-stable-flclash-proxy", lambda: verify_stable_proxy(run, plan))
        attempt("verify-final-dns", lambda: verify_dns(run, plan))
        attempt("record-final-route", lambda: event(run, "final-route", interface=route()))
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


def verify_excluded_vpn(plan):
    index, name = plan["verify_off_vpn"]
    if ui(plan, "vpn-verify-name", index, str(plan["vpn_count"]), name)["on"]:
        raise RuntimeError(f"{name} must remain disconnected")


def prepare(args):
    plan = dict(ui=str(args.ui.resolve()), vpn_index=args.vpn_index, vpn_count=args.vpn_count)
    if args.fl_map:
        plan["fl_map"] = str(args.fl_map.resolve())
    if not Path(plan["ui"]).is_file():
        raise RuntimeError("Compile the local UI helper before preparation")
    plan["route"] = route()
    if args.replace_vpn:
        index, name = args.replace_vpn
        plan.update(prior_index=int(index), prior_name=name, proxy_port=args.fl_proxy_port,
                    flclash={"tun": True, "proxy": True})
        if not plan["route"].startswith("ipsec") or plan["prior_index"] == plan["vpn_index"]:
            raise RuntimeError("Expected a separate active IKEv2 profile")
        if not prior_vpn(plan, "verify-name", name)["on"]:
            raise RuntimeError("The specified previous VPN is disconnected")
        ui(plan, "fl-engine-check")
        if not proxies_off() or fl_proxy_listening(plan):
            raise RuntimeError("Expected a stopped FlClash engine and inactive system proxy")
    elif plan["route"].startswith("ipsec"):
        raise RuntimeError(f"이미 IKEv2 VPN({plan['route']})이 연결되어 있습니다. 시스템 설정 → VPN에서 현재 프로필을 확인하세요.")
    if not args.replace_vpn:
        plan["flclash"] = ui(plan, "fl-state")
    if args.cycle_fl_engine:
        plan.update(cycle_fl_engine=True, proxy_port=args.fl_proxy_port)
        ui(plan, "fl-engine-check")
        if plan["flclash"] != {"tun": True, "proxy": True} or not fl_proxy_listening(plan):
            raise RuntimeError("Start with the FlClash engine, TUN and system proxy all enabled")
        verify_proxy_internet(plan)
    if args.require_vpn_off:
        plan["verify_off_vpn"] = args.require_vpn_off
        verify_excluded_vpn(plan)
    if vpn(plan, "verify", SERVER)["on"]:
        raise RuntimeError("Puma must be disconnected before the pilot")
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


def pilot(run, plan):
    relay = None
    try:
        # Never ask for an admin password after connectivity is removed.
        command(["/usr/bin/sudo", "-n", "-v"])
        if plan.get("cycle_fl_engine"):
            if not fl_proxy_listening(plan):
                raise RuntimeError("FlClash engine stopped unexpectedly before the test")
            (run / "engine-stop-sent").touch()
            event(run, "stopping-flclash-engine")
            ui(plan, "fl-engine-stop")
            wait_for(lambda: not fl_proxy_listening(plan), 8, "FlClash engine did not stop")
            event(run, "flclash-engine-stopped")
            wait_for(lambda: proxies_off() and route() == plan["device"], 10,
                     "FlClash route/proxies did not clear to physical uplink")
            save(run / "relay-baseline.json", dns(plan["service"]))
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
        wait_for(ready, 45, "Relay readiness timeout")
        answers = command(["/usr/bin/dig", "@127.0.0.1", SERVER, "A", "+short", "+time=8", "+tries=1"])
        addresses = []
        for line in answers.splitlines():
            try:
                address = ipaddress.ip_address(line)
                if address.version == 4 and address.is_global:
                    addresses.append(str(address))
            except ValueError:
                pass
        if not addresses:
            raise RuntimeError("Relay returned no public Puma IPv4 answer")
        event(run, "relay-ready", addresses=addresses)
        # All artifacts, permissions and recovery are ready. No model calls below.
        if plan.get("prior_name"):
            if not prior_vpn(plan, "verify-name", plan["prior_name"])["on"]:
                raise RuntimeError("Previous VPN changed before the test")
            (run / "prior-vpn-touched").touch()
            prior_vpn(plan, "set", "off")
            wait_for(lambda: not prior_vpn(plan, "state")["on"], 10,
                     "Previous VPN did not disconnect")
            event(run, "previous-vpn-disconnected")
        elif not plan.get("cycle_fl_engine"):
            ui(plan, "fl-set", "proxy", "off")
            ui(plan, "fl-set", "tun", "off")
        wait_for(lambda: proxies_off() and route() == plan.get("device", "en0"), 10,
                 "FlClash route/proxies did not clear to physical uplink")
        if plan.get("cycle_fl_engine") and dns(plan.get("service", "Wi-Fi")) != "127.0.0.1":
            raise RuntimeError("Temporary DNS changed before connecting Puma")
        event(run, "offline-window-start")
        (run / "vpn-touched").touch()
        vpn(plan, "set", "on")
        wait_for(lambda: vpn(plan, "state")["on"] and re.fullmatch(r"ipsec[0-9]+", route()),
                 30, "Puma connection/route not established; ping unmeasured")
        tunnel = route()
        event(run, "puma-connected", tunnel=tunnel)
        output = command([sys.executable, SCRIPTS / "vpn-ping.py", "--server", SERVER,
                          "--tunnel", tunnel, "--log-dir", run], timeout=28)
        event(run, "ping-complete", result=json.loads(output))
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
    parser.add_argument("--vpn-index", type=int, help="Zero-based switch index verified in the live VPN UI")
    parser.add_argument("--vpn-count", type=int)
    parser.add_argument("--replace-vpn", nargs=2, metavar=("INDEX", "NAME"),
                        help="Disconnect this verified active profile, leave it off, then start FlClash with TUN and proxy on")
    parser.add_argument("--cycle-fl-engine", action="store_true",
                        help="Stop and restart the originally active FlClash engine")
    parser.add_argument("--require-vpn-off", nargs=2, metavar=("INDEX", "NAME"),
                        help="Verify that the named profile stays disconnected")
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
    if args.ui is None or args.vpn_index is None or not args.vpn_count or args.vpn_index < 0:
        parser.error("--ui, --vpn-index and --vpn-count are required")
    if args.replace_vpn and args.cycle_fl_engine:
        parser.error("--replace-vpn and --cycle-fl-engine are mutually exclusive")
    if (args.replace_vpn or args.cycle_fl_engine) and (not args.fl_map or not 1 <= args.fl_proxy_port <= 65535):
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
            ("After disconnecting the previous VPN, leave it off and start FlClash with TUN and system proxy on.\n"
             if plan.get("prior_name") else
             "Puma pilot restores the FlClash engine and saved TUN/proxy states.\n"
             if plan.get("cycle_fl_engine") else
             "Puma pilot restores the saved FlClash TUN/proxy states.\n") +
            "Restore DNS on the original physical network service.\n"
            "Do not close or rearrange the VPN and FlClash windows during the run.\n"
            "Manual fallback: disconnect only the verified Puma profile; stop this run's relay\n"
            "by creating relay-state/stop, verify DNS against plan.json, restore saved FlClash switches.\n"
            "Retry automatic cleanup with offline-pilot.py --recover --log-dir <this directory>.\n"
            "If Accessibility is unavailable, restore those switches directly in FlClash.\n")
        event(run, "prepared", run_requested=args.run)
        if not args.run:
            print(json.dumps(dict(prepared=True, network_changes=False, run=str(run))))
            return 0
        if sys.stdin.isatty():
            subprocess.run(["/usr/bin/sudo", "-v"], check=True)
        # Recheck sudo BEFORE launching a watchdog or changing DNS.
        command(["/usr/bin/sudo", "-n", "-v"])
        def stop(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGHUP, stop)
        with (run / "watchdog-console.txt").open("w") as file:
            guardian = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--log-dir", str(run),
                              "--watchdog", str(os.getpid()), "--deadline", str(time.time() + 180)],
                             stdin=subprocess.DEVNULL, stdout=file, stderr=subprocess.STDOUT,
                             pass_fds=(lock_file.fileno(),),
                             start_new_session=True)
        ok = False
        try:
            wait_for(lambda: guardian.poll() is None and (run / "watchdog-ready").exists(),
                     5, "Watchdog did not arm; no network changes made")
            pilot(run, plan)
            ok = True
        except (Exception, KeyboardInterrupt) as error:
            event(run, "pilot-failed", error=str(error), ping="see ping-results.jsonl if present")
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
