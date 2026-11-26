#!/usr/bin/env python3
"""Run a signed Mac app's native Puma test under an independent FlClash recovery watchdog.

Prepare with --app <signed.app> --ui <authorized offline-ui> --fl-map <map.json>
--log-dir <new directory>. Add --run to test. Retry recovery with --recover --log-dir <existing run>.
The app must already have a locally saved account and an authorized, disconnected, non-On-Demand VPN.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import runpy
import signal
import subprocess
import sys
import time

SCRIPT = Path(__file__).resolve()
SKILL = SCRIPT.parents[2] / "plugins/coreavpn-macos/skills/coreavpn-macos"
spec = importlib.util.spec_from_file_location("legacy_pilot", SKILL / "scripts/offline-pilot.py")
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
DEVNULL = subprocess.DEVNULL
WATCHDOG_SECONDS = 165


def app_command(plan, *args, timeout=15):
    proc = subprocess.run([plan["executable"], *args], capture_output=True, text=True,
                          stdin=DEVNULL, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(f"{args[0]} failed (exit {proc.returncode}); see the app's credential and VPN settings")
    value = json.loads(proc.stdout.strip())
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise RuntimeError(f"Unsuccessful app response: {args[0]}")
    return value


def verify_app(app):
    path = app.resolve(strict=True)
    if path.suffix != ".app":
        raise ValueError("--app must be a signed .app bundle")
    info = plistlib.loads((path / "Contents/Info.plist").read_bytes())
    executable = path / "Contents/MacOS" / "CoreaVPN"
    if info.get("CFBundleExecutable") != executable.name or not os.access(executable, os.X_OK):
        raise ValueError("Expected a CoreaVPN app executable")
    legacy.command(["/usr/bin/codesign", "--verify", "--strict", path])
    entitlements = subprocess.check_output(["/usr/bin/codesign", "--display", "--entitlements", "-", "--xml", path],
                                            stderr=DEVNULL, timeout=10)
    signed = plistlib.loads(entitlements)
    if "allow-vpn" not in signed.get("com.apple.developer.networking.vpn.api", []) or not signed.get("com.apple.developer.team-identifier"):
        raise ValueError("Sign the app with a provisioning profile that grants Personal VPN")
    return str(executable)


def prepare(args):
    if not args.ui.is_file() or not os.access(args.ui, os.X_OK) or not args.fl_map.is_file():
        raise ValueError("Provide the compiled, authorized offline-ui and current FlClash calibration")
    if not 1 <= args.fl_proxy_port <= 65535:
        raise ValueError("Invalid FlClash proxy port")
    plan = dict(executable=verify_app(args.app), ui=str(args.ui.resolve()), fl_map=str(args.fl_map.resolve()),
                cycle_fl_engine=True, proxy_port=args.fl_proxy_port)
    app_command(plan, "--pilot-ready")
    plan["flclash"] = legacy.ui(plan, "fl-state")
    legacy.ui(plan, "fl-engine-check")
    plan["route"] = legacy.route()
    if (plan["flclash"] != {"tun": True, "proxy": True} or not plan["route"].startswith("utun")
            or not legacy.fl_proxy_listening(plan)):
        raise RuntimeError("Start with FlClash engine, TUN and proxy on, and disconnect CoreaVPN")
    plan["device"], plan["service"] = runpy.run_path(str(SKILL / "assets/Puma-DNS/uplink.py"))["active_link"]()
    plan["dns"] = legacy.dns(plan["service"])
    if plan["dns"] == "127.0.0.1":
        raise RuntimeError("Stop the earlier temporary DNS relay before this test")
    legacy.verify_proxy_internet(plan)
    return plan


def worker(run, plan):
    # This process and its subprocesses all belong to the watchdog's isolated child process group.
    app_command(plan, "--pilot-ready")
    if legacy.route() != plan["route"] or legacy.dns(plan["service"]) != plan["dns"]:
        raise RuntimeError("Network baseline changed after preparation")
    legacy.verify_fl(plan)
    if not legacy.fl_proxy_listening(plan):
        raise RuntimeError("FlClash engine stopped after preparation")
    (run / "engine-stop-sent").touch()
    legacy.ui(plan, "fl-engine-stop")
    legacy.wait_for(lambda: not legacy.fl_proxy_listening(plan) and legacy.proxies_off()
                    and legacy.route() == plan["device"], 12, "Physical route did not clear")
    legacy.event(run, "physical-route-confirmed", interface=plan["device"])
    (run / "native-vpn-touched").touch()
    result = app_command(plan, "--pilot-puma", plan["device"], timeout=100)
    if result.get("sent") != 20 or type(result.get("received")) is not int or not 0 <= result["received"] <= 20:
        raise RuntimeError("Invalid twenty-probe result")
    legacy.save(run / "native-ping.json", result)
    # The native command itself has already restored its previous disconnected configuration.
    (run / "native-restored").touch()


def recover(run, plan):
    # Global pilot lock serializes against legacy and native pilots. This lock serializes
    # recovery attempts within this run and leaves every step retryable.
    with legacy.locked(run / "native-recovery.lock"):
        errors = []
        if (run / "native-vpn-touched").exists() and not (run / "native-restored").exists():
            try:
                app_command(plan, "--pilot-disconnect", timeout=35)
                (run / "native-restored").touch()
            except Exception as error:
                errors.append(str(error))
        if (run / "engine-stop-sent").exists():
            try:
                if not legacy.recover(run, plan):
                    errors.append("FlClash recovery incomplete; inspect recovered.json")
            except Exception as error:
                errors.append(str(error))
        try:
            app_command(plan, "--pilot-ready")
        except Exception as error:
            errors.append(str(error))
        try:
            # Verify connectivity even if the owned VPN failed its final readiness check.
            legacy.verify_fl(plan)
            if (legacy.dns(plan["service"]) != plan["dns"] or not legacy.route().startswith("utun")
                    or not legacy.fl_proxy_listening(plan)):
                raise RuntimeError("Physical service DNS, TUN route, or FlClash engine mismatch")
            legacy.verify_proxy_internet(plan)
        except Exception as error:
            errors.append(str(error))
        legacy.save(run / "native-recovered.json", {"ok": not errors, "errors": errors})
        return not errors


def supervisor(run, owner):
    plan = json.loads((run / "native-plan.json").read_text())
    child = None
    deadline = time.monotonic() + WATCHDOG_SECONDS
    try:
        os.kill(owner, 0)
        with (run / "worker.log").open("w") as log:
            child = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--worker", str(os.getpid()),
                                      "--log-dir", str(run)], stdin=DEVNULL, stdout=log,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        while child.poll() is None and time.monotonic() < deadline and not (run / "cancel").exists():
            try:
                os.kill(owner, 0)
            except ProcessLookupError:
                break
            time.sleep(0.25)
    finally:
        # Terminate any descendant still doing UI or VPN work before touching recovery.
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
        recovered = recover(run, plan)
    measurement = run / "native-ping.json"
    measured = child is not None and child.returncode == 0 and measurement.is_file()
    replies = json.loads(measurement.read_text())["received"] if measured else None
    passed = measured and replies > 0 and recovered
    legacy.save(run / "native-result.json", {"ok": passed, "measured": measured, "received": replies, "recovered": recovered})
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path)
    parser.add_argument("--ui", type=Path)
    parser.add_argument("--fl-map", type=Path)
    parser.add_argument("--fl-proxy-port", type=int, default=7890)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--watchdog", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    run = args.log_dir.resolve()
    if args.worker:
        if args.worker != os.getppid():
            raise RuntimeError("Worker requires its watchdog")
        worker(run, json.loads((run / "native-plan.json").read_text()))
        return 0
    if args.watchdog:
        if args.watchdog != os.getppid():
            raise RuntimeError("Watchdog owner exited before arming")
        return supervisor(run, args.watchdog)
    with legacy.locked(Path("/private/tmp") / f"coreavpn-offline-{os.getuid()}.lock", blocking=False) as lock:
        if args.recover:
            plan = json.loads((run / "native-plan.json").read_text())
            return 0 if recover(run, plan) else 1
        if not all((args.app, args.ui, args.fl_map)):
            parser.error("--app, --ui, and --fl-map are required")
        run.mkdir(mode=0o700, parents=True, exist_ok=False)
        plan = prepare(args)
        legacy.save(run / "native-plan.json", plan)
        legacy.event(run, "native-preflight-passed")
        if not args.run:
            print(json.dumps({"prepared": True, "network_changes": False, "run": str(run)}))
            return 0
        with (run / "watchdog.log").open("w") as log:
            guardian = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--watchdog", str(os.getpid()),
                                         "--log-dir", str(run)], start_new_session=True, stdin=DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT, pass_fds=(lock.fileno(),))
        print(f"Run log: {run}", flush=True)
        try:
            status = guardian.wait()
        except KeyboardInterrupt:
            (run / "cancel").touch()
            status = guardian.wait()
        result = run / "native-result.json"
        if result.is_file():
            print(result.read_text().strip())
        return status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(f"Native pilot stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
