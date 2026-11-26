"""Physical Mac acceptance checks. Arm before clicking the app's search button."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


def read(path):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}


def route():
    output = subprocess.check_output(["/sbin/route", "-n", "get", "168.126.63.1"], text=True, timeout=5)
    match = re.search(r"^\s*interface:\s*(\S+)$", output, re.M)
    return match.group(1) if match else ""


def watch(run, ui, case):
    deadline = time.monotonic() + 55 * 60
    held_since = None
    report = {"case": case}
    report_file = run / "acceptance-check.json"
    while time.monotonic() < deadline:
        state = read(run / "quick-state.json")
        phase = state.get("phase")
        if phase in ("failed", "no-match", "released"):
            print(json.dumps(state), flush=True)
            return
        if case in ("release-button", "release-during-check") and phase == "retained" and "buttonPressed" not in report:
            tunnel = state["sample"]["tunnel"]
            if route() != tunnel:
                raise RuntimeError("Retained route changed before the release check")
            if held_since is None:
                held_since = time.monotonic()
            if time.monotonic() - held_since >= 12:
                try:
                    response = subprocess.check_output([ui, "quick-press-release"], text=True, timeout=12)
                    report["buttonPressed"] = json.loads(response).get("pressed") is True
                finally:
                    report.update(host=state["host"], tunnel=tunnel, heldSeconds=round(time.monotonic() - held_since, 2))
                    report_file.write_text(json.dumps(report))
                if not report["buttonPressed"]:
                    raise RuntimeError("App release button did not confirm its action")
        if case == "release-during-check" and phase == "searching" and "buttonPressed" not in report:
            active = read(run / "active-profile.json")
            if active.get("server") and active["server"] != "leo.coreavpn.net" and re.fullmatch(r"ipsec\d+", route()):
                response = subprocess.check_output([ui, "quick-press-release"], text=True, timeout=12)
                report.update(host=active["server"], phase=phase, buttonPressed=json.loads(response).get("pressed") is True)
                report_file.write_text(json.dumps(report))
        if case == "worker-failure" and phase == "searching" and "workerStopped" not in report:
            if (run / "active-profile.json").exists() and re.fullmatch(r"ipsec\d+", route()):
                pid = read(run / "worker-group.json")["pid"]
                command = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "command="], text=True, timeout=5)
                if os.getpgid(pid) != pid or "quick-search.py --worker " not in command or str(run) not in command:
                    raise RuntimeError("Worker does not belong to this run")
                os.kill(pid, signal.SIGTERM)
                report["workerStopped"] = pid
                report_file.write_text(json.dumps(report))
        time.sleep(0.5)
    raise TimeoutError("Local acceptance check timed out")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("case", choices=["release-button", "release-during-check", "worker-failure"])
    parser.add_argument("--run-directory", type=Path, help="Observe one new explicitly named acceptance run")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    if args.run_directory:
        run = args.run_directory.resolve()
        if run.parent != workspace / "runs" or run.exists():
            parser.error("Expected a new run directly under the workspace runs folder")
        watch(run, workspace / "build/offline-ui-quick", args.case)
        return
    receipts = Path.home() / "Library/Application Support/CoreaVPN/LocalQuickSearch"
    previous = set(receipts.glob("*"))
    print("Waiting for the next app-owned quick search", flush=True)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        new = [x for x in receipts.glob("*") if x not in previous and x.is_dir()]
        if len(new) > 1:
            raise RuntimeError("Multiple new app runs")
        if new:
            request = str(uuid.UUID(new[0].name)).upper()
            run = workspace / "runs" / (request + "-quick-search")
            print(run, flush=True)
            try:
                watch(run, workspace / "build/offline-ui-quick", args.case)
            except Exception:
                # Release only this acceptance-test request if its UI check fails.
                run.with_name(run.name + ".release").touch(mode=0o600)
                raise
            return
        time.sleep(0.3)
    raise TimeoutError("No new app request")


if __name__ == "__main__":
    main()
