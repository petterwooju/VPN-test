#!/usr/bin/env python3
"""Measure CoreaVPN tunnels locally and retain only an eligible or explicitly selected server."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import time

from quick_policy import DEFAULT_MEASUREMENT, MEASUREMENTS, OPERATIONS, retention_destination

SCRIPT = Path(__file__).resolve()
GLOBAL_LOCK = Path("/private/tmp") / f"coreavpn-offline-{os.getuid()}.lock"
TERMINAL = {"released", "no-match", "completed", "failed"}


def write_json(path, payload):
    temp = path.with_name(path.name + f".{os.getpid()}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False) + "\n")
    temp.replace(path)


def read_json(path):
    return json.loads(path.read_text())


def state(run, phase, sample=None, **details):
    if sample is not None:
        details.update(host=sample["server"], sample=sample)
    write_json(run / "quick-state.json", dict(phase=phase, **details))


def releasing(run):
    return (run / "release").exists() or run.with_name(run.name + ".release").exists()


def worker(run, guardian):
    import quick_candidates as candidates
    if os.getppid() != guardian:
        raise RuntimeError("Worker lost its watchdog before startup")
    plan = read_json(run / "plan.json")
    hosts = read_json(run / "quick-hosts.json")
    measurement = plan.get("measurement", DEFAULT_MEASUREMENT)
    operation = plan.get("operation", "quick")
    def cancelled():
        return releasing(run) or os.getppid() != guardian
    try:
        if cancelled():
            return 0
        candidates.verify_baseline(plan)
        if cancelled():
            return 0
        sample = candidates.search(run, plan, cancelled)
        if sample is None or cancelled():
            return 0
        destination = retention_destination(sample, hosts, measurement, operation)
        if destination is None:
            raise RuntimeError("Connection retention evidence could not be verified")
        if not candidates.still_connected(plan, sample["server"], sample["tunnel"], destination):
            raise RuntimeError("Qualifying sample or connected route could not be verified")
        # Never publish a winner until the measured tunnel is still up.
        (run / "health").touch()
        write_json(run / "winner.json", sample)
        while not cancelled():
            if not candidates.still_connected(plan, sample["server"], sample["tunnel"], destination):
                raise RuntimeError("The retained CoreaVPN connection was lost")
            (run / "health").touch()
            time.sleep(4)
        return 0
    except Exception as error:
        write_json(run / "worker-error.json", {"reason": str(error)})
        return 1
    finally:
        if os.getppid() != guardian and (run / "engine-stop-sent").exists():
            # Both processes inherit the global lock. If the guardian itself
            # dies after handoff, this worker owns recovery until it exits.
            held = run / "winner.json"
            sample = read_json(held) if held.exists() else None
            state(run, "recovering", sample, reason="Watchdog exited")
            ok = restore(run, plan)
            state(run, "failed", sample, reason="Watchdog exited", recovered=ok)


def stop_worker(run, proc):
    # An intentional stop may arrive between editing a field and dismissing
    # the dedicated profile sheet. Let an already-started edit settle before
    # recovery. A blocked probe or watchdog failure can be fenced immediately.
    if releasing(run):
        pending = run / "profile-edit-in-progress"
        deadline = time.monotonic() + 18
        while pending.exists() and proc.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
    # Abort outstanding UI/measurement subprocesses before restoring network state.
    if proc.poll() == 0:
        # A clean worker exit has joined its synchronous UI and probe subprocesses.
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if proc.poll() != 0:
            raise
    proc.wait(timeout=5)


def watch(run, proc, owner, hosts, measurement, operation):
    winner = None
    # A paired scan runs both bounded probes plus DNS, connect and disconnect.
    per_host = 235 if operation == "all" else 180
    deadline = time.monotonic() + 90 + per_host * len(hosts)
    last_heartbeat = None
    healthy_at = time.monotonic()
    while True:
        code = proc.poll()
        if releasing(run):
            return "released", winner, "Release requested"
        if winner is None and os.getppid() != owner:
            return "failed", None, "Search launcher exited before connection handoff"
        if code is not None:
            failure = run / "worker-error.json"
            if failure.exists():
                return "failed", winner, read_json(failure)["reason"]
            if code or winner is not None:
                return "failed", winner, "Search or retained connection monitor stopped"
            if operation == "all":
                return "completed", None, "All eligible candidates examined"
            if operation == "select":
                return "failed", None, "The selected server could not be retained"
            return "no-match", None, f"No candidate met the {measurement.upper()} measurement thresholds"
        if winner is None:
            if (run / "winner.json").exists():
                winner = read_json(run / "winner.json")
                if retention_destination(winner, hosts, measurement, operation) is None:
                    return "failed", None, "Invalid measured winner"
                state(run, "retained", winner)
            elif time.monotonic() >= deadline:
                return "failed", None, "Search watchdog timed out"
        else:
            heartbeat = (run / "health").stat().st_mtime_ns
            if heartbeat != last_heartbeat:
                last_heartbeat, healthy_at = heartbeat, time.monotonic()
            elif time.monotonic() - healthy_at > 45:
                return "failed", winner, "Retained connection health monitor timed out"
        time.sleep(0.2)


def restore(run, plan):
    import quick_candidates as candidates
    if not (run / "engine-stop-sent").exists():
        return True
    for _ in range(2):
        try:
            if candidates.recover(run, plan):
                return True
        except Exception as error:
            write_json(run / "recovery-error.json", {"reason": str(error)})
    return False


class StopGuardian(Exception):
    pass


def on_stop(_signal, _frame):
    raise StopGuardian("Search watchdog received a stop signal")


def supervise(run, owner, lock_fd):
    if os.getppid() != owner:
        raise RuntimeError("Launch process exited before watchdog was ready")
    plan, hosts = read_json(run / "plan.json"), read_json(run / "quick-hosts.json")
    measurement = plan.get("measurement", DEFAULT_MEASUREMENT)
    operation = plan.get("operation", "quick")
    phase, winner, reason = "failed", None, "Search did not start"
    proc = None
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_stop)
    try:
        (run / "watchdog-ready").write_text(str(os.getpid()))
        if releasing(run):
            phase, reason = "released", "Release requested before starting"
        else:
            state(run, "searching")
            with (run / "worker.log").open("w") as log:
                proc = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--worker", str(os.getpid()),
                                         "--log-dir", str(run)], stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, start_new_session=True, pass_fds=(lock_fd,))
            phase, winner, reason = watch(run, proc, owner, hosts, measurement, operation)
    except (Exception, KeyboardInterrupt) as error:
        reason = str(error)
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        if proc is not None:
            stop_worker(run, proc)
        if winner is None and (run / "winner.json").exists():
            result = read_json(run / "winner.json")
            if retention_destination(result, hosts, measurement, operation) is not None:
                winner = result
        outcome = phase
        state(run, "recovering", winner, reason=reason, outcome=outcome)
        ok = restore(run, plan)
        if not ok:
            phase = "failed"
            reason += "; network recovery incomplete"
        state(run, phase, winner, reason=reason, outcome=outcome, recovered=ok)
    return int(phase == "failed")


def launch(run, args, lock):
    import quick_candidates as candidates
    run.mkdir(mode=0o700, parents=True, exist_ok=False)
    state(run, "preparing")
    try:
        if releasing(run):
            state(run, "released", reason="Release requested before preflight", recovered=True)
            return 0
        plan = candidates.prepare(run, args.ui, args.fl_map, args.hosts, args.measurement,
                                  args.operation, args.expected_device, args.expected_prefix)
        write_json(run / "plan.json", plan)
        write_json(run / "quick-hosts.json", args.hosts)
        command = shlex.join([sys.executable, "-B", str(SCRIPT), "--log-dir", str(run)])
        (run / "recovery.txt").write_text(
            "Click CoreaVPN 해제 in the Mac app, or run this command locally:\n"
            + command + " --release\n"
            f"The watchdog disconnects {candidates.PROFILE}, restores its original endpoints, "
            "and verifies FlClash engine, TUN, proxies and Internet access. "
            "The original network and profile are recorded in plan.json.\n"
            "If quick-state.json reports incomplete recovery, retry with:\n"
            + command + " --recover\n")
        if not args.run:
            state(run, "prepared", network_changes=False)
            return 0
        with (run / "guardian.log").open("w") as log:
            guardian = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "--guardian", str(os.getpid()), "--lock-fd", str(lock.fileno()),
                                         "--log-dir", str(run)], stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, pass_fds=(lock.fileno(),), start_new_session=True)
    except Exception as error:
        state(run, "failed", reason=str(error), recovered=True)
        raise
    while guardian.poll() is None:
        try:
            if read_json(run / "quick-state.json")["phase"] == "retained":
                # Handoff is durable and the independent guardian inherited the global lock.
                return 0
            time.sleep(0.25)
        except KeyboardInterrupt:
            (run / "release").touch()
    status = read_json(run / "quick-state.json")
    if status["phase"] not in TERMINAL:
        # Unexpected guardian death; worker detects reparenting. Fence remaining
        # worker group before starting cleanup from the still-live launcher.
        return retry_recovery(run, interrupted=True)
    return guardian.returncode


def retry_recovery(run, interrupted=False):
    old = read_json(run / "quick-state.json")
    if old.get("recovered") is True:
        return 0
    sample = old.get("sample")
    if interrupted or old["phase"] not in TERMINAL:
        stale = run / "worker-group.json"
        if stale.exists():
            group = read_json(stale)["pid"]
            # Never send a signal based solely on a PID from a previous boot.
            output = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,command="],
                                    capture_output=True, text=True, check=True).stdout
            prefix = f"{SCRIPT} --worker "
            for line in output.splitlines():
                fields = line.strip().split(None, 2)
                if (len(fields) == 3 and fields[:2] == [str(group), str(group)] and prefix in fields[2]
                        and fields[2].endswith("--log-dir " + str(run))):
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    break
    outcome = "failed" if interrupted else old.get("outcome", "released")
    if outcome not in TERMINAL:
        outcome = "failed"
    state(run, "recovering", sample, reason="Recovery retry", outcome=outcome)
    ok = restore(run, read_json(run / "plan.json"))
    state(run, outcome if ok else "failed", sample, outcome=outcome,
          reason="Recovery verified" if ok else "Recovery incomplete", recovered=ok)
    return int(not ok or interrupted)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ui", type=Path)
    parser.add_argument("--fl-map", type=Path)
    parser.add_argument("--hosts", nargs="+")
    parser.add_argument("--expected-device", help="Physical interface recorded by the app")
    parser.add_argument("--expected-prefix", help="IPv4 subnet recorded by the app")
    parser.add_argument("--operation", choices=OPERATIONS, default="quick",
                        help="Stop on first pass, scan both probes, or connect only the clicked server")
    parser.add_argument("--measurement", choices=MEASUREMENTS, default=DEFAULT_MEASUREMENT,
                        help="Choose HTTPS throughput and latency or ICMP ping")
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--release", action="store_true")
    parser.add_argument("--recover", action="store_true")
    parser.add_argument("--guardian", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--lock-fd", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--worker", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    run = args.log_dir.resolve()
    os.umask(0o077)
    if args.worker:
        if args.worker != os.getppid():
            raise RuntimeError("No watchdog")
        write_json(run / "worker-group.json", {"pid": os.getpid()})
        return worker(run, args.worker)
    if args.guardian:
        if args.lock_fd is None:
            parser.error("Watchdog requires its launcher's lock")
        return supervise(run, args.guardian, args.lock_fd)
    if args.release:
        if not run.is_dir():
            parser.error("Unknown run directory")
        (run / "release").touch(mode=0o600)
        return 0
    with GLOBAL_LOCK.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.recover:
            return retry_recovery(run)
        if not args.ui or not args.fl_map or not args.hosts:
            parser.error("--ui, --fl-map, --hosts are required to prepare a new run")
        return launch(run, args, lock)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (KeyboardInterrupt, Exception) as error:
        print(f"Quick search stopped: {error}", file=sys.stderr)
        raise SystemExit(1)
