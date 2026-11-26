"""Copy the last displayed local reports when installing the standalone Mac preview."""
import json
from pathlib import Path
import plistlib
import re
import shutil
import tempfile
import uuid


def _request_id(value):
    try:
        return str(uuid.UUID(str(value))).upper()
    except ValueError:
        return None


def _saved_requests(support):
    # The bundle identifier and its defaults are shared with the previous preview.
    prefs = support.parent.parent / "Preferences/net.petterwooju.coreavpn.preview.plist"
    if not prefs.is_file():
        return [], None
    values = plistlib.loads(prefs.read_bytes())
    reports = []
    for key in ("localQuickSearchRequest.v1", "localFullComparisonRequest.v1"):
        raw = values.get(key)
        if isinstance(raw, bytes):
            request = json.loads(raw)
            run_id = _request_id(request.get("id"))
            if run_id and run_id not in reports:
                reports.append(run_id)
    return reports, _request_id(values.get("localPumaTerminalRequest"))


def _copy_report(source, destination, quick):
    if destination.exists() or not source.exists():
        return
    if source.is_symlink() or not source.is_dir():
        raise ValueError(f"Expected a local report directory: {source}")
    fields = {"events.jsonl", "ping-results.jsonl", "https-results.jsonl", "plan.json", "recovered.json", "finished",
              "quick-state.json", "quick-hosts.json", "winner.json", "engine-stop-sent"}
    if quick and (source / "quick-state.json").is_file():
        state = json.loads((source / "quick-state.json").read_bytes())
        if state["phase"] not in {"completed", "released", "no-match", "failed"}:
            raise ValueError(f"Finish or release the previous quick search before installing: {source}")
    touched = any((source / marker).exists() for marker in ("engine-stop-sent", "relay-touched", "vpn-touched"))
    if touched:
        recovery = source / "recovered.json"
        if not recovery.is_file() or json.loads(recovery.read_bytes()).get("ok") is not True:
            raise ValueError(f"Finish network recovery in the previous app before installing: {source}")
    # Publish a complete report at once. Raw ping and state timestamps are part
    # of the evidence. The watchdog, release commands and PID files belong to the old run.
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        report = Path(tmp) / source.name
        report.mkdir(mode=0o700)
        for path in source.iterdir():
            if path.name not in fields and not re.fullmatch(r"ping-[a-z0-9.-]+-[0-9a-f]+\.txt", path.name):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Expected a regular report file: {path}")
            shutil.copy2(path, report / path.name)
        report.rename(destination)


def migrate_history(legacy_workspace, runtime, support):
    source = Path(legacy_workspace).resolve() / "runs"
    target = Path(runtime).resolve() / "runs"
    if source == target or not source.is_dir():
        return
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    quick, puma = _saved_requests(Path(support))
    for run_id in quick:
        name = f"{run_id}-quick-search"
        _copy_report(source / name, target / name, quick=True)

    publication = source / "imported-comparison.json"
    new_publication = target / publication.name
    if publication.is_file() and not publication.is_symlink() and not new_publication.exists():
        receipt = json.loads(publication.read_bytes())
        run_id = _request_id(receipt.get("id"))
        if run_id and receipt.get("imported") is True and receipt.get("operation") == "all":
            name = f"{run_id}-imported-comparison"
            _copy_report(source / name, target / name, quick=True)
            if (target / name).is_dir():
                with new_publication.open("xb") as output:
                    output.write(publication.read_bytes())

    name = None
    if puma:
        name = f"{puma}-puma-pilot"
        _copy_report(source / name, target / name, quick=False)
    pointer = source / "latest-puma-run.txt"
    if pointer.is_file() and not pointer.is_symlink():
        last = Path(pointer.read_text().strip())
        if (last.parent == source and
                re.fullmatch(r"(?:\d{8}-\d{6}|[0-9a-fA-F-]{36})-puma-pilot", last.name)):
            name = last.name
            _copy_report(source / name, target / name, quick=False)
    if name:
        new_pointer = target / "latest-puma-run.txt"
        if (target / name).is_dir() and not new_pointer.exists():
            with new_pointer.open("x") as output:
                output.write(str(target / name) + "\n")
