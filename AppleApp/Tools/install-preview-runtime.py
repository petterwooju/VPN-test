#!/usr/bin/env python3
"""Install this Mac's staged preview helpers without putting the project under Documents in the launch path."""
import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile

SKILL = Path("VPN-test/plugins/coreavpn-macos/skills/coreavpn-macos")
FILES = (
    Path("Run-Puma.command"),
    SKILL / "assets/servers.json",
    *(Path("build") / name for name in ("fl-map.json", "offline-ui-next", "offline-ui-quick", "quick-resolve")),
    *(SKILL / "scripts" / name for name in ("offline-pilot.py", "quick-search.py", "quick_candidates.py",
                                            "quick_policy.py", "https_speed.py", "vpn-ping.py")),
    *(SKILL / "assets/Puma-DNS" / name for name in ("relay.py", "session.py", "uplink.py")),
)
LAUNCHER = """#!/bin/bash
set -euo pipefail
base="$(cd "$(dirname "$0")" && pwd -P)"
export COREAVPN_PUMA_RUNTIME="$base"
export COREAVPN_PUMA_MAP="$base/build/fl-map.json"
exec "$base/current/Run-Puma.command" "$@"
"""
LOCK = Path("/private/tmp") / f"coreavpn-offline-{os.getuid()}.lock"


def install(staged, runtime, legacy=None, publish=None):
    source = staged / "LocalRuntime"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    if runtime.is_symlink():
        raise ValueError("Expected a local directory for the runtime")
    with os.fdopen(os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("A VPN check or recovery is active. Finish or release it before updating.") from None
        for name in ("runs", "releases"):
            folder = runtime / name
            if folder.is_symlink():
                raise ValueError(f"Expected a real directory for {folder}")
            folder.mkdir(mode=0o700, exist_ok=True)

        with tempfile.TemporaryDirectory(prefix=".install-", dir=runtime / "releases") as temp:
            scratch = Path(temp)
            package = scratch / "payload"
            digest = hashlib.sha256()
            for rel in FILES:
                original, copy = source / rel, package / rel
                if not original.is_file() or original.is_symlink():
                    raise ValueError(f"Missing regular staging input: {original}")
                copy.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copy2(original, copy)
                executable = rel.name in {"Run-Puma.command", "offline-ui-next", "offline-ui-quick", "quick-resolve"}
                copy.chmod(0o700 if executable else 0o600)
                digest.update(os.fsencode(rel) + b"\0" + hashlib.sha256(copy.read_bytes()).digest())
            if "COREAVPN_PUMA_RUNTIME" not in (package / "Run-Puma.command").read_text():
                raise ValueError("The staged Puma launcher does not support a separate runtime")
            release = Path("releases") / digest.hexdigest()
            current = runtime / "current"
            if current.exists() and not current.is_symlink():
                raise ValueError(f"Unexpected existing file at {current}")
            if not (runtime / release).exists():
                package.rename(runtime / release)
            # These two public paths are the existing Swift / Python launcher contract.
            # Run evidence stays directly in runs/ and survives code generation switches.
            for name in ("VPN-test", "build"):
                link, target = runtime / name, Path("current") / name
                if link.is_symlink() and os.readlink(link) == str(target):
                    continue
                link.symlink_to(target)

            if legacy is not None:
                from preview_history import migrate_history
                migrate_history(legacy, runtime, runtime.parent)

            launcher = runtime / "Run-Puma.command"
            if launcher.is_symlink() or (launcher.exists() and launcher.read_text() != LAUNCHER):
                raise ValueError(f"Unexpected existing launcher at {launcher}")
            if not launcher.exists():
                entry = scratch / "Run-Puma.command"
                entry.write_text(LAUNCHER)
                entry.chmod(0o700)
                entry.replace(launcher)
            selection = scratch / "current"
            selection.symlink_to(release)
            previous = os.readlink(current) if current.is_symlink() else None
            selection.replace(current)
            if publish is not None:
                try:
                    publish()
                except BaseException:
                    if previous is None:
                        current.unlink()
                    else:
                        selection.symlink_to(previous)
                        selection.replace(current)
                    raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", type=Path, help="Output directory of build-preview-mac.sh")
    parser.add_argument("--destination", type=Path, default=Path.home() / "Library/Application Support/CoreaVPN/LocalRuntime")
    parser.add_argument("--migrate-from", type=Path, help="Previous pilot workspace for this Mac")
    args = parser.parse_args()
    install(args.stage.absolute(), args.destination.absolute(), args.migrate_from)
    print(args.destination)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(str(error))
