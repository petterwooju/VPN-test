"""Build and publish the preview at its single per-user installation path."""
import ctypes
import os
from pathlib import Path
import plistlib
import runpy
import subprocess
import tempfile

TOOLS = Path(__file__).resolve().parent
APPS = Path.home() / "Applications"
APP = APPS / "CoreaVPN.app"
RUNTIME = Path.home() / "Library/Application Support/CoreaVPN/LocalRuntime"


def publish(bundle):
    if APP.is_symlink():
        raise ValueError(f"Unexpected symlink at {APP}")
    if not APP.exists():
        bundle.rename(APP)
        return
    with (APP / "Contents/Info.plist").open("rb") as stream:
        if plistlib.load(stream)["CFBundleIdentifier"] != "net.petterwooju.coreavpn.preview":
            raise ValueError(f"Another app occupies {APP}")
    # Darwin RENAME_SWAP atomically exchanges two directories on one volume.
    swap = ctypes.CDLL(None, use_errno=True).renamex_np
    if swap(os.fsencode(bundle), os.fsencode(APP), 2):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), APP)


def main():
    APPS.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".coreavpn-update-", dir=APPS) as temporary:
        stage = Path(temporary)
        env = os.environ.copy()
        calibration = Path(env.get("COREAVPN_QUICK_MAP", RUNTIME / "build/fl-map.json"))
        if calibration.is_file():
            helpers = stage / "helpers"
            subprocess.run([TOOLS / "build-local-quick.sh", helpers], check=True)
            env["COREAVPN_QUICK_UI"] = str(helpers / "offline-ui-quick")
        elif RUNTIME.joinpath("current").exists() or "COREAVPN_QUICK_MAP" in env:
            raise ValueError(f"Missing local calibration: {calibration}")
        subprocess.run([TOOLS / "build-preview-mac.sh", stage], env=env, check=True)
        bundle = stage / APP.name
        if (stage / "LocalRuntime").is_dir():
            install = runpy.run_path(str(TOOLS / "install-preview-runtime.py"))["install"]
            install(stage, RUNTIME, publish=lambda: publish(bundle))
        else:
            publish(bundle)
    print(APP)


if __name__ == "__main__":
    main()
