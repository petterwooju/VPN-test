#!/usr/bin/env python3
"""Verify a single HTTPS exit through a named mihomo group, without changing system routing."""

import argparse
from contextlib import contextmanager
import errno
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

HOST = "api.ipify.org"
SUPPORTED = {"ss": "shadowsocks", "anytls": "anytls"}
CAP = 12 * 1024 * 1024


class CheckFailed(Exception):
    pass


def api(port, token, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        conn.request("GET", path, headers={"Authorization": "Bearer " + token} if token else {})
        response = conn.getresponse()
        if response.status != 200:
            raise CheckFailed(f"Local controller returned HTTP {response.status}.")
        data = response.read(CAP + 1)
        if len(data) > CAP:
            raise CheckFailed("Local controller response exceeded the size limit.")
        return json.loads(data)
    finally:
        conn.close()


def take(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            raise CheckFailed("The local SOCKS connection closed early.")
        data.extend(part)
    return bytes(data)


def socks_handshake(sock):
    sock.sendall(b"\x05\x01\x00")
    if take(sock, 2) != b"\x05\x00":
        raise CheckFailed("An unauthenticated local SOCKS5 listener is required.")
    domain = HOST.encode("ascii")
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack(">H", 443))
    version, status, reserved, address_type = take(sock, 4)
    if (version, status, reserved) != (5, 0, 0):
        raise CheckFailed(f"SOCKS5 connection to the probe failed ({status}).")
    lengths = {1: 4, 4: 16}
    length = take(sock, 1)[0] if address_type == 3 else lengths.get(address_type)
    if length is None:
        raise CheckFailed("Malformed SOCKS5 response.")
    take(sock, length + 2)


def verify_chain(controller, token, port, group, expected_type):
    expires = time.monotonic() + 3
    while time.monotonic() < expires:
        active = api(controller, token, "/connections").get("connections") or []
        matches = []
        for conn in active:
            meta = conn.get("metadata", {})
            if (meta.get("host", "").lower() == HOST and str(meta.get("destinationPort")) == "443"
                    and str(meta.get("sourcePort")) == str(port)):
                matches.append(conn.get("chains") or [])
        if len(matches) > 1:
            raise CheckFailed("Multiple connections matched the probe.")
        if matches:
            chain = matches[0]
            if not chain or group not in chain or any(str(v).upper() in ("DIRECT", "REJECT") for v in chain):
                raise CheckFailed("The probe connection did not traverse the requested group.")
            types = api(controller, token, "/proxies").get("proxies", {})
            leaf_type = str(types.get(chain[0], {}).get("type", "")).lower()
            if leaf_type != SUPPORTED[expected_type]:
                raise CheckFailed("The actual proxy protocol differed from the requested protocol.")
            return
        time.sleep(0.12)
    raise CheckFailed("The live connection could not be attributed to the probe socket.")


def check_exit(socks_port, controller_port, token, group, protocol):
    # Controller/token remain on loopback. Only the observer receives the HTTPS GET.
    api(controller_port, token, "/version")
    with socket.create_connection(("127.0.0.1", socks_port), timeout=12) as raw:
        source_port = raw.getsockname()[1]
        socks_handshake(raw)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=HOST) as tls:
            verify_chain(controller_port, token, source_port, group, protocol)
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n".encode("ascii"))
            response = http.client.HTTPResponse(tls)
            response.begin()
            if response.status != 200:
                raise CheckFailed(f"The HTTPS IP observer returned HTTP {response.status}.")
            ip = ipaddress.ip_address(response.read(65).decode("ascii").strip())
            if not ip.is_global:
                raise CheckFailed("The observer did not return a public exit IP.")
            return str(ip)


def load_node(path, group, protocol, explicit_node):
    # Read only this local profile. Keep its contents in process memory.
    with path.open("rb") as source:
        profile_data = source.read(CAP + 1)
    if len(profile_data) > CAP:
        raise CheckFailed("The profile exceeds the size limit.")
    ruby = "require 'yaml'; require 'json'; print JSON.generate(YAML.safe_load(STDIN.read, aliases: true))"
    result = subprocess.run(["/usr/bin/ruby", "-e", ruby], input=profile_data, capture_output=True, timeout=8)
    if result.returncode:
        raise CheckFailed("The local YAML profile could not be parsed.")
    profile = json.loads(result.stdout)
    groups = {g["name"]: g for g in profile.get("proxy-groups", [])}
    proxies = {n["name"]: n for n in profile.get("proxies", [])}
    if group is None:
        group = next((r.split(",", 1)[1] for r in reversed(profile.get("rules", []))
                      if isinstance(r, str) and r.startswith("MATCH,")), None)
    if group not in groups:
        raise CheckFailed("Specify a proxy group present in the selected local profile.")
    seen = set()

    def find(name):
        if name in seen:
            return None
        seen.add(name)
        node = proxies.get(name)
        if node and node.get("type") == protocol and (explicit_node is None or explicit_node == name):
            if node.get("dialer-proxy"):
                return None
            return node
        for member in groups.get(name, {}).get("proxies", []):
            found = find(member)
            if found:
                return found
        return None

    node = find(group)
    if node is None:
        raise CheckFailed("No matching inline node belongs to the selected group.")
    return group, node


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def isolated(args):
    group, node = load_node(args.profile, args.group, args.protocol, args.node)
    socket.if_nametoindex(args.interface)
    controller, socks_port = unused_port(), unused_port()
    while controller == socks_port:
        socks_port = unused_port()
    token = secrets.token_urlsafe(32)
    node = {**node, "interface-name": args.interface}
    config = {"socks-port": socks_port, "allow-lan": False, "bind-address": "127.0.0.1",
              "mode": "rule", "ipv6": False, "log-level": "silent", "interface-name": args.interface,
              "geo-auto-update": False, "tun": {"enable": False}, "dns": {"enable": False},
              "profile": {"store-selected": False, "store-fake-ip": False},
              "external-controller": f"127.0.0.1:{controller}", "secret": token,
              "proxies": [node], "proxy-groups": [{"name": group, "type": "select", "proxies": [node["name"]]}],
              "rules": ["MATCH," + group]}
    with tempfile.TemporaryDirectory(prefix="coreavpn-proxy-lab-") as folder:
        fifo = Path(folder, "profile.pipe")
        os.mkfifo(fifo, 0o600)
        core = subprocess.Popen([str(args.core.resolve()), "-d", folder, "-f", str(fifo)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        try:
            until = time.monotonic() + 12
            while True:
                try:
                    writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError as e:
                    if e.errno != errno.ENXIO or time.monotonic() >= until or core.poll() is not None:
                        raise CheckFailed("The isolated core did not open its configuration FIFO.") from None
                    time.sleep(0.04)
            with os.fdopen(writer, "wb") as pipe:
                os.set_blocking(pipe.fileno(), True)
                pipe.write(json.dumps(config, ensure_ascii=False).encode())
            while time.monotonic() < until:
                if core.poll() is not None:
                    raise CheckFailed("The isolated core rejected the selected node/configuration.")
                try:
                    api(controller, token, "/version")
                    break
                except OSError:
                    time.sleep(0.08)
            else:
                raise CheckFailed("The isolated core's loopback controller did not start.")
            yield socks_port, controller, token, group
        finally:
            core.terminate()
            try:
                core.wait(timeout=3)
            except subprocess.TimeoutExpired:
                core.kill()
                core.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=SUPPORTED, required=True)
    parser.add_argument("--group", help="exact local proxy group; defaults to the isolated profile's MATCH group")
    parser.add_argument("--show-ip", action="store_true", help="display the measured public address in this terminal")
    modes = parser.add_subparsers(dest="mode", required=True)
    lab = modes.add_parser("isolated", help="test a selected group member with a separate loopback-only mihomo")
    lab.add_argument("--profile", type=Path, required=True)
    lab.add_argument("--interface", required=True, help="physical interface such as en6")
    lab.add_argument("--node", help="exact node name within the selected group; default first matching protocol")
    lab.add_argument("--core", type=Path, required=True, help="path to a trusted mihomo executable")
    active = modes.add_parser("existing", help="read-only measurement with an already available localhost controller")
    active.add_argument("--socks-port", type=int, required=True)
    active.add_argument("--controller-port", type=int, required=True)
    args = parser.parse_args()
    if args.mode == "isolated":
        with isolated(args) as (port, controller, token, group):
            ip = check_exit(port, controller, token, group, args.protocol)
    else:
        if not args.group:
            parser.error("existing mode requires --group")
        group = args.group
        ip = check_exit(args.socks_port, args.controller_port, os.environ.get("MIHOMO_READ_TOKEN", ""),
                        group, args.protocol)
    result = {"verified": True, "mode": args.mode, "group": group, "protocol": args.protocol, "public_exit": True}
    if args.show_ip:
        result["exit_ip"] = ip
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, CheckFailed, EOFError, subprocess.TimeoutExpired, http.client.HTTPException) as exc:
        # Core log lines and profile contents can include credentials.
        message = str(exc) if isinstance(exc, CheckFailed) else type(exc).__name__
        sys.exit(f"Group egress unverified: {message}")
