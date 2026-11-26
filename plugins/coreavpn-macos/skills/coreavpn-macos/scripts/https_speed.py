#!/usr/bin/env python3
"""Measure HTTPS throughput and response time on one verified macOS IKEv2 route."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
from statistics import mean
import subprocess
import sys
import time
from uuid import uuid4


TARGET = "speed.cloudflare.com"
IP_BOUND_IF = 25  # Darwin <netinet/in.h>; Python does not export this socket option.
LATENCY_SAMPLES = 20
CONNECT_SECONDS = 2
IDLE_SECONDS = 12
TRANSFER_SECONDS = 6
PARALLEL_CONNECTIONS = 4
DOWNLOAD_PER_CONNECTION = 4 * 1024 * 1024
UPLOAD_PER_CONNECTION = 1024 * 1024
UPLOAD_BLOCK = 256 * 1024
WARMUP_BYTES = 64 * 1024
HTTP_FAILURES = (OSError, http.client.HTTPException)


def public_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("The HTTPS probe requires a public IPv4 peer")
    return str(address)


def resolve_peer():
    answers = socket.getaddrinfo(TARGET, 443, socket.AF_INET, socket.SOCK_STREAM)
    for *_, address in answers:
        try:
            return public_ipv4(address[0])
        except ValueError:
            continue
    raise RuntimeError(f"No public IPv4 answer for {TARGET}")


def route_interface(peer_ipv4):
    process = subprocess.run(
        ["/sbin/route", "-n", "get", "-inet", public_ipv4(peer_ipv4)],
        capture_output=True, text=True, timeout=5,
    )
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", process.stdout, re.M)
    if process.returncode or not match:
        raise RuntimeError("Cannot verify the HTTPS measurement route")
    return match[1]


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("HTTPS measurement deadline reached")
    return seconds


class DownloadResponseError(http.client.HTTPException):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def download_error_kind(error):
    if isinstance(error, DownloadResponseError):
        return error.kind
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, (http.client.IncompleteRead, http.client.RemoteDisconnected, ssl.SSLEOFError)):
        return "early_eof"
    if isinstance(error, ssl.SSLError):
        return "tls"
    if isinstance(error, ConnectionResetError):
        return "connection_reset"
    return "socket" if isinstance(error, OSError) else "http"


class BoundHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, peer_ipv4, tunnel, interface_index, context):
        super().__init__(TARGET, timeout=CONNECT_SECONDS, context=context)
        self.peer_ipv4 = peer_ipv4
        self.tunnel = tunnel
        self.interface_index = interface_index
        self.deadline = 0

    def connect(self):
        # Bind before connecting to a pinned A record. The URL, Host header and
        # validated TLS SNI remain speed.cloudflare.com.
        self.stage = "tcp_connect"
        if sys.platform != "darwin" or socket.if_nametoindex(self.tunnel) != self.interface_index:
            raise OSError("The verified IKEv2 interface is unavailable")
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(min(CONNECT_SECONDS, remaining(self.deadline)))
            raw.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, self.interface_index)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw.connect((self.peer_ipv4, 443))
            raw.settimeout(min(CONNECT_SECONDS, remaining(self.deadline)))
            self.stage = "tls_handshake"
            self.sock = self._context.wrap_socket(raw, server_hostname=TARGET)
        except BaseException:
            raw.close()
            raise

    def begin(self, deadline):
        self.deadline = deadline
        if self.sock is None:
            self.connect()
        self.sock.settimeout(remaining(deadline))

    def response(self, deadline, *, download=None, upload=None, on_sent=None):
        self.stage = "request"
        self.begin(deadline)
        self.stage = "request"
        headers = {"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}
        nonce = uuid4().hex
        if upload is None:
            self.request("GET", f"/__down?bytes={download}&nonce={nonce}", headers=headers)
        else:
            headers["Content-Type"] = "application/octet-stream"
            self.request("POST", f"/__up?nonce={nonce}", body=upload, headers=headers)
        if on_sent is not None:
            on_sent()  # The complete HTTP request has been handed to the TLS socket.
        self.stage = "response_headers"
        self.sock.settimeout(remaining(deadline))
        # HTTPConnection can detach a socket when the server closes after this
        # response. Our socket reference still controls the response read timeout.
        response_socket = self.sock
        response = self.getresponse()
        if not 200 <= response.status < 300:
            response.close()
            raise DownloadResponseError("http_status", f"HTTPS measurement server returned {response.status}")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            response.close()
            raise DownloadResponseError("encoding", "Unexpected encoding on HTTPS measurement response")
        return response, response_socket


def latency_request(connection, deadline, on_sent=None):
    try:
        connection.begin(deadline)  # DNS, TCP and TLS are outside the latency sample.
        started = time.monotonic()
        response, peer_socket = connection.response(deadline, download=0, on_sent=on_sent)
        with response:
            peer_socket.settimeout(remaining(deadline))
            if response.read(1):
                raise http.client.HTTPException("Non-empty HTTPS latency response")
        return (time.monotonic() - started) * 1000
    except HTTP_FAILURES:
        connection.close()
        return None


def receive(connection, size, deadline, diagnostic=None):
    started = time.monotonic()
    count = 0
    stage = None
    try:
        response, peer_socket = connection.response(deadline, download=size)
        with response:
            stage = "response_headers"
            if response.length is not None and response.length != size:
                raise DownloadResponseError("length", f"Expected {size} bytes, received Content-Length {response.length}")
            stage = "body"
            while count < size:
                peer_socket.settimeout(remaining(deadline))
                block = response.read1(min(64 * 1024, size - count))
                if not block:
                    raise DownloadResponseError("early_eof", "Response body ended before the requested size")
                count += len(block)
            stage = "end_validation"
            peer_socket.settimeout(remaining(deadline))
            if response.read(1):
                count += 1
                raise DownloadResponseError("length", "HTTPS download exceeded the requested size")
        if diagnostic is not None:
            diagnostic.update(status="complete", stage="complete")
        return count
    except HTTP_FAILURES as error:
        if isinstance(error, http.client.IncompleteRead):
            count += len(error.partial)
        if diagnostic is not None:
            diagnostic.update(status="failed", stage=stage or connection.stage,
                              error_type=download_error_kind(error),
                              error_class=type(error).__name__, error=str(error) or type(error).__name__)
        raise
    finally:
        if diagnostic is not None:
            diagnostic.update(expected_bytes=size, received_bytes=count, elapsed_seconds=time.monotonic() - started)


def transmit(connection, payload, deadline):
    confirmed = 0
    while confirmed < UPLOAD_PER_CONNECTION and time.monotonic() < deadline:
        try:
            response, peer_socket = connection.response(deadline, upload=payload)
            with response:
                peer_socket.settimeout(remaining(deadline))
                if response.length is not None and response.length > 4096:
                    raise http.client.HTTPException("Unexpected HTTPS upload response length")
                if len(response.read(4097)) > 4096 or response.length not in (None, 0):
                    raise http.client.HTTPException("Unexpected HTTPS upload response")
            confirmed += len(payload)
        except HTTP_FAILURES:
            connection.close()
            break
    return confirmed


def prepare_lane(new_connection, deadline, diagnostic=None):
    connection = new_connection()
    try:
        if receive(connection, WARMUP_BYTES, deadline, diagnostic) == WARMUP_BYTES:
            return connection
    except HTTP_FAILURES:
        pass
    connection.close()
    return None


def transfer_lane(connection, payload, deadline, diagnostic=None):
    try:
        count = (transmit(connection, payload, deadline) if payload is not None
                 else receive(connection, DOWNLOAD_PER_CONNECTION, deadline, diagnostic))
    except HTTP_FAILURES:
        count = 0
    return count, time.monotonic()


def transfer_phase(new_connection, latency_connection, *, upload=False, download_lanes=None):
    payload = os.urandom(UPLOAD_BLOCK) if upload else None
    with ThreadPoolExecutor(max_workers=PARALLEL_CONNECTIONS) as pool:
        warm_deadline = time.monotonic() + CONNECT_SECONDS
        lanes = []
        for index in range(PARALLEL_CONNECTIONS):
            report = None
            if download_lanes is not None:
                report = dict(lane=index + 1, warmup={}, transfer=None)
                download_lanes.append(report)
            future = pool.submit(prepare_lane, new_connection, warm_deadline, report["warmup"] if report else None)
            lanes.append((future, report))
        connections = [(conn, report) for future, report in lanes if (conn := future.result()) is not None]
        if not connections:
            return 0, None, None
        started = time.monotonic()
        deadline = started + TRANSFER_SECONDS
        try:
            transfers = []
            for conn, report in connections:
                diagnostic = None
                if report is not None:
                    diagnostic = report["transfer"] = {}
                transfers.append(pool.submit(transfer_lane, conn, payload, deadline, diagnostic))
            # Time each worker independently so a final latency request cannot
            # lengthen the throughput denominator after the data has finished.
            loaded = []
            while not all(transfer.done() for transfer in transfers) and time.monotonic() < deadline:
                response = latency_request(latency_connection, min(deadline, time.monotonic() + 1))
                if response is not None and not all(transfer.done() for transfer in transfers):
                    loaded.append(response)
                if not all(transfer.done() for transfer in transfers):
                    time.sleep(0.075)
            results = [transfer.result() for transfer in transfers]
        finally:
            for connection, _ in connections:
                connection.close()
    count = sum(size for size, _ in results)
    duration = max(finished for _, finished in results) - started
    if not upload and count != len(connections) * DOWNLOAD_PER_CONNECTION:
        count = None  # A failed lane invalidates the entire download rate.
    return count, duration, mean(loaded) if loaded else None


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def measure(server, peer_ipv4, tunnel, download_checkpoint=None, idle_checkpoint=None):
    entry = dict(measurement="https", valid=False, server=server, target=TARGET,
                 peer_ipv4=peer_ipv4, tunnel=tunnel, started=timestamp(),
                 speed=dict(sent=0, received=0, average_ms=None,
                            download_mbps=None, upload_mbps=None, download_loaded_ms=None,
                            upload_loaded_ms=None, download_bytes=None, upload_bytes=None))
    stats = entry["speed"]
    try:
        if route_interface(peer_ipv4) != tunnel:
            raise RuntimeError("The HTTPS measurement destination is outside the expected VPN tunnel")
        index = socket.if_nametoindex(tunnel)
        context = ssl.create_default_context()
        def new_connection():
            return BoundHTTPSConnection(peer_ipv4, tunnel, index, context)
        connection = new_connection()
        samples = []
        def sent_request():
            stats["sent"] += 1
        def checkpoint(callback):
            if callback is None:
                return
            if route_interface(peer_ipv4) != tunnel or socket.if_nametoindex(tunnel) != index:
                raise RuntimeError("The HTTPS measurement route changed before the checkpoint")
            partial = dict(entry, valid=True, ended=timestamp(), speed=stats.copy())
            if "errors" in partial:
                partial["errors"] = partial["errors"].copy()
            callback(partial)
        try:
            deadline = time.monotonic() + IDLE_SECONDS
            for _ in range(LATENCY_SAMPLES):
                if time.monotonic() >= deadline:
                    break
                duration = latency_request(connection, min(deadline, time.monotonic() + 1), sent_request)
                if duration is not None:
                    samples.append(duration)
            stats["received"] = len(samples)
            stats["average_ms"] = mean(samples) if samples else None
            if not samples:
                entry.setdefault("errors", {})["idle"] = ("No idle HTTPS request was sent" if not stats["sent"]
                                                         else "No idle HTTPS request received a valid response")
            if stats["sent"]:
                checkpoint(idle_checkpoint)
            for mode in ("download", "upload"):
                try:
                    download_lanes = None
                    if mode == "download":
                        download_lanes = entry["download_lanes"] = []
                    size, elapsed, loaded = transfer_phase(new_connection, connection, upload=mode == "upload",
                                                           download_lanes=download_lanes)
                    stats[mode + "_bytes"] = size
                    stats[mode + "_loaded_ms"] = loaded
                    if size and elapsed and elapsed > 0:
                        stats[mode + "_mbps"] = 8 * size / (1_000_000 * elapsed)
                        stats[mode + "_seconds"] = elapsed
                    else:
                        reason = ("Incomplete parallel download" if size is None else
                                  "No warmed TLS connection" if elapsed is None else
                                  "No response payload bytes received" if mode == "download" else
                                  "No upload block acknowledged by the server")
                        entry.setdefault("errors", {})[mode] = f"HTTPS {mode}: {reason}"
                except HTTP_FAILURES as error:
                    entry.setdefault("errors", {})[mode] = f"HTTPS {mode}: {error or 'transfer failed'}"
                if mode == "download" and (entry["download_lanes"] or stats["sent"] or stats["download_mbps"] is not None):
                    checkpoint(download_checkpoint)
        finally:
            connection.close()
        if route_interface(peer_ipv4) != tunnel or socket.if_nametoindex(tunnel) != index:
            raise RuntimeError("The HTTPS measurement route changed during the test")
        if not samples and stats["download_mbps"] is None and stats["upload_mbps"] is None:
            raise RuntimeError("The HTTPS endpoint provided no measurement")
        entry["valid"] = True
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        entry["error"] = str(error)
    entry["ended"] = timestamp()
    return entry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolve-peer", action="store_true")
    parser.add_argument("--server")
    parser.add_argument("--peer-ip", type=public_ipv4)
    parser.add_argument("--tunnel")
    parser.add_argument("--log-dir", type=Path)
    args = parser.parse_args()
    if args.resolve_peer:
        try:
            print(resolve_peer())
        except (OSError, RuntimeError, ValueError) as error:
            parser.exit(1, f"HTTPS peer resolution failed: {error}\n")
        return 0
    if not args.server or not re.fullmatch(r"[a-z0-9-]+\.coreavpn\.(net|com|kr)", args.server):
        parser.error("Use a CoreaVPN server hostname")
    if not args.peer_ip or not args.tunnel or not re.fullmatch(r"ipsec[0-9]+", args.tunnel) or not args.log_dir:
        parser.error("A public peer address, an IKEv2 tunnel, and a log directory are required")
    record = measure(args.server, args.peer_ip, args.tunnel)
    line = json.dumps(record, ensure_ascii=False, allow_nan=False)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    with (args.log_dir / "https-results.jsonl").open("a", encoding="utf-8") as log:
        log.write(line + "\n")
    print(line)
    return 0 if record["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
