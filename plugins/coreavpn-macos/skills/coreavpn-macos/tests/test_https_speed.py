"""HTTPS speed regressions exercise route validation and counting without live VPN traffic."""
import http.client
import json
from pathlib import Path
import socket
from queue import SimpleQueue
import ssl
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import https_speed as speed


PEER = "104.16.184.86"
HOST = "leo.coreavpn.net"
TUNNEL = "ipsec4"


def latency_responses(values):
    replies = iter(values)
    def request(channel, deadline, on_sent=None):
        if on_sent is not None:
            on_sent()
        return next(replies)
    return request


class HTTPSSpeedTests(unittest.TestCase):
    def test_selects_only_a_public_ipv4_peer(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, 443))
                   for address in ("127.0.0.1", "192.168.0.2", "224.0.0.1", PEER)]
        with patch.object(speed.socket, "getaddrinfo", return_value=answers) as lookup:
            self.assertEqual(speed.resolve_peer(), PEER)
        lookup.assert_called_once_with(speed.TARGET, 443, socket.AF_INET, socket.SOCK_STREAM)

    def test_socket_is_bound_before_connect_and_keeps_tls_verification(self):
        context = ssl.create_default_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        raw = Mock()
        secure = Mock()
        channel = speed.BoundHTTPSConnection(PEER, TUNNEL, 7, context)
        with patch.object(speed.sys, "platform", "darwin"), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed.socket, "socket", return_value=raw), \
             patch.object(context, "wrap_socket", return_value=secure) as wrap:
            channel.begin(speed.time.monotonic() + 1)
            self.assertIs(channel.sock, secure)
        self.assertLess(raw.method_calls.index(call.setsockopt(socket.IPPROTO_IP, speed.IP_BOUND_IF, 7)),
                        raw.method_calls.index(call.connect((PEER, 443))))
        wrap.assert_called_once_with(raw, server_hostname=speed.TARGET)

    def test_moved_interface_is_rejected_before_opening_a_socket(self):
        channel = speed.BoundHTTPSConnection(PEER, TUNNEL, 7, ssl.create_default_context())
        with patch.object(speed.sys, "platform", "darwin"), \
             patch.object(speed.socket, "if_nametoindex", return_value=8), \
             patch.object(speed.socket, "socket") as create:
            with self.assertRaises(OSError):
                channel.begin(speed.time.monotonic() + 1)
            create.assert_not_called()

    def test_non_tunnel_route_never_contacts_measurement_server(self):
        with patch.object(speed, "route_interface", return_value="en6") as route, \
             patch.object(speed, "BoundHTTPSConnection") as channel:
            record = speed.measure(HOST, PEER, TUNNEL)
            channel.assert_not_called()
        self.assertFalse(record["valid"])
        self.assertEqual(record["speed"]["sent"], 0)
        route.assert_called_once_with(PEER)

    def test_result_preserves_https_failures_and_directional_data(self):
        checks = [(10000, 2, 32), (5000, 1, 38)]
        with patch.object(speed, "route_interface", return_value=TUNNEL) as route, \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "latency_request", side_effect=latency_responses([None, 75] * 2 + [75] * 16)), \
             patch.object(speed, "transfer_phase", side_effect=checks):
            record = speed.measure(HOST, PEER, TUNNEL)
        self.assertTrue(record["valid"])
        self.assertEqual(route.call_args_list, [call(PEER), call(PEER)])
        self.assertEqual(record["speed"], dict(
            sent=20, received=18, average_ms=75, download_bytes=10000, upload_bytes=5000,
            download_mbps=0.04, upload_mbps=0.04, download_seconds=2, upload_seconds=1,
            download_loaded_ms=32, upload_loaded_ms=38,
        ))

    def test_failed_idle_and_upload_keep_verified_download_checkpoint(self):
        checkpoint = Mock()
        with patch.object(speed, "route_interface", return_value=TUNNEL), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "latency_request", return_value=None), \
             patch.object(speed, "transfer_phase", side_effect=[(1500000, 1, None), TimeoutError("Upload timed out")]):
            record = speed.measure(HOST, PEER, TUNNEL, download_checkpoint=checkpoint)
        self.assertTrue(record["valid"])
        self.assertEqual(record["speed"]["download_mbps"], 12)
        self.assertEqual(record["speed"]["received"], 0)
        self.assertIsNone(record["speed"]["upload_mbps"])
        self.assertIn("Upload timed out", record["errors"]["upload"])
        self.assertEqual(checkpoint.call_args.args[0]["speed"]["download_mbps"], 12)

    def test_route_change_invalidates_otherwise_successful_transfer(self):
        with patch.object(speed, "route_interface", side_effect=[TUNNEL, "en6"]), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "latency_request", side_effect=latency_responses([50] * 20)), \
             patch.object(speed, "transfer_phase", return_value=(10000, 2, 40)):
            record = speed.measure(HOST, PEER, TUNNEL)
        self.assertFalse(record["valid"])
        self.assertIn("route changed", record["error"])
        self.assertEqual(record["speed"]["received"], 20)

    def test_idle_checkpoint_precedes_transfer_and_counts_only_sent_requests(self):
        idle = Mock()
        with patch.object(speed, "route_interface", return_value=TUNNEL), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "latency_request", side_effect=latency_responses([None] + [60] * 19)), \
             patch.object(speed, "transfer_phase", side_effect=[(0, None, None), (200_000, 1, None)]):
            record = speed.measure(HOST, PEER, TUNNEL, idle_checkpoint=idle)
        partial = idle.call_args.args[0]["speed"]
        self.assertEqual((partial["sent"], partial["received"]), (20, 19))
        self.assertIsNone(partial["download_bytes"])
        self.assertEqual(record["speed"]["upload_mbps"], 1.6)
        self.assertIn("download:", record["errors"]["download"])
        channel = Mock()
        channel.begin.side_effect = TimeoutError("TLS handshake failed")
        notified = Mock()
        self.assertIsNone(speed.latency_request(channel, speed.time.monotonic() + 1, notified))
        notified.assert_not_called()

    def test_timeout_after_receiving_bytes_fails_the_download(self):
        response = MagicMock(length=100)
        response.read1.side_effect = [b"x" * 37, TimeoutError()]
        peer_socket = Mock()
        channel = Mock()
        channel.response.return_value = response, peer_socket
        with self.assertRaises(TimeoutError):
            speed.receive(channel, 100, speed.time.monotonic() + 1)

    def test_diagnostic_distinguishes_partial_socket_timeout_short_body_and_bad_headers(self):
        for steps, length, expected, kind, stage in [
            ([b"x" * 37, socket.timeout("timed out")], 100, 37, "timeout", "body"),
            ([b"x" * 14, b""], 100, 14, "early_eof", "body"),
            ([], 50, 0, "length", "response_headers"),
        ]:
            with self.subTest(kind=kind):
                response = MagicMock(length=length)
                response.read1.side_effect = steps
                channel = Mock()
                channel.response.return_value = response, Mock()
                diagnostic = {}
                with self.assertRaises(speed.HTTP_FAILURES):
                    speed.receive(channel, 100, speed.time.monotonic() + 1, diagnostic)
                self.assertEqual(diagnostic["stage"], stage)
                self.assertEqual(diagnostic["error_type"], kind)
                self.assertEqual(diagnostic["status"], "failed")
                self.assertEqual(diagnostic["received_bytes"], expected)
                self.assertEqual(diagnostic["expected_bytes"], 100)
                self.assertGreaterEqual(diagnostic["elapsed_seconds"], 0)

    def test_download_lanes_are_in_final_record_and_checkpoint_without_partial_credit(self):
        # All four pools use the same fixed body/deadline policy. One warm-up never
        # finishes, one transfer times out after a prefix, and two transfers finish.
        roles = SimpleQueue()
        for role in ["warmup_timeout", "transfer_timeout", "complete", "complete"]:
            roles.put(role)

        class Channel:
            def response(self, deadline, *, download):
                if self.role == "warmup_timeout":
                    self.stage = "response_headers"
                    raise socket.timeout("timed out awaiting headers")
                response = MagicMock(length=download)
                response.read.return_value = b""
                response.read1.side_effect = ([b"x" * 15, socket.timeout("read timed out")]
                    if self.role == "transfer_timeout" and download == 128 else [b"x" * download])
                return response, Mock()

            def close(self):
                pass

        def connect():
            channel = Channel()
            channel.role = roles.get_nowait()
            return channel

        original_phase = speed.transfer_phase
        def phase(factory, channel, *, upload, download_lanes):
            if upload:
                return 4096, 0.1, None
            return original_phase(connect, channel, download_lanes=download_lanes)

        checkpoint = Mock()
        with patch.object(speed, "route_interface", return_value=TUNNEL), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "WARMUP_BYTES", 8), patch.object(speed, "DOWNLOAD_PER_CONNECTION", 128), \
             patch.object(speed, "latency_request", return_value=None), \
             patch.object(speed, "transfer_phase", side_effect=phase):
            result = speed.measure(HOST, PEER, TUNNEL, download_checkpoint=checkpoint)
        reports = result["download_lanes"]
        self.assertEqual(checkpoint.call_args.args[0]["download_lanes"], reports)
        self.assertEqual([r["lane"] for r in reports], [1, 2, 3, 4])
        skipped, = [r["warmup"] for r in reports if r["transfer"] is None]
        self.assertEqual((skipped["stage"], skipped["error_type"]), ("response_headers", "timeout"))
        transfers = [r["transfer"] for r in reports if r["transfer"] is not None]
        self.assertEqual(sorted(t["received_bytes"] for t in transfers), [15, 128, 128])
        failed, = [t for t in transfers if t["status"] == "failed"]
        self.assertEqual((failed["stage"], failed["error_type"]), ("body", "timeout"))
        self.assertIsNone(result["speed"]["download_mbps"])
        self.assertIsNone(result["speed"]["download_bytes"])
        self.assertEqual(result["errors"]["download"], "HTTPS download: Incomplete parallel download")
        self.assertTrue(result["valid"])

    def test_one_incomplete_download_lane_invalidates_rate_but_keeps_other_measurements(self):
        complete = speed.DOWNLOAD_PER_CONNECTION
        now = speed.time.monotonic()
        with patch.object(speed, "prepare_lane", return_value=Mock()), \
             patch.object(speed, "latency_request", return_value=50), \
             patch.object(speed, "transfer_lane", side_effect=[(n, now + 1) for n in (complete, 0, complete, complete)]):
            failed_download = speed.transfer_phase(Mock(), Mock())
        self.assertIsNone(failed_download[0])
        with patch.object(speed, "route_interface", return_value=TUNNEL), \
             patch.object(speed.socket, "if_nametoindex", return_value=7), \
             patch.object(speed, "BoundHTTPSConnection"), \
             patch.object(speed, "latency_request", side_effect=latency_responses([50] * 20)), \
             patch.object(speed, "transfer_phase", side_effect=[failed_download, (200000, 1, 70)]):
            record = speed.measure(HOST, PEER, TUNNEL)
        self.assertTrue(record["valid"])
        self.assertIn("Incomplete parallel download", record["errors"]["download"])
        self.assertEqual(record["speed"]["received"], 20)
        self.assertEqual(record["speed"]["upload_mbps"], 1.6)
        for field in ("download_mbps", "download_seconds", "download_bytes"):
            self.assertIsNone(record["speed"].get(field))

    def test_upload_counts_only_accepted_blocks(self):
        response = MagicMock(length=0)
        response.read.return_value = b""
        channel = Mock()
        channel.response.side_effect = [(response, Mock()), http.client.HTTPException()]
        payload = b"x" * speed.UPLOAD_BLOCK
        self.assertEqual(speed.transmit(channel, payload, speed.time.monotonic() + 1), len(payload))

    def test_transfer_is_bounded_and_does_not_count_the_warmup(self):
        timely_result = (speed.DOWNLOAD_PER_CONNECTION, speed.time.monotonic() + 1)
        with patch.object(speed, "prepare_lane", return_value=Mock()) as ready, \
             patch.object(speed, "transfer_lane", return_value=timely_result) as lane, \
             patch.object(speed, "latency_request", side_effect=latency_responses([50] * 20)):
            size, _, _ = speed.transfer_phase(Mock(), Mock())
        self.assertEqual(size, 4 * speed.DOWNLOAD_PER_CONNECTION)
        self.assertEqual(ready.call_count, 4)
        self.assertEqual(lane.call_count, 4)

    def test_main_appends_machine_readable_results_even_when_invalid(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(speed, "route_interface", return_value="en6"), \
             patch.object(speed.sys, "argv", ["https_speed.py", "--server", HOST, "--peer-ip", PEER,
                                              "--tunnel", TUNNEL, "--log-dir", temp]), \
             patch("builtins.print") as output:
            self.assertEqual(speed.main(), 1)
            record = json.loads((Path(temp) / "https-results.jsonl").read_text())
        self.assertFalse(record["valid"])
        self.assertEqual(record["measurement"], "https")
        self.assertEqual(record, json.loads(output.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
