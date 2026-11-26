"""Qualification rule shared by the candidate search and its watchdog."""
import math
import re

from https_speed import TARGET as HTTPS_TARGET, public_ipv4

ICMP_TARGET = "168.126.63.1"
MEASUREMENTS = ("https", "icmp")
DEFAULT_MEASUREMENT = "https"
OPERATIONS = ("quick", "all", "select")


def destination_for_sample(sample, measurement):
    # The ping helper's historical JSONL uses the target and ping statistics
    # without a separate measurement field.
    if measurement == "icmp" and sample.get("measurement", "icmp") == "icmp":
        return ICMP_TARGET if sample.get("target") == ICMP_TARGET else None
    if (measurement == "https" and sample.get("measurement") == "https"
            and sample.get("target") == HTTPS_TARGET):
        try:
            return public_ipv4(sample["peer_ipv4"]) if isinstance(sample.get("peer_ipv4"), str) else None
        except ValueError:
            return None
    return None


def qualifies(sample, hosts, expected_tunnel=None, *, measurement=DEFAULT_MEASUREMENT):
    if not isinstance(sample, dict) or sample.get("valid") is not True:
        return False
    tunnel = sample.get("tunnel")
    if (sample.get("server") not in hosts or destination_for_sample(sample, measurement) is None
            or not isinstance(tunnel, str) or not re.fullmatch(r"ipsec[0-9]+", tunnel)
            or (expected_tunnel is not None and tunnel != expected_tunnel)):
        return False
    statistics = sample.get("ping" if measurement == "icmp" else "speed")
    if not isinstance(statistics, dict):
        return False
    sent, received = statistics.get("sent"), statistics.get("received")
    if measurement == "https":
        download = statistics.get("download_mbps")
        count = statistics.get("download_bytes")
        seconds = statistics.get("download_seconds")
        return (type(download) in (float, int) and math.isfinite(download) and download >= 10
                and type(count) is int and count > 0 and type(seconds) in (float, int)
                and math.isfinite(seconds) and seconds > 0
                and math.isclose(download, 8 * count / (1_000_000 * seconds), rel_tol=1e-9))
    mean = statistics.get("average_ms")
    if (type(sent) is not int or sent != 20 or type(received) is not int or not 18 <= received <= sent
            or type(mean) not in (float, int) or not 0 <= mean <= 100):
        return False
    loss = statistics.get("loss_pct")
    minimum, maximum = statistics.get("minimum_ms"), statistics.get("maximum_ms")
    return (type(loss) in (float, int) and loss == 100 * (sent - received) / sent
            and type(minimum) in (float, int) and 0 <= minimum <= mean
            and type(maximum) in (float, int) and mean <= maximum < math.inf)


def retention_destination(sample, hosts, measurement, operation):
    """A manual click retains its requested, verified route without inventing benchmark results."""
    if operation == "quick" and qualifies(sample, hosts, measurement=measurement):
        return destination_for_sample(sample, measurement)
    if (operation == "select" and isinstance(sample, dict) and sample.get("valid") is True
            and sample.get("measurement") == "connection" and hosts == [sample.get("server")]
            and sample.get("target") == ICMP_TARGET and isinstance(sample.get("tunnel"), str)
            and re.fullmatch(r"ipsec[0-9]+", sample["tunnel"])
            and type(sample.get("interface_index")) is int and sample["interface_index"] > 0):
        return ICMP_TARGET
    return None
