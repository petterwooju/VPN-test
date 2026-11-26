"""Find the active physical IPv4 uplink and its macOS network service."""
import re
import subprocess


def active_device():
    nwi = subprocess.check_output(["/usr/sbin/scutil", "--nwi"], text=True, timeout=5)
    nwi = nwi.split("IPv6 network interface")[0]
    match = re.search(r"^\s*(en[0-9]+) : flags.*IPv4", nwi, re.M)
    return match[1] if match else None


def active_link():
    device = active_device()
    if device is None:
        raise RuntimeError("No active physical IPv4 uplink")
    services = subprocess.check_output(["/usr/sbin/networksetup", "-listnetworkserviceorder"], text=True, timeout=5)
    matches = re.findall(r"^\(\d+\) (.+)\n\(Hardware Port: [^\n]+, Device: " + device + r"\)$", services, re.M)
    if len(matches) != 1:
        raise RuntimeError("Cannot identify unique network service for " + device)
    return device, matches[0]


def resolver_settings(service, device, baseline):
    """Return the upstream IPv4 address and the restore argument to networksetup."""
    import ipaddress
    if baseline == f"There aren't any DNS Servers set on {service}.":
        values = subprocess.check_output(
            ["/usr/sbin/ipconfig", "getoption", device, "domain_name_server"],
            text=True, timeout=5).split()
        if not values:
            raise RuntimeError("DHCP did not provide an IPv4 DNS server")
        upstream = ipaddress.IPv4Address(values[0])
        if upstream.is_loopback or upstream.is_unspecified or upstream.is_multicast:
            raise RuntimeError("Invalid DHCP upstream DNS")
        return str(upstream), "Empty"
    if baseline == "223.5.5.5":
        return baseline, baseline
    raise RuntimeError("Unsupported manual DNS configuration on " + service)
