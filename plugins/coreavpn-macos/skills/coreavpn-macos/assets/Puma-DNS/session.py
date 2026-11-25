"""Temporary Wi-Fi DNS relay for this Mac and an optional iPhone."""

import argparse
import fcntl
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NETWORKSETUP = "/usr/sbin/networksetup"
PYTHON = "/usr/bin/python3"
WIFI = "Wi-Fi"
WIFI_INTERFACE = "en0"
ORIGINAL_DNS = "223.5.5.5"
RELAY_ADDRESS = "127.0.0.1"
PUMA_HOST = "puma.coreavpn.net"
PRIVATE_NETWORKS = tuple(map(ipaddress.IPv4Network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))

# Pass a fixed controller to sudo. The DNS worker runs with the user's UID.
CONTROLLER = r"""
import os
import signal
import socket
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

state, worker = map(Path, sys.argv[1:3])
uid, gid = map(int, sys.argv[3:5])
service, original, local = sys.argv[5:8]
device, upstream, restore = sys.argv[8:11]
lan = sys.argv[11:]
networksetup = "/usr/sbin/networksetup"

def get_dns():
    return subprocess.check_output(
        [networksetup, "-getdnsservers", service], text=True, timeout=8
    ).strip()

def set_dns(address):
    subprocess.run(
        [networksetup, "-setdnsservers", service, address], check=True, timeout=10
    )

def stop_requested():
    try:
        return (state / "stop").exists() or time.time() - (state / "heartbeat").stat().st_mtime > 25
    except FileNotFoundError:
        return True

def stop(signum, frame):
    raise KeyboardInterrupt

def enter_user_context():
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)

def bind_pair(resources, address, interface=None):
    udp = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    tcp = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    for listener in (udp, tcp):
        if interface:
            # macOS IP_BOUND_IF limits the listener to the physical Wi-Fi interface.
            listener.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
        listener.bind((address, 53))
    tcp.listen(32)
    return udp, tcp

if uid <= 0 or gid <= 0 or int(os.environ.get("SUDO_UID", "-1")) != uid:
    sys.exit("Unexpected sudo user")
if get_dns() != original:
    sys.exit("Wi-Fi DNS did not match the saved baseline")
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, stop)
signal.signal(signal.SIGINT, stop)
with ExitStack() as resources:
    local_sockets = bind_pair(resources, local)
    sockets = local_sockets
    worker_args = [str(listener.fileno()) for listener in local_sockets]
    if lan:
        interface, address, allowed_clients = lan
        lan_sockets = bind_pair(resources, address, interface)
        sockets += lan_sockets
        worker_args.extend((str(lan_sockets[0].fileno()), str(lan_sockets[1].fileno()), allowed_clients))
    worker_process = subprocess.Popen(
        ["/usr/bin/python3", "-I", str(worker), str(state), str(state / "relay.log"),
         "--interface", device, "--upstream", upstream, *worker_args],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        pass_fds=tuple(listener.fileno() for listener in sockets), preexec_fn=enter_user_context,
        start_new_session=True,
    )
    changed = False
    try:
        while worker_process.poll() is None and not stop_requested():
            if (state / "validated").exists():
                if get_dns() != original:
                    raise RuntimeError("Wi-Fi DNS changed during preparation")
                changed = True
                set_dns(local)
                if get_dns() != local:
                    raise RuntimeError("Applying the local DNS failed")
                print("Wi-Fi DNS " + local, flush=True)
                while worker_process.poll() is None and not stop_requested():
                    time.sleep(0.5)
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, signal.SIG_IGN)
        # Keep a functioning relay available until restoration has been verified.
        if changed:
            restored = False
            for _ in range(4):
                try:
                    if get_dns() == local:
                        set_dns(restore)
                    if get_dns() == original:
                        restored = True
                        print("Final Wi-Fi DNS " + get_dns().replace("\n", " "), flush=True)
                        break
                except (OSError, subprocess.SubprocessError):
                    time.sleep(1)
            if not restored:
                print("Wi-Fi DNS restoration could not be verified", file=sys.stderr, flush=True)
                sys.exit(2)
        worker_process.terminate()
        try:
            worker_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker_process.kill()
            worker_process.wait()
"""


def current_dns():
    return subprocess.check_output(
        [NETWORKSETUP, "-getdnsservers", WIFI], text=True, timeout=8
    ).strip()


def wifi_lan_configuration(raw_address=None):
    interface = subprocess.check_output(
        ["/sbin/ifconfig", WIFI_INTERFACE], text=True, timeout=5
    )
    match = re.search(r"^\s*inet (\S+) netmask (0x[0-9a-f]+)", interface, re.M | re.I)
    if not match:
        raise RuntimeError("Mac의 Wi-Fi IPv4 주소를 확인하지 못했습니다.")
    mac = ipaddress.IPv4Address(match[1])
    netmask = ipaddress.IPv4Address(int(match[2], 16))
    network = ipaddress.IPv4Network(f"{mac}/{netmask}", strict=False)
    if not any(network.subnet_of(private) for private in PRIVATE_NETWORKS):
        raise RuntimeError("Wi-Fi의 사설 IPv4 서브넷을 확인하지 못했습니다.")
    if raw_address is None:
        return WIFI_INTERFACE, str(mac), str(network)
    try:
        iphone = ipaddress.IPv4Address(raw_address)
    except ipaddress.AddressValueError:
        raise RuntimeError("--iphone에는 아이폰의 Wi-Fi IPv4 주소를 입력하세요.") from None
    if iphone not in network or iphone in (mac, network.network_address, network.broadcast_address):
        raise RuntimeError("Mac과 같은 Wi-Fi 서브넷에 있는 아이폰의 IPv4 주소를 입력하세요.")
    route = subprocess.run(
        ["/sbin/route", "-n", "get", "-ifscope", WIFI_INTERFACE, "default"],
        text=True, capture_output=True, timeout=5,
    )
    gateway = re.search(r"^\s*gateway:\s+(\S+)", route.stdout, re.M)
    if gateway and gateway[1] == str(iphone):
        raise RuntimeError(
            f"{iphone}은 Wi-Fi 공유기 주소입니다. 아이폰의 IPv4 ‘IP 주소’ 줄을 확인하세요."
        )
    return WIFI_INTERFACE, str(mac), str(iphone)


def check_answer(name, record_type, tcp=False):
    args = [
        "/usr/bin/dig", "@" + RELAY_ADDRESS, name, record_type,
        "+time=7", "+tries=1", "+noall", "+comments", "+answer",
    ]
    if tcp:
        args.append("+tcp")
    output = subprocess.check_output(args, text=True, timeout=9)
    if "status: NOERROR" not in output:
        raise RuntimeError(f"{name} {record_type} 조회에 실패했습니다.")
    return [
        fields[-1] for line in output.splitlines()
        if line and not line.startswith(";") and len(fields := line.split()) >= 5
        and fields[3] == record_type
    ]


def validate_relay(heartbeat):
    puma_answers = {}
    for name, record_type, tcp in (
        (PUMA_HOST, "A", False), (PUMA_HOST, "AAAA", False),
        ("example.com", "A", False), ("example.com", "A", True),
    ):
        heartbeat.touch()
        addresses = check_answer(name, record_type, tcp)
        if record_type == "A" and not addresses:
            raise RuntimeError(f"{name}에서 IPv4 주소를 받지 못했습니다.")
        if name == PUMA_HOST:
            if not all(ipaddress.ip_address(address).is_global for address in addresses):
                raise RuntimeError("Puma DNS 응답에 공용 주소가 아닌 값이 포함됐습니다.")
            puma_answers[record_type] = addresses
    return puma_answers


def show_domain_addresses(relay_file, heartbeat, puma_answers):
    domains = subprocess.check_output(
        [PYTHON, "-I", str(relay_file), "--list-domains"], text=True, timeout=5
    ).splitlines()

    def ipv4_status(domain):
        try:
            addresses = puma_answers["A"] if domain == PUMA_HOST else check_answer(domain, "A")
        except (OSError, RuntimeError, subprocess.SubprocessError):
            return "조회 실패"
        return " ".join(addresses) if addresses else "IPv4 응답 없음"

    print(f"CoreaVPN .net DNS 조회 결과 ({len(domains)}개)", flush=True)
    with ThreadPoolExecutor(max_workers=5) as executor:
        for domain, status in zip(domains, executor.map(ipv4_status, domains)):
            heartbeat.touch()
            print(f"{domain:<23} A     {status}", flush=True)
            if domain == PUMA_HOST and puma_answers["AAAA"]:
                print(f"{domain:<23} AAAA  {' '.join(puma_answers['AAAA'])}", flush=True)


def stop_session(signum, frame):
    raise KeyboardInterrupt


def run_session(iphone=None, allow_lan=False, state_dir=None):
    if os.getuid() == 0:
        raise RuntimeError("일반 사용자로 실행하고, 실행 중 표시되는 sudo 요청만 승인하세요.")
    lan = wifi_lan_configuration(iphone) if allow_lan or iphone is not None else ()
    global ORIGINAL_DNS
    ORIGINAL_DNS = current_dns()
    import runpy
    upstream_dns, restore_dns = runpy.run_path(str(Path(__file__).with_name("uplink.py")))["resolver_settings"](
        WIFI, WIFI_INTERFACE, ORIGINAL_DNS)

    relay_file = Path(__file__).resolve().with_name("relay.py")
    if state_dir is None:
        state = Path(tempfile.mkdtemp(prefix="puma-dns-", dir="/private/tmp"))
    else:
        state = Path(state_dir).resolve()
        state.mkdir(mode=0o700, parents=False, exist_ok=False)
    heartbeat = state / "heartbeat"
    print("중계기 로그 " + str(state / "relay.log"), flush=True)
    subprocess.run(["/usr/bin/sudo", "-v"], check=True)

    signal.signal(signal.SIGHUP, stop_session)
    signal.signal(signal.SIGTERM, stop_session)
    heartbeat.touch()
    controller = subprocess.Popen(
        [
            "/usr/bin/sudo", "-n", PYTHON, "-I", "-S", "-c", CONTROLLER,
            str(state), str(relay_file), str(os.getuid()), str(os.getgid()),
            WIFI, ORIGINAL_DNS, RELAY_ADDRESS, WIFI_INTERFACE, upstream_dns, restore_dns, *lan,
        ],
        stdin=subprocess.DEVNULL,
    )
    interrupted = False
    try:
        deadline = time.monotonic() + 15
        while not (state / "listening").exists():
            if controller.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("루프백 포트 53에서 중계기를 시작하지 못했습니다.")
            heartbeat.touch()
            time.sleep(0.2)
        puma_answers = validate_relay(heartbeat)
        heartbeat.touch()
        if state_dir is None:
            show_domain_addresses(relay_file, heartbeat, puma_answers)
        heartbeat.touch()
        (state / "validated").touch()
        deadline = time.monotonic() + 15
        while current_dns() != RELAY_ADDRESS:
            if controller.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Wi-Fi에 임시 DNS를 적용하지 못했습니다.")
            heartbeat.touch()
            time.sleep(0.2)
        print(
            "중계기가 켜졌습니다. FlClash를 끄고 사용할 CoreaVPN 서버에 연결하세요.\n"
            "사용이 끝나면 VPN을 끊고 이 창에서 Control+C를 누르세요.",
            flush=True,
        )
        if lan:
            print(f"{'Wi-Fi' if allow_lan else '아이폰'} DNS 서버 {lan[1]} · 허용 IPv4 {lan[2]}", flush=True)
        while controller.poll() is None:
            heartbeat.touch()
            if lan and wifi_lan_configuration(iphone) != lan:
                raise RuntimeError("Mac의 Wi-Fi 주소가 바뀌었습니다. 중계기를 다시 실행하세요.")
            time.sleep(2)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        (state / "stop").touch()
        try:
            controller.wait(timeout=60)
        except subprocess.TimeoutExpired:
            print("자동 복구를 기다리는 중입니다. 안내서의 복구 명령으로 확인할 수 있습니다.", file=sys.stderr)
    if current_dns() != ORIGINAL_DNS:
        raise RuntimeError(
            "Wi-Fi DNS 원복을 확인하지 못했습니다. "
            "Check the original DNS of the selected service."
        )
    if not interrupted:
        raise RuntimeError("중계기가 종료됐습니다. Wi-Fi DNS는 원래 값입니다.")
    print(f"Wi-Fi DNS {ORIGINAL_DNS} 복구 확인.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CoreaVPN DNS 중계기")
    parser.add_argument("--state-dir", type=Path,
                        help="New private session directory for an offline runner's recovery watchdog")
    clients = parser.add_mutually_exclusive_group()
    clients.add_argument("--lan", action="store_true", help="현재 Wi-Fi IPv4 서브넷의 기기에 DNS 제공")
    clients.add_argument(
        "--iphone", nargs="?", const="", metavar="IPv4",
        help="같은 Wi-Fi의 아이폰에서 DNS 사용을 허용 (값을 생략하면 직접 입력)",
    )
    parser.add_argument("--expected-interface")
    args = parser.parse_args()
    try:
        import runpy
        if args.iphone is None and not args.lan:
            WIFI_INTERFACE, WIFI = runpy.run_path(str(Path(__file__).with_name("uplink.py")))["active_link"]()
        if args.expected_interface and args.expected_interface != WIFI_INTERFACE:
            raise RuntimeError("Physical interface changed during preparation")
        with (Path(tempfile.gettempdir()) / "puma-dns-session.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                sys.exit("이미 Puma DNS 중계기를 실행 중입니다.")
            if args.iphone == "":
                try:
                    args.iphone = input("아이폰 IPv4 ‘IP 주소’ (공유기 주소와 다름): ").strip()
                except EOFError:
                    sys.exit("터미널에서 아이폰의 IPv4 주소를 입력하세요.")
            run_session(args.iphone, allow_lan=args.lan, state_dir=args.state_dir)
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
