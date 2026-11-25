import concurrent.futures
from contextlib import ExitStack
import datetime
import http.client
import ipaddress
import select
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

DOH_DOMAIN_LABELS = tuple(
    (name, b'coreavpn', b'net')
    for name in (
        b'lynx', b'puma', b'saturn', b'ibex', b'lion', b'titan', b'hornet',
        b'venus', b'wolf', b'oryx', b'gannet', b'leo', b'falcon', b'hawk',
        b'cougar', b'moon', b'eagle',
    )
)
DOH_DOMAINS = frozenset(DOH_DOMAIN_LABELS)

if sys.argv[1:] == ['--list-domains']:
    for domain in DOH_DOMAIN_LABELS:
        print(b'.'.join(domain).decode('ascii'))
    sys.exit(0)

state = Path(sys.argv[1])
logfile = Path(sys.argv[2])
lock = threading.Lock()
if sys.argv[3:4] == ["--interface"]:
    device = sys.argv[4]
    del sys.argv[3:5]
else:
    import runpy
    device, _ = runpy.run_path(str(Path(__file__).with_name("uplink.py")))["active_link"]()
upstream_dns = "223.5.5.5"
if sys.argv[3:4] == ["--upstream"]:
    upstream_dns = str(ipaddress.IPv4Address(sys.argv[4]))
    del sys.argv[3:5]
wifi = socket.if_nametoindex(device)

def note(message):
    with lock, logfile.open('a') as log:
        print(datetime.datetime.now().strftime('%H:%M:%S'), message, file=log, flush=True)

def question(data):
    if len(data) < 17 or data[2] & 128 or data[4:6] != b'\x00\x01':
        raise ValueError('invalid question')
    labels = []
    i = 12
    while data[i]:
        n = data[i]
        if n > 63 or i + n + 1 >= len(data):
            raise ValueError('invalid label')
        labels.append(data[i+1:i+1+n].lower())
        i += n+1
    return labels, int.from_bytes(data[i+1:i+3], 'big')

def upstream_socket(t, ip, port, timeout=5):
    s = socket.socket(socket.AF_INET, t)
    try:
        s.settimeout(timeout)
        s.setsockopt(socket.IPPROTO_IP, 25, wifi)
        s.connect((ip, port))
        return s
    except BaseException:
        s.close()
        raise

class WifiHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = upstream_socket(socket.SOCK_STREAM, self.upstream_ip, 443, timeout=3)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

def readn(s, n):
    out = bytearray()
    while len(out) < n:
        part = s.recv(n-len(out))
        if not part:
            raise EOFError()
        out.extend(part)
    return bytes(out)

def doh_reply(data):
    for attempt, ip in enumerate(("101.198.193.29", "101.198.192.33")):
        conn = WifiHTTPS('doh.360.cn', timeout=5, context=ssl.create_default_context())
        conn.upstream_ip = ip
        try:
            conn.request('POST','/dns-query',data,{'Content-Type':'application/dns-message','Accept':'application/dns-message'})
            res = conn.getresponse()
            if res.status != 200:
                raise OSError('DoH HTTP '+str(res.status))
            return res.read(65536)
        except (ssl.SSLEOFError, http.client.RemoteDisconnected, ConnectionResetError, socket.timeout) as error:
            note(f"DoH attempt {attempt+1} on {device}: {type(error).__name__}")
            if attempt == 1:
                raise
        finally:
            conn.close()


def answer(data, tcp, client_address):
    labels, kind = question(data)
    if tuple(labels) in DOH_DOMAINS:
        reply = doh_reply(data)
        if len(reply)<12 or len(reply)>65535 or not reply[2]&128 or question_response_name(reply) != (labels,kind):
            raise ValueError('unexpected DoH response')
        domain = b'.'.join(labels).decode('ascii')
        note(f'{domain} type={kind} via 360 HTTPS, answers={int.from_bytes(reply[6:8], "big")}, '
             f'rcode={reply[3] & 15}, client={client_address}')
        return data[:2]+reply[2:]
    with upstream_socket(socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM,upstream_dns,53) as upstream:
        if tcp:
            upstream.sendall(struct.pack('!H',len(data))+data)
            reply=readn(upstream,int.from_bytes(readn(upstream,2),'big'))
        else:
            upstream.send(data)
            reply=upstream.recv(65535)
        if len(reply)<12 or reply[:2]!=data[:2] or not reply[2]&128 or question_response_name(reply)!=(labels,kind):
            raise ValueError('unexpected DNS response')
        return reply

def question_response_name(reply):
    return question(reply[:2]+bytes([reply[2]&127])+reply[3:])

def respond(data, tcp, client_address):
    try:
        return answer(data,tcp,client_address)
    except Exception as exc:
        note('DNS error: '+type(exc).__name__)
        return data[:2]+b'\x81\x82'+bytes(8) if len(data)>=2 else b''

def udp_job(s, data, addr):
    s.sendto(respond(data,False,addr[0]),addr)

def tcp_job(s, client_address):
    with s:
        s.settimeout(6)
        try:
            while True:
                data=readn(s,int.from_bytes(readn(s,2),'big'))
                reply=respond(data,True,client_address)
                s.sendall(struct.pack('!H',len(reply))+reply)
        except (EOFError,OSError):
            pass

def inherited_pair(resources, descriptors):
    return tuple(resources.enter_context(socket.socket(fileno=int(fd))) for fd in descriptors)


with ExitStack() as resources:
    args = sys.argv[3:]
    if args == ['preflight']:
        udp = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        tcp = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        udp.bind(('127.0.0.1', 10530))
        tcp.bind(('127.0.0.1', 10530))
        tcp.listen(32)
    else:
        udp, tcp = inherited_pair(resources, args[:2])
    loopback = ipaddress.IPv4Network('127.0.0.1')
    allowed_peers = {udp: loopback, tcp: loopback}
    if len(args) == 5:
        lan_udp, lan_tcp = inherited_pair(resources, args[2:4])
        allowed_lan = ipaddress.IPv4Network(args[4])
        allowed_peers.update({lan_udp: allowed_lan, lan_tcp: allowed_lan})
        note(f'LAN DNS at {lan_udp.getsockname()}, allowed IPv4={allowed_lan}')

    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
        note('Relay ready at ' + str(udp.getsockname()))
        (state / 'listening').touch()
        while not (state / 'closed').exists():
            for listener in select.select(list(allowed_peers), [], [], 1)[0]:
                allowed = allowed_peers[listener]
                if listener.type == socket.SOCK_STREAM:
                    try:
                        client, address = listener.accept()
                    except (ConnectionAbortedError, InterruptedError):
                        continue
                    if ipaddress.IPv4Address(address[0]) in allowed:
                        pool.submit(tcp_job, client, address[0])
                    else:
                        client.close()
                else:
                    try:
                        data, address = listener.recvfrom(65535)
                    except (ConnectionResetError, InterruptedError):
                        continue
                    if ipaddress.IPv4Address(address[0]) in allowed:
                        pool.submit(udp_job, listener, data, address)
