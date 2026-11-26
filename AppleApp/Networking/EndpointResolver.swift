import Foundation
import Network
import Security
import Darwin

enum VPNNetworkError: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case .message(let description): return description }
    }
}

/// Only provider-published endpoints can be used for credentialed IKEv2 sessions.
enum VPNEndpoints {
    static let net = Set("lynx puma saturn ibex lion titan hornet venus wolf oryx gannet leo falcon hawk cougar moon eagle"
        .split(separator: " ").map { "\($0).coreavpn.net" })
    static let all = net.union(["lynx.coreavpn.com", "puma.coreavpn.com", "gannet.coreavpn.com",
                                "moon.coreavpn.com", "lynx.coreavpn.kr", "venus.coreavpn.kr"])
    static func isPublicIPv4(_ string: String) -> Bool {
        guard let data = IPv4Address(string)?.rawValue else { return false }
        let p = Array(data)
        guard p[0] > 0, p[0] < 224, ![10, 127].contains(p[0]) else { return false }
        switch (p[0], p[1]) {
        case (100, 64...127), (169, 254), (172, 16...31), (192, 168), (198, 18...19): return false
        default: break
        }
        switch (p[0], p[1], p[2]) {
        case (192, 0, 0), (192, 0, 2), (192, 88, 99), (198, 51, 100), (203, 0, 113): return false
        default: return true
        }
    }
}

private let invalidDNS = VPNNetworkError.message("DNS 응답 형식 또는 서버 주소를 확인할 수 없습니다.")

/// RFC 1035 A response with question, transaction ID and CNAME ownership validation.
enum EndpointDNS {
    static func query(_ host: String, id: UInt16) -> Data {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(truncatingIfNeeded: id), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in host.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count)); bytes += label.utf8
        }
        bytes += [0, 0, 1, 0, 1]
        return Data(bytes)
    }

    static func answer(_ wire: Data, for host: String, id: UInt16) throws -> (address: String, ttl: UInt32) {
        let b = Array(wire)
        func u16(_ i: Int) throws -> Int {
            guard i >= 0, i + 2 <= b.count else { throw invalidDNS }
            return Int(b[i]) << 8 | Int(b[i + 1])
        }
        func name(_ start: Int) throws -> (String, Int) {
            var labels: [String] = [], i = start, end: Int?
            var visited = Set<Int>()
            while i < b.count, visited.insert(i).inserted, visited.count <= 128 {
                let n = Int(b[i])
                if n == 0 { return (labels.joined(separator: ".").lowercased(), end ?? i + 1) }
                if n & 0xC0 == 0xC0 {
                    let pointer = try u16(i) & 0x3FFF
                    guard pointer < i else { throw invalidDNS }
                    if end == nil { end = i + 2 }
                    i = pointer
                } else {
                    guard n <= 63, i + n < b.count,
                          let label = String(bytes: b[(i+1)...(i+n)], encoding: .ascii) else { throw invalidDNS }
                    labels.append(label)
                    i += n + 1
                }
            }
            throw invalidDNS
        }
        guard b.count >= 12, try u16(0) == Int(id), b[2] & 0xFA == 0x80,
              b[3] & 0x0F == 0, try u16(4) == 1 else { throw invalidDNS }
        let (question, qend) = try name(12)
        guard question == host, try u16(qend) == 1, try u16(qend + 2) == 1 else { throw invalidDNS }
        var i = qend + 4
        var addresses = [String: (String, UInt32)](), aliases = [String: (String, UInt32)]()
        for _ in 0..<(try u16(6)) {
            let (owner, end) = try name(i)
            let kind = try u16(end), cls = try u16(end + 2), length = try u16(end + 8)
            let ttl = UInt32(try u16(end + 4)) << 16 | UInt32(try u16(end + 6))
            let start = end + 10
            i = start + length
            guard i <= b.count else { throw invalidDNS }
            if cls == 1, kind == 1, length == 4 {
                let ip = b[start..<i].map(String.init).joined(separator: ".")
                if VPNEndpoints.isPublicIPv4(ip), addresses[owner] == nil { addresses[owner] = (ip, ttl) }
            } else if cls == 1, kind == 5 {
                let (target, next) = try name(start)
                guard next == i else { throw invalidDNS }
                aliases[owner] = (target, ttl)
            }
        }
        var key = host, lifetime = UInt32.max, visited = Set<String>()
        while visited.insert(key).inserted {
            if let (address, ttl) = addresses[key] { return (address, min(ttl, lifetime)) }
            guard let (target, ttl) = aliases[key] else { break }
            key = target; lifetime = min(lifetime, ttl)
        }
        throw invalidDNS
    }
}

/// A short-lived HTTP/1.1 DoH exchange. Connect to the bootstrap IP with TLS SNI
/// and verify system trust against doh.360.cn rather than the numeric IP.
private final class DoHRequest: @unchecked Sendable {
    private let queue = DispatchQueue(label: "CoreaVPN.DoH")
    private let connection: NWConnection
    private var continuation: CheckedContinuation<Data, Error>?
    private var received = Data()
    private var cancelled = false
    private let request: Data

    init(ip: String, interface: NWInterface, query: Data) {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, "doh.360.cn")
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, trust, complete in
            let t = sec_trust_copy_ref(trust).takeRetainedValue()
            guard SecTrustSetPolicies(t, SecPolicyCreateSSL(true, "doh.360.cn" as CFString)) == errSecSuccess else {
                complete(false); return
            }
            complete(SecTrustEvaluateWithError(t, nil))
        }, queue)
        let params = NWParameters(tls: tls)
        params.requiredInterface = interface
        params.preferNoProxies = true
        connection = NWConnection(host: NWEndpoint.Host(ip), port: 443, using: params)
        let headers = ["POST /dns-query HTTP/1.1", "Host: doh.360.cn", "Connection: close",
                       "Content-Type: application/dns-message", "Accept: application/dns-message",
                       "Content-Length: \(query.count)", "", ""].joined(separator: "\r\n")
        request = Data(headers.utf8) + query
    }

    func run() async throws -> Data {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { completion in
                queue.async {
                    guard !self.cancelled else { completion.resume(throwing: CancellationError()); return }
                    self.continuation = completion
                    self.connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            self.connection.send(content: self.request, completion: .contentProcessed { error in
                                if let error { self.finish(.failure(error)) }
                                else { self.read() }
                            })
                        case .failed(let error): self.finish(.failure(error))
                        default: break
                        }
                    }
                    self.connection.start(queue: self.queue)
                    self.queue.asyncAfter(deadline: .now() + 6) {
                        self.finish(.failure(VPNNetworkError.message("DNS 중계 응답 시간이 초과되었습니다.")))
                    }
                }
            }
        }, onCancel: { self.queue.async { self.cancelled = true; self.finish(.failure(CancellationError())) } })
    }

    private func read() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, ended, error in
            guard self.continuation != nil else { return }
            if let data { self.received += data }
            do {
                guard self.received.count <= 128 * 1024 else { throw invalidDNS }
                let done = ended || error != nil
                if let body = try Self.body(self.received, eof: done) { self.finish(.success(body)) }
                else if let error { self.finish(.failure(error)) }
                else if ended { self.finish(.failure(invalidDNS)) }
                else { self.read() }
            } catch { self.finish(.failure(error)) }
        }
    }

    private static func body(_ data: Data, eof: Bool) throws -> Data? {
        let crlf = Data("\r\n".utf8)
        guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        guard let header = String(data: data[..<headerEnd.lowerBound], encoding: .ascii) else { throw invalidDNS }
        let lines = header.lowercased().components(separatedBy: "\r\n")
        guard let status = lines.first?.split(separator: " "), status.count >= 2, status[1] == "200",
              lines.contains(where: { $0.hasPrefix("content-type:") && $0.contains("application/dns-message") })
        else { throw invalidDNS }
        let bytes = data[headerEnd.upperBound...]
        if lines.contains(where: { $0.hasPrefix("transfer-encoding:") && $0.contains("chunked") }) {
            var p = bytes.startIndex, output = Data()
            while let end = bytes.range(of: crlf, in: p..<bytes.endIndex) {
                let sizeText = String(decoding: bytes[p..<end.lowerBound], as: UTF8.self).split(separator: ";").first
                guard let sizeText, let size = Int(sizeText, radix: 16), (0...65535).contains(size) else { throw invalidDNS }
                p = end.upperBound
                if size == 0 { return output }
                guard bytes.endIndex - p >= size + 2 else { return nil }
                guard bytes[(p + size)..<(p + size + 2)].elementsEqual(crlf) else { throw invalidDNS }
                output += bytes[p..<(p + size)]
                p += size + 2
            }
            return nil
        }
        if let lengthHeader = lines.first(where: { $0.hasPrefix("content-length:") }) {
            guard let length = Int(lengthHeader.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)),
                  (0...65535).contains(length) else { throw invalidDNS }
            return bytes.count >= length ? Data(bytes.prefix(length)) : nil
        }
        return eof ? Data(bytes) : nil
    }

    private func finish(_ result: Result<Data, Error>) {
        guard let c = continuation else { return }
        continuation = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        c.resume(with: result)
    }
}

actor VPNResolver {
    private let monitor = NWPathMonitor()
    private let physicalMonitors = [NWInterface.InterfaceType.wiredEthernet, .wifi, .cellular]
        .map { NWPathMonitor(requiredInterfaceType: $0) }
    private var seenInterfaces: [String: NWInterface] = [:]
    private var cached = [String: (String, Date)]()
    private var lastNetwork: String?
    private var revision: UInt = 0

    init() {
        let queue = DispatchQueue(label: "CoreaVPN.DNSPath")
        for m in [monitor] + physicalMonitors {
            m.pathUpdateHandler = { _ in }
            m.start(queue: queue)
        }
    }
    deinit { monitor.cancel(); physicalMonitors.forEach { $0.cancel() } }

    func nextExpiry() -> Date? { cached.values.map { $0.1 }.min() }
    func flush() { revision &+= 1; cached.removeAll(); seenInterfaces.removeAll(); lastNetwork = nil }

    private func interfaceIsUp(_ name: String) -> Bool {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return false }
        defer { freeifaddrs(first) }
        return sequence(first: first, next: { $0.pointee.ifa_next }).contains { entry in
            let item = entry.pointee
            guard String(cString: item.ifa_name) == name,
                  item.ifa_flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING),
                  let address = item.ifa_addr else { return false }
            return [AF_INET, AF_INET6].contains(Int32(address.pointee.sa_family))
        }
    }

    private func physicalInterface(named name: String?) async throws -> NWInterface {
        for _ in 0..<24 {
            try Task.checkCancellation()
            let path = monitor.currentPath
            let advertised = ([path] + physicalMonitors.map { $0.currentPath }).flatMap { $0.availableInterfaces }
            for link in advertised where [.wifi, .wiredEthernet, .cellular].contains(link.type) {
                seenInterfaces[link.name] = link
            }
            if let name {
                if let exact = seenInterfaces[name], exact.index == Int(if_nametoindex(name)), interfaceIsUp(name) { return exact }
            } else {
                let available = advertised.filter { [.wifi, .wiredEthernet, .cellular].contains($0.type) && interfaceIsUp($0.name) }
                if let best = available.first(where: { path.usesInterfaceType($0.type) }) ?? available.first { return best }
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw VPNNetworkError.message("선택한 물리 네트워크 회선을 찾을 수 없습니다.")
    }

    func resolve(_ host: String, network: String, interface: String? = nil) async throws -> String {
        guard VPNEndpoints.all.contains(host) else { throw invalidDNS }
        guard VPNEndpoints.net.contains(host) else { return host }
        return try await publicAnswer(for: host, network: network, interface: interface)
    }

    /// Used exclusively for the remote server of an explicitly selected proxy leaf.
    /// The IKEv2 credential path above retains its own closed 23-host allowlist.
    func resolveProxyEndpoint(_ host: String, network: String, interface: String) async throws -> String {
        if VPNEndpoints.isPublicIPv4(host) { return host }
        let name = host.lowercased(), labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard !interface.isEmpty, IPv4Address(name) == nil, IPv6Address(name) == nil,
              !name.hasSuffix(".local"), name.utf8.count <= 253, labels.count >= 2,
              labels.allSatisfy({ label in
                  !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
                      label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
              }) else { throw invalidDNS }
        return try await publicAnswer(for: name, network: network, interface: interface)
    }

    private func publicAnswer(for host: String, network: String, interface: String?) async throws -> String {
        let scope = network + "/" + (interface ?? "")
        if lastNetwork != scope { flush(); lastNetwork = scope }
        let started = revision
        if let (ip, until) = cached[host], until > Date() { return ip }
        let id = UInt16.random(in: 0...UInt16.max)
        let query = EndpointDNS.query(host, id: id)
        var reason: Error = invalidDNS
        let bootstraps = ["101.198.193.29", "101.198.192.33"]
        for attempt in 0..<4 {
            try Task.checkCancellation()
            let physical = try await physicalInterface(named: interface)
            let ip = bootstraps[attempt % bootstraps.count]
            if attempt == 2 { try await Task.sleep(nanoseconds: 400_000_000) }
            do {
                let data = try await DoHRequest(ip: ip, interface: physical, query: query).run()
                let answer = try EndpointDNS.answer(data, for: host, id: id)
                guard revision == started else { throw CancellationError() }
                cached[host] = (answer.address, Date().addingTimeInterval(TimeInterval(answer.ttl)))
                return answer.address
            } catch is CancellationError { throw CancellationError() }
            catch { reason = error }
        }
        throw reason
    }
}
