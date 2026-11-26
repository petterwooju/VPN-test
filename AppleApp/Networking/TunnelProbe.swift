import Foundation
import Darwin

enum TunnelProbe {
    static let destination = "168.126.63.1"
    static let count = 20
    private static let routeFailure = VPNNetworkError.message("측정 목적지의 VPN 경로를 확인할 수 없습니다.")

    private static func target(_ ip: String = destination) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr(ip)
        return address
    }

    private static func connect(_ fd: Int32, address: inout sockaddr_in) throws {
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result < 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .ENETUNREACH) }
    }

    /// UDP connect only selects a source address; it never sends a datagram.
    static func routeInterface(destination ip: String = destination) throws -> String {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw routeFailure }
        defer { close(fd) }
        var address = target(ip)
        address.sin_port = UInt16(9).bigEndian
        try connect(fd, address: &address)
        return try localInterface(of: fd)
    }

    private static func localInterface(of fd: Int32) throws -> String {
        var local = sockaddr_in(), len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let result = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard result == 0 else { throw routeFailure }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0 else { throw routeFailure }
        defer { freeifaddrs(list) }
        var cursor = list, matches = Set<String>()
        while let item = cursor?.pointee {
            if let address = item.ifa_addr, Int32(address.pointee.sa_family) == AF_INET {
                let sin = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self)
                if sin.pointee.sin_addr.s_addr == local.sin_addr.s_addr {
                    matches.insert(String(cString: item.ifa_name))
                }
            }
            cursor = item.ifa_next
        }
        guard matches.count == 1, let name = matches.first else { throw routeFailure }
        return name
    }

    static func isTunnel(_ name: String) -> Bool {
        ["ipsec", "utun", "ppp", "tun"].contains { prefix in
            let suffix = name.dropFirst(prefix.count)
            return name.hasPrefix(prefix) && !suffix.isEmpty && suffix.allSatisfy(\.isNumber)
        }
    }

    private static func packet(sequence: UInt16, token: [UInt8], identifier: UInt16) -> [UInt8] {
        var bytes: [UInt8] = [8, 0, 0, 0, UInt8(identifier >> 8), UInt8(truncatingIfNeeded: identifier),
                              UInt8(sequence >> 8), UInt8(truncatingIfNeeded: sequence)] + token
        var sum: UInt32 = 0
        for i in stride(from: 0, to: bytes.count, by: 2) {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let checksum = ~UInt16(truncatingIfNeeded: sum)
        bytes[2] = UInt8(checksum >> 8); bytes[3] = UInt8(truncatingIfNeeded: checksum)
        return bytes
    }

    static func matchesEcho(_ reply: ArraySlice<UInt8>, sequence: UInt16, token: [UInt8]) -> Bool {
        let r = Array(reply)
        guard r.count >= 8 else { return false }
        let offset = r[0] >> 4 == 4 ? Int(r[0] & 15) * 4 : 0
        if offset != 0 && (offset < 20 || r.count <= 9 || r[9] != UInt8(IPPROTO_ICMP)) { return false }
        guard r.count >= offset + 8 + token.count, r[offset] == 0, r[offset + 1] == 0,
              r[offset + 6] == UInt8(sequence >> 8), r[offset + 7] == UInt8(truncatingIfNeeded: sequence)
        else { return false }
        return r[(offset + 8)..<(offset + 8 + token.count)].elementsEqual(token)
    }

    @MainActor static func measure(interface: String, validate: () throws -> Void) async throws -> [Double] {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { throw VPNNetworkError.message("ICMP 측정 소켓을 열 수 없습니다 (\(errno)).") }
        defer { close(fd) }
        var index = if_nametoindex(interface), address = target()
        guard index != 0, setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index,
                                     socklen_t(MemoryLayout<UInt32>.size)) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw routeFailure }
        try connect(fd, address: &address)
        guard try localInterface(of: fd) == interface else { throw routeFailure }
        var random = SystemRandomNumberGenerator()
        // 56 payload bytes, matching the existing macOS ping helper's default size.
        let token = (0..<56).map { _ in UInt8.random(in: 0...255, using: &random) }
        let identifier = UInt16.random(in: 1...UInt16.max)
        var echoes: [Int: Double] = [:], sentAt: [UInt64] = []
        let began = DispatchTime.now().uptimeNanoseconds
        // Keep late replies until 22 seconds, as in the historical ping -c 20 -i 1 -t 22.
        for tick in 0..<22 {
            try Task.checkCancellation()
            try validate()
            let expectedStart = began + UInt64(tick) * 1_000_000_000
            guard DispatchTime.now().uptimeNanoseconds < expectedStart + 900_000_000 else {
                throw VPNNetworkError.message("앱이 중단되어 ping 측정을 다시 시작해야 합니다.")
            }
            let next = began + UInt64(tick + 1) * 1_000_000_000
            if tick < count {
                let bytes = packet(sequence: UInt16(tick), token: token, identifier: identifier)
                sentAt.append(DispatchTime.now().uptimeNanoseconds)
                let sent = bytes.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
                guard sent == bytes.count else {
                    throw VPNNetworkError.message("ICMP 요청을 보내지 못했습니다 (\(errno)).")
                }
            }
            // Poll on a utility queue. RTT is timestamped at receive, independent of UI refresh/scheduling.
            let times = try await collectReplies(fd: fd, until: next, starts: sentAt,
                                                 token: token, previous: Set(echoes.keys))
            for (sequence, rtt) in times where echoes[sequence] == nil { echoes[sequence] = rtt }
            if echoes.count == count { break }
        }
        try Task.checkCancellation()
        try validate()
        return echoes.keys.sorted().compactMap { echoes[$0] }
    }

    private static func collectReplies(fd: Int32, until deadline: UInt64, starts: [UInt64],
                                       token: [UInt8], previous: Set<Int>) async throws -> [Int: Double] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                var buffer = [UInt8](repeating: 0, count: 2048), replies: [Int: Double] = [:]
                var watch = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                while replies.count + previous.count < count {
                    let now = DispatchTime.now().uptimeNanoseconds
                    if now >= deadline { break }
                    let timeout = Int32(min((deadline - now + 999_999) / 1_000_000, 1000))
                    let available = poll(&watch, 1, timeout)
                    if available == 0 { continue }
                    if available < 0 && errno == EINTR { continue }
                    guard available > 0, watch.revents & Int16(POLLIN) != 0 else {
                        continuation.resume(throwing: routeFailure); return
                    }
                    let size = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
                    let receipt = DispatchTime.now().uptimeNanoseconds
                    if size < 0 && [EAGAIN, EWOULDBLOCK, EINTR].contains(errno) { continue }
                    guard size >= 0 else {
                        continuation.resume(throwing: VPNNetworkError.message("ICMP 응답 수신 오류 (\(errno)).")); return
                    }
                    guard size >= 8 else { continue }
                    let offset = buffer[0] >> 4 == 4 ? Int(buffer[0] & 15) * 4 : 0
                    guard offset + 8 <= size else { continue }
                    let seq = Int(buffer[offset + 6]) << 8 | Int(buffer[offset + 7])
                    if seq < starts.count, !previous.contains(seq), replies[seq] == nil,
                       matchesEcho(buffer.prefix(size), sequence: UInt16(seq), token: token) {
                        replies[seq] = Double(receipt - starts[seq]) / 1_000_000
                    }
                }
                continuation.resume(returning: replies)
            }
        }
    }
}
