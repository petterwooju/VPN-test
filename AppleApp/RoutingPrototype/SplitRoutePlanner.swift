import Darwin
import Foundation
import Network
import NetworkExtension

/// A static CIDR or a DNS answer bound to a particular uplink generation.
struct SplitRouteLease: Codable, Hashable {
    let label: String
    let cidr: String
    let policy: RoutingPolicy
    let networkID: String
    let expiresAt: Date?
}

enum SplitRouteError: LocalizedError {
    case invalid(String), changedNetwork, expired(String), overlap(String, String), missingTransport(RoutingPolicy)

    var errorDescription: String? {
        switch self {
        case let .invalid(message): return message
        case .changedNetwork: return "회선이 변경되었습니다. 경로를 다시 확인해 주세요."
        case let .expired(label): return "\(label)의 DNS 경로가 만료되었습니다."
        case let .overlap(first, second): return "\(first) 및 \(second)의 IP 대역이 겹치지만 지정한 출구가 다릅니다."
        case let .missingTransport(policy): return "\(policy.title) 경로에 사용할 인증된 전송 연결이 없습니다."
        }
    }
}

private struct RouteBlock: Hashable {
    let family: Int32
    let prefix: Int
    let bytes: [UInt8]

    private init(family: Int32, prefix: Int, bytes: [UInt8]) {
        self.family = family
        self.prefix = prefix
        self.bytes = bytes
    }

    init(_ value: String) throws {
        guard let cidr = RoutingCIDR(value), cidr.bits > 0 else {
            throw SplitRouteError.invalid("명시적인 IPv4·IPv6 대역이 필요합니다. 기본 경로는 허용하지 않습니다.")
        }
        family = cidr.family
        prefix = cidr.bits
        bytes = zip(cidr.network, Self.mask(cidr.bits, size: cidr.network.count)).map { $0 & $1 }
    }

    static func mask(_ prefix: Int, size: Int) -> [UInt8] {
        (0..<size).map { octet in
            let bits = min(8, max(0, prefix - 8 * octet))
            return bits == 0 ? 0 : UInt8.max << (8 - bits)
        }
    }

    var address: String {
        if family == AF_INET { return bytes.map(String.init).joined(separator: ".") }
        var result = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = bytes.withUnsafeBytes { inet_ntop(AF_INET6, $0.baseAddress, &result, socklen_t(result.count)) }
        return String(cString: result)
    }

    var subnetMask: String { Self.mask(prefix, size: 4).map(String.init).joined(separator: ".") }

    func contains(_ child: Self) -> Bool {
        guard family == child.family, prefix <= child.prefix else { return false }
        let whole = prefix / 8, remainder = prefix % 8
        guard bytes.prefix(whole) == child.bytes.prefix(whole) else { return false }
        return remainder == 0 || bytes[whole] >> (8 - remainder) == child.bytes[whole] >> (8 - remainder)
    }

    static func ordered(_ a: Self, _ b: Self) -> Bool {
        if a.family != b.family { return a.family < b.family }
        if a.bytes != b.bytes { return a.bytes.lexicographicallyPrecedes(b.bytes) }
        return a.prefix < b.prefix
    }

    /// Split only along the path to an explicitly different condition. A /128
    /// inside a /64 yields 64 complementary blocks and one host, not 2^64 hosts.
    func partition(at boundary: Self) -> [Self] {
        guard prefix < boundary.prefix, contains(boundary) else { return [self] }
        var parts: [Self] = [], current = self
        while current.prefix < boundary.prefix {
            let offset = current.prefix / 8, bit = UInt8(0x80) >> (current.prefix % 8)
            var upperBytes = current.bytes
            upperBytes[offset] |= bit
            let lower = Self(family: family, prefix: current.prefix + 1, bytes: current.bytes)
            let upper = Self(family: family, prefix: current.prefix + 1, bytes: upperBytes)
            let goUpper = boundary.bytes[offset] & bit != 0
            parts.append(goUpper ? lower : upper)
            current = goUpper ? upper : lower
        }
        parts.append(current)
        return parts
    }

    func combiningSibling(_ other: Self) -> Self? {
        guard family == other.family, prefix == other.prefix, prefix > 0, bytes != other.bytes else { return nil }
        var parentBytes = bytes
        parentBytes[(prefix - 1) / 8] &= ~(UInt8(0x80) >> ((prefix - 1) % 8))
        let parent = Self(family: family, prefix: prefix - 1, bytes: parentBytes)
        return parent.contains(other) ? parent : nil
    }
}

struct AppleSplitRoutes {
    var includedIPv4: [NEIPv4Route] = []
    var includedIPv6: [NEIPv6Route] = []
    var excludedIPv4: [NEIPv4Route] = []
    var excludedIPv6: [NEIPv6Route] = []
}

struct SplitRoutePlan {
    fileprivate struct Entry {
        let lease: SplitRouteLease
        let block: RouteBlock
    }
    fileprivate let entries: [Entry]
    let networkID: String
    let validUntil: Date?

    var routeCount: Int { entries.count }
    var requiredTransports: Set<RoutingPolicy> { Set(entries.map { $0.lease.policy }.filter { $0 != .direct }) }

    func validate(networkID: String, now: Date) throws {
        guard self.networkID == networkID else { throw SplitRouteError.changedNetwork }
        if let date = validUntil, now >= date { throw SplitRouteError.expired("현재 규칙") }
    }

    /// The caller must have an authenticated data plane for every captured policy.
    /// Generating NE route values does not install them or start a tunnel.
    func appleRoutes(networkID: String, now: Date = Date(), readyPolicies: Set<RoutingPolicy>) throws -> AppleSplitRoutes {
        try validate(networkID: networkID, now: now)
        var routes = AppleSplitRoutes()
        for entry in entries {
            let block = entry.block, direct = entry.lease.policy == .direct
            guard direct || readyPolicies.contains(entry.lease.policy) else { throw SplitRouteError.missingTransport(entry.lease.policy) }
            if block.family == AF_INET {
                let route = NEIPv4Route(destinationAddress: block.address, subnetMask: block.subnetMask)
                if direct { routes.excludedIPv4.append(route) } else { routes.includedIPv4.append(route) }
            } else {
                let route = NEIPv6Route(destinationAddress: block.address, networkPrefixLength: NSNumber(value: block.prefix))
                if direct { routes.excludedIPv6.append(route) } else { routes.includedIPv6.append(route) }
            }
        }
        return routes
    }

    func policy(for address: String, networkID: String, now: Date = Date()) throws -> RoutingPolicy? {
        try validate(networkID: networkID, now: now)
        let candidate = try RouteBlock(address + (address.contains(":") ? "/128" : "/32"))
        return entries.first { $0.block.contains(candidate) }?.lease.policy
    }
}

enum SplitRoutePlanner {
    static func startupLimit(proxyGroups: Int) -> TimeInterval {
        // Each group can require four bounded physical DoH attempts followed
        // by a twelve-second authenticated proxy preflight.
        30 + 50 * Double(proxyGroups)
    }
    /// Prove one first-match action for every address in the requested block.
    /// Earlier process/domain/port dependencies require per-flow metadata that a
    /// system IP route cannot encode. Never infer a subnet policy from its first IP.
    static func policy(forCIDR cidr: String, document: RoutingDocument) throws -> RoutingPolicy {
        var pending = [try RouteBlock(cidr)]
        let targets = document.knownTargets
        var selected: RoutingPolicy?
        for rule in document.rules {
            let boundaries = rule.addressConditions.compactMap { try? RouteBlock($0) }
            var remaining: [RouteBlock] = []
            for region in pending {
                var parts = [region]
                for boundary in boundaries {
                    parts = parts.flatMap { $0.partition(at: boundary) }
                    guard parts.count <= 16384 else { throw SplitRouteError.invalid("규칙 경계가 너무 많습니다. 검사 범위를 더 작은 대역으로 나누어 주세요.") }
                }
                for part in parts {
                    var query = RouteQuery()
                    query.ip = part.address
                    switch rule.compare(query, supportsProcess: RoutingDocument.supportsProcess) {
                    case .no: remaining.append(part)
                    case .unknown:
                        throw SplitRouteError.invalid("\(part.address)/\(part.prefix)에서 앞선 \(rule.kind) 조건을 IP만으로 확정할 수 없습니다.")
                    case .yes:
                        if case .group(let name) = rule.policy, !targets.contains(name) { throw SplitRouteError.missingTransport(rule.policy) }
                        if let selected, selected != rule.policy {
                            throw SplitRouteError.invalid("\(cidr)에 \(selected.title) 및 \(rule.policy.title) 경로가 함께 지정되어 있습니다. 대역을 나누어 주세요.")
                        }
                        selected = rule.policy
                    }
                }
            }
            pending = remaining
            guard pending.count <= 16384 else { throw SplitRouteError.invalid("규칙 경계가 너무 많습니다. 검사 범위를 더 작은 대역으로 나누어 주세요.") }
            if pending.isEmpty, let selected { return selected }
        }
        throw SplitRouteError.invalid("\(cidr)의 모든 주소가 명시된 규칙과 일치해야 합니다.")
    }

    static func make(leases: [SplitRouteLease], networkID: String, now: Date = Date()) throws -> SplitRoutePlan {
        guard !networkID.isEmpty, !leases.isEmpty else { throw SplitRouteError.invalid("검증할 회선과 경로가 필요합니다.") }
        var entries: [SplitRoutePlan.Entry] = []
        var validUntil: Date?
        for lease in leases {
            guard lease.networkID == networkID else { throw SplitRouteError.changedNetwork }
            if let expiry = lease.expiresAt {
                guard expiry > now else { throw SplitRouteError.expired(lease.label) }
                validUntil = min(validUntil ?? expiry, expiry)
            }
            guard lease.policy != .reject else { throw SplitRouteError.invalid("REJECT 규칙에는 별도의 콘텐츠 필터가 필요합니다.") }
            entries.append(.init(lease: lease, block: try RouteBlock(lease.cidr)))
        }
        entries.sort { RouteBlock.ordered($0.block, $1.block) }
        var disjoint: [SplitRoutePlan.Entry] = []
        // Canonical CIDRs of one family are either disjoint or one contains the other.
        // Sorting by address and prefix puts a containing block before every child.
        for entry in entries {
            if let prior = disjoint.last, prior.block.contains(entry.block) {
                guard prior.lease.policy == entry.lease.policy else { throw SplitRouteError.overlap(prior.lease.label, entry.lease.label) }
            } else { disjoint.append(entry) }
        }
        // Two /1s or eight /3s can silently recreate a full tunnel even though
        // every individual entry has a nonzero prefix.
        var captures: [RouteBlock] = []
        for entry in disjoint where entry.lease.policy != .direct {
            var next = entry.block
            while let last = captures.last, let merged = last.combiningSibling(next) {
                captures.removeLast()
                next = merged
            }
            guard next.prefix > 0 else { throw SplitRouteError.invalid("선택한 대역들의 합은 기본 경로를 포함할 수 없습니다.") }
            captures.append(next)
        }
        return SplitRoutePlan(entries: disjoint, networkID: networkID, validUntil: validUntil)
    }
}

/// Compute on the host before preparing leases and again in the provider on start.
enum SplitUplink {
    /// Ask the kernel which source address it would use for the IKE peer. A UDP
    /// connect on a fresh datagram socket sets a route without sending a packet.
    /// A new utun or changed VPN default gateway must not invalidate the real
    /// uplink if the excluded IKE peer still follows its original physical route.
    static func fingerprint(to peer: String) -> String? {
        var remote = sockaddr_in()
        remote.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        remote.sin_family = sa_family_t(AF_INET)
        remote.sin_port = UInt16(500).bigEndian
        guard inet_pton(AF_INET, peer, &remote.sin_addr) == 1 else { return nil }
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        let routed = withUnsafePointer(to: &remote) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard routed == 0 else { return nil }
        var local = sockaddr_in(), length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let selected = withUnsafeMutablePointer(to: &local) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard selected == 0, local.sin_addr.s_addr != 0 else { return nil }
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let head = first else { return nil }
        defer { freeifaddrs(head) }
        var found = Set<String>()
        for cursor in sequence(first: head, next: { $0.pointee.ifa_next }) {
            let row = cursor.pointee
            guard let address = row.ifa_addr, let netmask = row.ifa_netmask, address.pointee.sa_family == AF_INET,
                  row.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
            let ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr.s_addr
            guard ip == local.sin_addr.s_addr else { continue }
            let name = String(cString: row.ifa_name)
            // Only physical Ethernet/Wi-Fi and iOS cellular interfaces qualify.
            let physical = ["en", "pdp_ip"].contains { prefix in
                let suffix = name.dropFirst(prefix.count)
                return name.hasPrefix(prefix) && !suffix.isEmpty && suffix.allSatisfy(\.isNumber)
            }
            guard physical else { return nil }
            let mask = UnsafeRawPointer(netmask).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr.s_addr
            found.insert("\(name)#\(if_nametoindex(row.ifa_name))|\(UInt32(bigEndian: ip))/\(UInt32(bigEndian: mask))")
        }
        return found.count == 1 ? found.first : nil
    }

    static func fingerprint(_ path: Network.NWPath) -> String? {
        guard path.status == .satisfied else { return nil }
        let physical: [NWInterface.InterfaceType] = [.wiredEthernet, .wifi, .cellular]
        let links = path.availableInterfaces
            .filter { physical.contains($0.type) && path.usesInterfaceType($0.type) }
            .map { "\($0.name)#\($0.index)" }.sorted()
        guard !links.isEmpty else { return nil }
        let gateways = path.gateways.map(String.init(describing:)).sorted()
        return (links + gateways).joined(separator: "|")
    }
}
