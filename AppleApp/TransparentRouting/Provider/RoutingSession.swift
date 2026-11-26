import CoreIPSec
import Darwin
import Foundation
import SystemConfiguration

struct RouteBinding: Equatable {
    let name: String
    let index: UInt32
    let ipv4: String

    init?(_ values: [String: Any], _ role: String) {
        let pattern = role == "vpn" ? #"^(ipsec|utun)[0-9]+$"# : #"^en[0-9]+$"#
        guard let name = values[role + "Interface"] as? String, name.range(of: pattern, options: .regularExpression) != nil,
              let number = values[role + "Index"] as? Int, let index = UInt32(exactly: number), index > 0,
              let ip = values[role + "IPv4"] as? String else { return nil }
        var address = in_addr()
        guard inet_pton(AF_INET, ip, &address) == 1 else { return nil }
        self.name = name; self.index = index; self.ipv4 = ip
    }

    var available: Bool {
        guard if_nametoindex(name) == index else { return false }
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return false }
        defer { freeifaddrs(head) }
        var entry = head, expected = in_addr()
        guard inet_pton(AF_INET, ipv4, &expected) == 1 else { return false }
        while let node = entry {
            entry = node.pointee.ifa_next
            guard String(cString: node.pointee.ifa_name) == name, node.pointee.ifa_flags & UInt32(IFF_UP) != 0,
                  let address = node.pointee.ifa_addr, address.pointee.sa_family == UInt8(AF_INET) else { continue }
            let bytes = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            if bytes.s_addr == expected.s_addr { return true }
        }
        return false
    }
}

struct FlowExit {
    let binding: RouteBinding
    let isVPN: Bool
    let node: String?
    let specification: String

    init?(binding: RouteBinding, vpn: Bool = false, node: String? = nil, settings: [String: Any]? = nil) {
        var values: [String: Any] = ["interface": binding.name, "index": Int(binding.index), "ipv4": binding.ipv4]
        if let settings { values["node"] = settings }
        guard let data = try? JSONSerialization.data(withJSONObject: values), let text = String(data: data, encoding: .utf8) else { return nil }
        self.binding = binding; self.isVPN = vpn; self.node = node; self.specification = text
    }

    func open(host: String, port: Int, udp: Bool) -> Int32 {
        guard binding.available else { return -1 }
        return specification.withCString { spec in host.withCString { address in
            CRouteOpen(UnsafeMutablePointer(mutating: spec), UnsafeMutablePointer(mutating: address), Int32(port), udp ? 1 : 0)
        }}
    }

    func probe(url: String) -> Int {
        guard binding.available else { return -1 }
        return specification.withCString { spec in url.withCString { endpoint in
            Int(CRouteProbe(UnsafeMutablePointer(mutating: spec), UnsafeMutablePointer(mutating: endpoint)))
        }}
    }
}

/// All mutations and selection happen on the provider's single state queue.
/// Slow health requests and socket opens execute separately.
final class RoutingSession {
    let document: RoutingDocument
    let physical: RouteBinding
    private(set) var vpn: RouteBinding?
    private(set) var server: String?
    private(set) var sessionDate: Double?
    private var leaseExpires: TimeInterval = 0
    private(set) var physicalInvalidated = false
    private let uptime: () -> TimeInterval
    private var leaves = [String: FlowExit]()
    private let nodeNames: Set<String>
    private let peers: [String: String]
    private let selections: [String: String]
    private let groups: [String: RoutingGroup]
    private let geo: RoutingGeoDatabase?
    private let queue: DispatchQueue
    private let probes = OperationQueue()
    private var revision = 0
    private struct HealthKey: Hashable { let leaf: String; let url: String }
    private var health = [HealthKey: (time: Date, latency: Int)]()
    private var pending = Set<HealthKey>()
    private var lastChoice = [String: String]()
    private var nextMember = [String: Int]()

    init(config: [String: Any], queue: DispatchQueue,
         uptime: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) throws {
        self.uptime = uptime
        guard config["version"] as? Int == 1, let rules = config["rules"] as? Data,
              let physical = RouteBinding(config, "physical") else { throw RuleProblem.message("라우팅 구성과 실제 회선을 확인하십시오.") }
        self.physical = physical
        self.queue = queue
        self.document = try RoutingDocument.decode(rules)
        guard !document.rules.isEmpty, document.rules.count <= 100_000, document.groups.count <= 2048 else {
            throw RuleProblem.message("적용할 규칙 수를 확인하십시오.")
        }
        self.groups = Dictionary(uniqueKeysWithValues: document.groups.map { ($0.name, $0) })
        self.geo = try (config["geoIP"] as? Data).map { try RoutingGeoDatabase($0) }
        self.selections = config["selections"] as? [String: String] ?? [:]
        self.peers = config["peers"] as? [String: String] ?? [:]
        self.nodeNames = Set((config["nodes"] as? [String: Data] ?? [:]).keys)
        self.probes.maxConcurrentOperationCount = 4
        self.probes.qualityOfService = .utility
        // VPN bindings originate from the running host after route and session verification.
    }

    deinit { probes.cancelAllOperations() }

    func updateVPN(_ message: [String: Any]) {
        let host = message["selectedServer"] as? String
        let official = host?.range(of: #"^[a-z]+\.coreavpn\.(net|com|kr)$"#, options: .regularExpression) != nil
        let date = message["sessionDate"] as? Double
        vpn = !physicalInvalidated && official && date?.isFinite == true ? RouteBinding(message, "vpn") : nil
        server = vpn == nil ? nil : host
        sessionDate = vpn == nil ? nil : date
        leaseExpires = vpn == nil ? 0 : uptime() + 15
    }

    var vpnLeaseValid: Bool { vpn != nil && uptime() < leaseExpires }

    func checkPhysical() -> Bool {
        if physicalInvalidated { return false }
        let global = SCDynamicStoreCopyValue(nil, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        let primary = global?["PrimaryInterface"] as? String
        if !physical.available || (primary?.hasPrefix("en") == true && primary != physical.name) {
            invalidatePhysical()
        }
        return !physicalInvalidated
    }

    func invalidatePhysical() {
        physicalInvalidated = true
        updateVPN([:])
        probes.cancelAllOperations()
    }

    func replaceNodes(_ nodes: [String: Data]) {
        revision &+= 1
        probes.cancelAllOperations()
        pending.removeAll(); health.removeAll(); leaves.removeAll()
        for (name, raw) in nodes where nodeNames.contains(name) && raw.count <= 65_536 {
            guard var value = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
                  value["name"] as? String == name, let type = value["type"] as? String,
                  type == document.nodeTypes?[name], ["ss", "anytls"].contains(type),
                  let peer = peers[name] else { continue }
            // The untrusted proxy options never supply the interface or initiate DNS.
            value.removeValue(forKey: "interface-name")
            value["server"] = peer
            leaves[name] = FlowExit(binding: physical, node: name, settings: value)
        }
        refreshHealth()
    }

    func refreshHealth() {
        guard !physicalInvalidated, physical.available else { return }
        for group in document.groups where ["url-test", "fallback", "load-balance"].contains(group.type) {
            let url = group.url ?? "https://www.gstatic.com/generate_204"
            let age = TimeInterval(max(1, group.interval ?? 300))
            for name in reachableLeaves(group.name, visited: []) {
                let key = HealthKey(leaf: name, url: url)
                guard let leaf = leaves[name], pending.contains(key) == false,
                      health[key].map({ Date().timeIntervalSince($0.time) >= age }) ?? true else { continue }
                pending.insert(key)
                let generation = revision
                probes.addOperation { [weak self] in
                    let latency = leaf.probe(url: url)
                    self?.queue.async { [weak self] in
                        guard let self, self.revision == generation else { return }
                        self.pending.remove(key)
                        self.recordHealth(leaf: key.leaf, url: key.url, latency: latency)
                    }
                }
            }
        }
    }

    func recordHealth(leaf: String, url: String, latency: Int, at time: Date = Date()) {
        health[HealthKey(leaf: leaf, url: url)] = (time, latency)
    }

    private func children(_ group: RoutingGroup) -> [String] {
        guard group.providers.isEmpty, (group.unsupportedOptions ?? []).isEmpty else { return [] }
        if group.type == "select" {
            guard let chosen = selections[group.name] ?? group.members.first, group.members.contains(chosen) else { return [] }
            return [chosen]
        }
        guard ["url-test", "fallback", "load-balance"].contains(group.type) else { return [] }
        return group.members
    }

    private func reachableLeaves(_ name: String, visited: Set<String>) -> [String] {
        guard visited.count < 12, !visited.contains(name) else { return [] }
        guard let group = groups[name] else { return leaves[name] == nil ? [] : [name] }
        return children(group).flatMap { reachableLeaves($0, visited: visited.union([name])) }
    }

    func decision(for query: RouteQuery) -> (rule: RoutingRule, exits: [FlowExit])? {
        guard !physicalInvalidated else { return nil }
        var q = query
        q.geoMatch = geo?.classifier(address: q.ip)
        let preview = document.preview(q, supportsProcess: true)
        guard let match = preview.match, preview.undecided.allSatisfy({ $0.policy == match.policy }) else { return nil }
        let exits: [FlowExit]
        switch match.policy {
        case .reject: return nil
        case .direct: exits = [FlowExit(binding: physical)].compactMap { $0 }
        case .coreaVPN:
            guard vpnLeaseValid, let vpn, let exit = FlowExit(binding: vpn, vpn: true) else { return nil }
            exits = [exit]
        case let .group(name): exits = routes(name, key: q.domain.isEmpty ? q.ip : q.domain, visited: [])
        }
        return exits.isEmpty ? nil : (match, exits)
    }

    private func routes(_ name: String, key: String, visited: Set<String>) -> [FlowExit] {
        guard !visited.contains(name), visited.count < 12 else { return [] }
        if name == "DIRECT" || document.nodeTypes?[name] == "direct" { return [FlowExit(binding: physical)].compactMap { $0 } }
        guard let group = groups[name] else { return leaves[name].map { [$0] } ?? [] }
        let members = children(group)
        let descendants = visited.union([name])
        if group.type == "select" { return members.first.map { routes($0, key: key, visited: descendants) } ?? [] }

        let url = group.url ?? "https://www.gstatic.com/generate_204"
        var seen = Set<String>()
        var ranked: [(exit: FlowExit, latency: Int)] = members.flatMap { routes($0, key: key, visited: descendants) }.compactMap { exit in
            guard let node = exit.node, seen.insert(node).inserted,
                  let sample = health[HealthKey(leaf: node, url: url)], sample.latency > 0,
                  Date().timeIntervalSince(sample.time) < TimeInterval(max(1, group.interval ?? 300) + 30) else { return nil }
            return (exit, sample.latency)
        }
        guard !ranked.isEmpty else { return [] }
        switch group.type {
        case "fallback": break  // configured order among healthy nodes
        case "url-test":
            ranked.sort { $0.latency < $1.latency }
            let tolerance = group.tolerance ?? 0
            if let i = ranked.firstIndex(where: { $0.exit.node == lastChoice[name] && $0.latency - ranked[0].latency <= tolerance }) {
                let previous = ranked.remove(at: i)
                ranked.insert(previous, at: 0)
            }
            lastChoice[name] = ranked[0].exit.node
        case "load-balance":
            switch group.strategy ?? "consistent-hashing" {
            case "consistent-hashing":
                // Rendezvous hashing keeps unrelated destinations stable when a node fails.
                func score(_ name: String) -> UInt64 {
                    (key + "\u{0}" + name).utf8.reduce(UInt64(14695981039346656037)) { ($0 ^ UInt64($1)) &* 1099511628211 }
                }
                ranked.sort { score($0.exit.node ?? "") > score($1.exit.node ?? "") }
            case "round-robin":
                let i = (nextMember[name] ?? 0) % ranked.count
                nextMember[name] = (i + 1) % ranked.count
                ranked = Array(ranked[i...] + ranked[..<i])
            default: return []
            }
        default: return []
        }
        return ranked.map(\.exit)
    }
}
