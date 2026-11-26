import Foundation

@main struct TransparentRoutingChecks {
    static func main() throws {
        let url = "http://health.example/check"
        let source = """
        proxies:
          - { name: first, type: ss }
          - { name: second, type: ss }
        proxy-groups:
          - { name: Failover, type: fallback, proxies: [first, second], url: http://health.example/check, interval: 5 }
          - { name: Speed, type: url-test, proxies: [first, second], url: http://health.example/check, tolerance: 15 }
          - { name: Spread, type: load-balance, strategy: consistent-hashing, proxies: [first, second], url: http://health.example/check }
          - { name: Use, type: select, proxies: [first, second] }
          - { name: Cycle, type: select, proxies: [Cycle] }
        rules:
          - DOMAIN,direct.example,DIRECT
          - DOMAIN,failover.example,Failover
          - DOMAIN,speed.example,Speed
          - DOMAIN,spread.example,Spread
          - DOMAIN,select.example,Use
          - DOMAIN,cycle.example,Cycle
          - DOMAIN,deny.example,REJECT
          - MATCH,DIRECT
        """
        var doc = try ClashRuleImport.parse(source)
        doc.rules.insert(RoutingRule(kind: "DOMAIN", value: "vpn.example", policy: .coreaVPN), at: 0)
        let config: [String: Any] = [
            "version": 1, "rules": try JSONEncoder().encode(doc),
            "physicalInterface": "en999", "physicalIndex": 123456, "physicalIPv4": "192.0.2.1",
            "nodes": ["first": Data([1]), "second": Data([2])],
            "peers": ["first": "1.1.1.1", "second": "1.1.1.2"], "selections": ["Use": "second"]
        ]
        var tick: TimeInterval = 50
        let session = try RoutingSession(config: config, queue: DispatchQueue(label: "checks"), uptime: { tick })
        func paths(_ domain: String) -> [FlowExit] {
            var q = RouteQuery()
            q.domain = domain; q.ip = "203.0.113.80"; q.port = 443; q.transport = "TCP"
            return session.routes(q)
        }
        precondition(paths("vpn.example").isEmpty)
        let tuple: [String: Any] = ["vpnInterface": "ipsec4", "vpnIndex": 19, "vpnIPv4": "10.4.5.6",
                                    "selectedServer": "puma.coreavpn.net", "sessionDate": 14.0]
        session.updateVPN(tuple)
        precondition(paths("direct.example").first?.binding.name == "en999")
        precondition(paths("vpn.example").first?.binding.name == "ipsec4")
        tick += 14
        precondition(paths("vpn.example").count == 1)
        session.updateVPN(tuple)
        tick += 14
        precondition(paths("vpn.example").count == 1)
        tick += 1
        precondition(paths("vpn.example").isEmpty && paths("direct.example").count == 1)
        session.updateVPN([:])
        precondition(paths("vpn.example").isEmpty)
        precondition(paths("deny.example").isEmpty && paths("cycle.example").isEmpty)
        precondition(paths("select.example").isEmpty)
        var nodes = [String: Data]()
        for name in ["first", "second"] {
            nodes[name] = try JSONSerialization.data(withJSONObject: ["name": name, "type": "ss", "password": "fixture", "server": "proxy.example", "port": 443, "cipher": "aes-128-gcm"])
        }
        session.replaceNodes(nodes)
        precondition(paths("select.example").first?.node == "second")
        precondition(paths("failover.example").isEmpty)
        session.recordHealth(leaf: "first", url: url, latency: 50)
        session.recordHealth(leaf: "second", url: url, latency: 40)
        precondition(paths("failover.example").compactMap(\.node) == ["first", "second"])
        precondition(paths("speed.example").first?.node == "second")
        session.recordHealth(leaf: "first", url: url, latency: 30)
        precondition(paths("speed.example").first?.node == "second")
        session.recordHealth(leaf: "first", url: url, latency: 10)
        precondition(paths("speed.example").first?.node == "first")
        let initial = paths("spread.example").map(\.node)
        precondition(initial.count == 2 && paths("spread.example").map(\.node) == initial)
        session.recordHealth(leaf: "first", url: url, latency: -1)
        precondition(paths("failover.example").compactMap(\.node) == ["second"])
        session.recordHealth(leaf: "second", url: url, latency: 40, at: .distantPast)
        precondition(paths("failover.example").isEmpty)
        precondition(paths("").isEmpty)  // prior domain rules require a known hostname
        session.replaceNodes([:])
        precondition(paths("select.example").isEmpty)

        session.invalidatePhysical()
        session.updateVPN(tuple)
        precondition(paths("direct.example").isEmpty && paths("vpn.example").isEmpty)

        let geoRule = RoutingDocument(rules: [RoutingRule(kind: "GEOIP", value: "CN", policy: .direct)])
        // GeoIPList { country_code: CN, cidr: 1.2.3.0/24 } plus an unreferenced region.
        let fixture = Data([10,14,10,2,67,78,18,8,10,4,1,2,3,0,16,24,10,4,10,2,85,83])
        let subset = try RoutingGeoDatabase.subset(from: fixture, for: geoRule)
        precondition(subset.count == 16)
        let db = try RoutingGeoDatabase(subset)
        precondition(db.classifier(address: "1.2.3.9")("CN") == .yes)
        precondition(db.classifier(address: "1.2.4.9")("CN") == .no)
        precondition(db.classifier(address: "1.2.3.9")("US") == .unknown)
        do { _ = try RoutingGeoDatabase(Data([10,255])); preconditionFailure("truncated GEOIP was accepted") }
        catch is RuleProblem {}

        if CommandLine.arguments.count == 3 {
            let active = try ClashRuleImport.parse(String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8))
            let raw = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]), options: .mappedIfSafe)
            let subset = try RoutingGeoDatabase.subset(from: raw, for: active)
            let db = try RoutingGeoDatabase(subset)
            precondition(db.classifier(address: "10.0.0.1")("PRIVATE") == .yes)
            precondition(db.classifier(address: "223.5.5.5")("CN") == .yes)
            precondition(db.classifier(address: "8.8.8.8")("CN") == .no)
            print("Imported \(active.rules.count) rules, \(active.groups.count) groups, \(subset.count) bytes of GEOIP prefixes")
        }
        print("Transparent policy, selected server, group availability and GEOIP checks passed")
    }
}
