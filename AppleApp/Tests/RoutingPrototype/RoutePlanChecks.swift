import Foundation

@main struct RoutePlanChecks {
    static func main() throws {
        let now = Date(timeIntervalSince1970: 100), network = "test/1"
        func lease(_ ip: String, _ policy: RoutingPolicy, _ ttl: Double? = nil) -> SplitRouteLease {
            .init(label: ip, cidr: ip, policy: policy, networkID: network, expiresAt: ttl.map(now.addingTimeInterval))
        }
        let rules = [lease("192.0.2.57/24", .coreaVPN), lease("192.0.2.5/32", .coreaVPN, 20),
                     lease("198.51.100.1/32", .direct), lease("2001:db8:1234::1/64", .group("A"))]
        let plan = try SplitRoutePlanner.make(leases: rules, networkID: network, now: now)
        precondition(plan.routeCount == 3 && plan.validUntil == now.addingTimeInterval(20))
        let os = try plan.appleRoutes(networkID: network, now: now, readyPolicies: [.coreaVPN, .group("A")])
        precondition(os.includedIPv4[0].destinationAddress == "192.0.2.0" && os.includedIPv4[0].destinationSubnetMask == "255.255.255.0")
        precondition(os.excludedIPv4[0].destinationAddress == "198.51.100.1")
        precondition(os.includedIPv6[0].destinationAddress == "2001:db8:1234::" && os.includedIPv6[0].destinationNetworkPrefixLength == 64)
        let group = try plan.policy(for: "2001:db8:1234::77", networkID: network, now: now)
        let outside = try plan.policy(for: "203.0.113.1", networkID: network, now: now)
        precondition(group == .group("A") && outside == nil)
        func mustFail(_ block: () throws -> Void) {
            do { try block(); preconditionFailure("unsafe plan accepted") } catch { }
        }
        mustFail { _ = try plan.appleRoutes(networkID: network, now: now, readyPolicies: [.coreaVPN]) }
        mustFail { try plan.validate(networkID: "test/2", now: now) }
        mustFail { try plan.validate(networkID: network, now: now.addingTimeInterval(20)) }
        for bad in [lease("0.0.0.0/0", .coreaVPN), lease("::/0", .group("A")), lease("192.0.2.4/32", .direct),
                    lease("192.0.2.0/24", .group("A")), lease("198.51.100.2/32", .coreaVPN, 0), lease("203.0.113.1/32", .reject)] {
            mustFail { _ = try SplitRoutePlanner.make(leases: rules + [bad], networkID: network, now: now) }
        }
        for pair in [("0.0.0.0/1", "128.0.0.0/1"), ("::/1", "8000::/1")] {
            mustFail { _ = try SplitRoutePlanner.make(leases: [lease(pair.0, .coreaVPN), lease(pair.1, .group("A"))], networkID: network, now: now) }
        }
        func choice(_ cidr: String, _ ruleLines: [String]) throws -> RoutingPolicy {
            let d = try RoutingDocument(groups: [.init(name: "P", type: "select")],
                                        rules: ruleLines.map(RoutingRule.imported))
            return try SplitRoutePlanner.policy(forCIDR: cidr, document: d)
        }
        let subnet = "192.0.2.0/24"
        let halves = ["IP-CIDR,192.0.2.0/25,P", "IP-CIDR,192.0.2.128/25,P"]
        let same = try choice(subnet, halves + ["PROCESS-NAME,unknown,DIRECT"])
        precondition(same == .group("P"))
        mustFail { _ = try choice(subnet, ["IP-CIDR,192.0.2.254/32,DIRECT", "IP-CIDR,192.0.2.0/24,P"]) }
        mustFail { _ = try choice(subnet, ["DOMAIN,example.test,DIRECT", "IP-CIDR,192.0.2.0/24,P"]) }
        mustFail { _ = try choice(subnet, ["IP-CIDR,192.0.2.0/25,P"]) }
        mustFail { _ = try choice(subnet, ["AND,((IP-CIDR,192.0.2.252/30),(DST-PORT,443)),P", "MATCH,DIRECT"]) }
        let disjointRule = try choice(subnet, ["AND,((IP-CIDR,203.0.113.0/24),(DST-PORT,443)),P", "MATCH,DIRECT"])
        precondition(disjointRule == .direct)
        let covered = try choice("2001:db8::/64", ["IP-CIDR6,2001:db8::1/128,P", "IP-CIDR6,2001:db8::/64,P"])
        precondition(covered == .group("P"))
        mustFail { _ = try choice("2001:db8::/64", ["IP-CIDR6,2001:db8::ffff/128,P", "MATCH,DIRECT"]) }
        let firstWins = try choice(subnet, ["IP-CIDR,192.0.0.0/16,P", "DOMAIN,example.test,DIRECT", "MATCH,DIRECT"])
        precondition(firstWins == .group("P"))
        print("Split route checks passed: OS routes, region-wide priority, overlapping exits, default unions, TTL, transport and path changes.")
    }
}
