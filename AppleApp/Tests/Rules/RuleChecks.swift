import Foundation

@main struct RuleChecks {
    static func main() throws {
        let source = """
        proxies:
          - { name: node1, type: ss, password: secret-not-exported }
        proxy-providers:
          feed: { url: "https://example.invalid/token-not-exported" }
        proxy-groups:
          - name: "User # Group"
            type: select
            proxies:
              - DIRECT
              - node1
            use:
              - feed
          - { name: Alternate, type: select, proxies: [DIRECT, 'User # Group'] }
        rules:
          - "AND,((NETWORK,UDP),(DST-PORT,3478-3479/5350)),REJECT"
          - 'DOMAIN-SUFFIX,sample.test,User # Group' # keep group
          - PROCESS-NAME,App,DIRECT
          - IP-CIDR,198.51.100.0/24,Alternate,no-resolve
          - IP-CIDR6,2001:db8::/63,DIRECT
          - MATCH,Alternate
        """
        let doc = try ClashRuleImport.parse(source)
        precondition(doc.rules.count == 6)
        precondition(doc.groups.map(\.name) == ["User # Group", "Alternate"])
        precondition(doc.groups[0].members == ["DIRECT", "node1"])
        precondition(doc.groups[0].providers == ["feed"])
        precondition(doc.groups[1].members == ["DIRECT", "User # Group"])
        precondition(doc.nodeTypes == ["node1": "ss"])
        let encoded = try JSONEncoder().encode(doc)
        let output = String(decoding: encoded, as: UTF8.self)
        precondition(!output.contains("secret-not-exported") && !output.contains("token-not-exported"))
        let read = try RoutingDocument.decode(encoded)
        precondition(read.rules == doc.rules && read.groups == doc.groups)
        var q = RouteQuery()
        q.domain = "CHILD.sample.TEST."
        q.port = 443
        q.transport = "TCP"
        let exact = doc.preview(q, supportsProcess: false)
        precondition(exact.match?.policy == .group("User # Group") && exact.undecided.isEmpty)
        q.transport = "UDP"; q.port = 3478
        precondition(doc.preview(q).match?.policy == .reject)
        q.transport = "TCP"; q.port = 443; q.domain = "notasample.test"; q.ip = "198.51.100.9"
        let unknown = doc.preview(q, supportsProcess: false)
        precondition(unknown.match?.policy == .group("Alternate") && unknown.undecided.map(\.kind) == ["PROCESS-NAME"])
        q.processName = "Other"
        precondition(doc.preview(q, supportsProcess: true).undecided.isEmpty)
        q.processName = "App"
        precondition(doc.preview(q, supportsProcess: true).match?.kind == "PROCESS-NAME")
        precondition(RoutingCIDR("2001:db8::/63")?.contains("2001:db8:0:1::1") == true)
        precondition(RoutingCIDR("2001:db8::/63")?.contains("2001:db8:0:2::1") == false)
        precondition(RoutingCIDR("0.0.0.0/0")?.contains("203.0.113.2") == true)
        precondition(RoutingCIDR("198.51.100.0/32")?.contains("198.51.100.1") == false)
        precondition(RoutingCIDR("junk/12") == nil)
        let malformed = "rules:\n  - *external\n"
        do { _ = try ClashRuleImport.parse(malformed); preconditionFailure("YAML alias accepted") }
        catch is RuleProblem { }
        let unrecognized = try RoutingRule.imported("RULE-SET,stream,G")
        precondition(unrecognized.original == "RULE-SET,stream,G")
        precondition(unrecognized.compare(q, supportsProcess: true) == .unknown)
        var changed = doc
        changed.rules[1].policy = .coreaVPN
        q.domain = "x.sample.test"
        precondition(changed.preview(q).match?.policy == .coreaVPN)
        if CommandLine.arguments.count == 2 {
            let file = URL(fileURLWithPath: CommandLine.arguments[1])
            let active = try ClashRuleImport.parse(String(contentsOf: file, encoding: .utf8))
            let destinations = Set(active.rules.map(\.policy))
            let known = active.knownTargets
            let count = active.rules.filter { $0.issue(groups: known, supportsProcess: true) != nil }.count
            print("Imported \(active.rules.count) active rules, \(active.groups.count) defined groups, \(destinations.count) distinct targets; \(active.nodeTypes?.count ?? 0) node references; \(count) unresolved rows on Mac.")
        }
        print("Rule import, preview and archive checks passed.")
    }
}
