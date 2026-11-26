import Foundation

@main struct ProxyLeafChecks {
    static func main() throws {
        let sample = """
        proxies:
          - {name: direct-proxy, type: ss, server: v.example, port: 443, password: 'test, secret', cipher: chacha20-ietf-poly1305, udp: true, udp-over-tcp: true, plugin: obfs, plugin-opts: {mode: tls, host: ob.example}}
          - name: node-a
            type: anytls
            port: 443
            server: proxy.test
            password: "test"
            skip-cert-verify: true
            alpn:
              - h2
        proxy-groups:
          - { name: Selected, type: select, proxies: [Other] }
          - { name: Other, type: select, proxies: [node-a, direct-proxy, Selected] }
        rules:
          - MATCH,Selected
        """
        let catalog = try ProxyLeafCatalog(text: sample)
        let members = catalog.members(of: "Selected")
        precondition(members.map(\.name) == ["node-a","direct-proxy"])
        let ss = try members[1].configuration()
        precondition(ss["port"] as? Int == 443 && ss["udp-over-tcp"] as? Bool == true)
        precondition(ss["password"] as? String == "test, secret")
        precondition((ss["plugin-opts"] as? [String: Any])?["host"] as? String == "ob.example")
        precondition((try? members[0].configuration()) == nil)
        precondition((try? members[0].configuration(trustedPin: "garbage")) == nil)
        let a = try members[0].configuration(verifiedName: "trusted.test")
        precondition(a["sni"] as? String == "trusted.test" && a["skip-cert-verify"] as? Bool == false)
        precondition(a["alpn"] as? [String] == ["h2"])
        let p = try members[0].configuration(trustedPin: String(repeating:"af",count:32))
        precondition(p["skip-cert-verify"] as? Bool == false)
        if let file = CommandLine.arguments.dropFirst().first {
            let real = try ProxyLeafCatalog(text: String(contentsOfFile: file, encoding: .utf8))
            var valid = Set<String>(), needAuth = Set<String>()
            for g in real.groups {
                for n in real.members(of:g.name) {
                    if (try? n.configuration()) != nil { valid.insert(n.name) }
                    else if n.kind == "anytls" { needAuth.insert(n.name) }
                }
            }
            print("Local profile: \(real.groups.count) groups, \(valid.count) eligible nodes, \(needAuth.count) AnyTLS nodes need verified peer configuration.")
        }
        print("Proxy leaf import checks passed.")
    }
}
