import Foundation
import NetworkExtension
import Security

@main struct ProviderInputChecks {
    static func main() async throws {
        let tag = "unit"
        func profile(_ leases: [SplitRouteLease], address: String = "9.9.9.9", host: String = "puma.coreavpn.net",
                     auth: String = "eap-cert") throws -> NETunnelProviderProtocol {
            let proto = NETunnelProviderProtocol()
            proto.enforceRoutes = true
            proto.serverAddress = address
            proto.username = "local-test"
            // Synthetic ref only; this test never opens Keychain or network.
            proto.passwordReference = Data([1])
            proto.providerConfiguration = [
                "remoteHost": host, "leases": try JSONEncoder().encode(leases), "authentication": auth,
                "networkID": tag, "uplinkFingerprint": "unit-interface"
            ]
            return proto
        }
        let sample = SplitRouteLease(label: "selected test", cidr: "192.0.2.1/32", policy: .coreaVPN, networkID: tag, expiresAt: nil)
        let included = try ScopedConfiguration(profile([sample]))
        precondition(included.plan.routeCount == 2)
        let gatewayRoute = try included.plan.policy(for: "9.9.9.9", networkID: tag)
        precondition(gatewayRoute == .direct)
        func refuse(_ make: () throws -> NETunnelProviderProtocol) {
            do { _ = try ScopedConfiguration(make()); preconditionFailure("invalid profile accepted") } catch { }
        }
        refuse { try profile([]) }
        refuse { try profile([sample], host: "other.invalid") }
        refuse { try profile([sample], address: "127.0.0.1") }
        refuse { try profile([sample], auth: "psk-eap") }
        let group = SplitRouteLease(label: "unavailable", cidr: "198.51.100.2/32", policy: .group("demo"), networkID: tag, expiresAt: nil)
        refuse { try profile([sample, group]) }
        let overlaps = SplitRouteLease(label: "loop", cidr: "9.9.9.9/32", policy: .coreaVPN, networkID: tag, expiresAt: nil)
        refuse { try profile([overlaps]) }
        let broad = SplitRouteLease(label: "broad", cidr: "192.0.2.0/24", policy: .coreaVPN, networkID: tag, expiresAt: nil)
        let subnetPlan = try ScopedConfiguration(profile([broad])).plan
        let lastHost = try subnetPlan.policy(for: "192.0.2.255", networkID: tag)
        precondition(lastHost == .coreaVPN)
        refuse { let bad = try profile([sample]); bad.enforceRoutes = false; return bad }
        var packet = [UInt8](repeating: 0, count: 20)
        packet[0] = 0x45; packet[3] = 20; packet.replaceSubrange(16..<20, with: [192, 0, 2, 15])
        precondition(PacketEnvelope(Data(packet))?.address == "192.0.2.15")
        packet[0] = 0x4f
        precondition(PacketEnvelope(Data(packet)) == nil)
        var ipv6 = [UInt8](repeating: 0, count: 40)
        ipv6[0] = 0x60; ipv6[39] = 1
        precondition(PacketEnvelope(Data(ipv6))?.address == "::1")
        ipv6[5] = 1
        precondition(PacketEnvelope(Data(ipv6)) == nil)

        func proxyItem(type: String, obfsHost: String? = nil) throws -> [String: Any] {
            var config: [String: Any] = ["name": "local-leaf", "server": "proxy.example.test", "type": type,
                                         "port": 443, "plugin-opts": ["mode": "tls"]]
            if let obfsHost { config["plugin-opts"] = ["mode": "tls", "host": obfsHost] }
            let envelope: [String: Any] = ["version": 1, "group": "test-group", "node": "local-leaf", "configuration": config]
            return [kSecAttrService as String: "net.petterwooju.coreavpn.lab.proxy-leaf.v1",
                    kSecAttrLabel as String: "local-leaf", kSecAttrAccount as String: "test-group",
                    kSecValueData as String: try JSONSerialization.data(withJSONObject: envelope)]
        }
        for type in ["anytls", "ss"] {
            let item = try proxyItem(type: type)
            let info = try await VerifiedProxyLeaf.decodeItem(item, group: "test-group") { _ in "9.9.9.9" }
            let leaf = try JSONSerialization.jsonObject(with: info.payload) as! [String: Any]
            precondition(leaf["server"] as? String == "9.9.9.9")
            let identity = type == "anytls" ? leaf["sni"] as? String : (leaf["plugin-opts"] as? [String: Any])?["host"] as? String
            precondition(identity == "proxy.example.test")
            do { _ = try await VerifiedProxyLeaf.decodeItem(item, group: "other") { _ in "9.9.9.9" }; preconditionFailure() }
            catch is SplitRouteError { }
            do { _ = try await VerifiedProxyLeaf.decodeItem(item, group: "test-group") { _ in "127.0.0.1" }; preconditionFailure() }
            catch is SplitRouteError { }
            do { _ = try await VerifiedProxyLeaf.decodeItem(item, group: "test-group") { _ in "198.18.0.1" }; preconditionFailure() }
            catch is SplitRouteError { }
        }
        let custom = "handshake.example.test:opaque"
        let overridden = try await VerifiedProxyLeaf.decodeItem(proxyItem(type: "ss", obfsHost: custom),
                                                                group: "test-group", physicalInterface: "en6") { host in
            precondition(host == "proxy.example.test")
            return "9.9.9.9"
        }
        let pinned = try JSONSerialization.jsonObject(with: overridden.payload) as! [String: Any]
        precondition((pinned["plugin-opts"] as? [String: String])?["host"] == custom && pinned["interface-name"] as? String == "en6")
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        // CProxyCreate only initializes a leaf. Never preflight this fixture or
        // contact an external host; neither direction may carry packets yet.
        let fake: [String: Any] = ["name": "fixture", "type": "ss", "server": "9.9.9.9",
                                   "port": 443, "cipher": "aes-128-gcm", "password": "local-fixture"]
        var config = try JSONSerialization.data(withJSONObject: fake)
        let transport = try GroupPacketTransport(configuration: &config)
        precondition(!transport.send(Data(packet)))
        var buffer = [UInt8](repeating: 0, count: 2048)
        precondition(transport.read(into: &buffer) < 0)
        transport.close()
        transport.close()
        #endif
        print("Prototype profile, gateway loop, scoped proxy identity and packet-envelope checks passed.")
    }
}
