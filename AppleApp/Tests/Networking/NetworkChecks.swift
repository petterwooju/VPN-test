import Foundation
import NetworkExtension
#if os(macOS)
import CoreaSpeed
#endif

@main struct NetworkChecks {
    static func main() throws {
        let host = "puma.coreavpn.net", id: UInt16 = 0x1234
        func mustReject(_ fn: () throws -> Void) {
            do { try fn(); preconditionFailure("unexpected success") } catch {}
        }
        let query = EndpointDNS.query(host, id: id)
        func dns(_ records: [UInt8], count: UInt8 = 1) -> Data {
            var r = Array(query)
            r[2] = 0x81; r[3] = 0x80; r[7] = count
            return Data(r + records)
        }
        let a: [UInt8] = [0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]
        let answer = try EndpointDNS.answer(dns(a), for: host, id: id)
        precondition(answer.address == "1.2.3.4" && answer.ttl == 60)
        let cname: [UInt8] = [0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 5, 0, 3, 1, 120, 0]
        let aliasA = [UInt8(1), 120, 0] + a.dropFirst(2)
        let chained = try EndpointDNS.answer(dns(cname + aliasA, count: 2), for: host, id: id)
        precondition(chained.ttl == 5 && chained.address == "1.2.3.4")
        mustReject { _ = try EndpointDNS.answer(dns(a), for: host, id: id+1) }
        mustReject { _ = try EndpointDNS.answer(dns(a), for: "other.coreavpn.net", id: id) }
        mustReject { _ = try EndpointDNS.answer(dns(aliasA), for: host, id: id) }
        mustReject { _ = try EndpointDNS.answer(dns(Array(a.dropLast())), for: host, id: id) }
        let privateA = a.dropLast(4) + [192, 168, 0, 2]
        mustReject { _ = try EndpointDNS.answer(dns(Array(privateA)), for: host, id: id) }
        precondition(!VPNEndpoints.isPublicIPv4("198.18.0.1"))
        precondition(!VPNEndpoints.isPublicIPv4("100.64.0.1"))
        precondition(VPNEndpoints.net.count == 17 && VPNEndpoints.all.count == 23)
        precondition(!VPNEndpoints.all.contains("x.coreavpn.net"))

        let token: [UInt8] = [12, 123], echo: [UInt8] = [0, 0, 0, 0, 42, 10, 0, 3] + token
        precondition(TunnelProbe.matchesEcho(echo[...], sequence: 3, token: token))
        precondition(!TunnelProbe.matchesEcho(echo[...], sequence: 4, token: token))
        precondition(!TunnelProbe.matchesEcho(echo[...], sequence: 3, token: [9, 9]))
        var hdr = [UInt8](repeating: 0, count: 20); hdr[0] = 0x45; hdr[9] = 1
        precondition(TunnelProbe.matchesEcho((hdr + echo)[...], sequence: 3, token: token))
        hdr[9] = 17
        precondition(!TunnelProbe.matchesEcho((hdr + echo)[...], sequence: 3, token: token))
        precondition(TunnelProbe.isTunnel("ipsec0") && TunnelProbe.isTunnel("utun1"))
        precondition(!TunnelProbe.isTunnel("en6") && !TunnelProbe.isTunnel("ipsec"))

        #if os(macOS)
        let laneBytes = 4 * 1024 * 1024
        precondition(NativeSpeedProbe.completedDownloadBytes(laneBytes * 4, lanes: 4) == laneBytes * 4)
        precondition(NativeSpeedProbe.completedDownloadBytes(laneBytes, lanes: 4) == nil)
        precondition(NativeSpeedProbe.completedDownloadBytes(laneBytes * 4 - 1, lanes: 4) == nil)
        // Exercise the transport parser and vanished-interface guard without sending traffic.
        precondition(csOpen("unavailable42", 0, "1.1.1.1", { _ in 0 }, nil) == nil)
        for (encoding, shouldReject) in [("identity", false), ("gzip", true), ("identity-other", true)] {
            var lane = CSLane()
            var bytes = Array("Content-Encoding: \(encoding)\r\n".utf8CString)
            let length = bytes.count - 1
            _ = csHeader(&bytes, 1, length, &lane)
            precondition((lane.badEncoding != 0) == shouldReject)
        }
        #endif

        func plist(_ ike: [String: Any], format: PropertyListSerialization.PropertyListFormat = .xml) throws -> Data {
            let payload: [String: Any] = ["PayloadType": "com.apple.vpn.managed", "VPNType": "IKEv2", "IKEv2": ike]
            let profile: [String: Any] = ["PayloadType": "Configuration", "PayloadContent": [payload]]
            return try PropertyListSerialization.data(fromPropertyList: profile, format: format, options: 0)
        }
        var ike: [String: Any] = ["RemoteAddress": host, "RemoteIdentifier": host, "LocalIdentifier": "fixture",
                                   "AuthenticationMethod": "SharedSecret", "SharedSecret": Data([0, 12, 255]),
                                   "IKESecurityAssociationParameters": ["EncryptionAlgorithm": "AES-256", "DiffieHellmanGroup": 19]]
        for format in [PropertyListSerialization.PropertyListFormat.xml, .binary] {
            let profile = try OfficialIKEProfile.parse(plist(ike, format: format))
            let proto = NEVPNProtocolIKEv2()
            profile.apply(to: proto)
            precondition(profile.host == host && profile.psk == Data([0, 12, 255]))
            precondition(!proto.useExtendedAuthentication && proto.localIdentifier == "fixture")
            precondition(proto.ikeSecurityAssociationParameters.diffieHellmanGroup.rawValue == 19)
        }
        ike.removeValue(forKey: "SharedSecret")
        mustReject { _ = try OfficialIKEProfile.parse(plist(ike)) }
        ike["AuthenticationMethod"] = "None"; ike["ExtendedAuthEnabled"] = 1
        let eap = try OfficialIKEProfile.parse(plist(ike))
        precondition(eap.extended && eap.psk == nil)
        ike["RemoteAddress"] = "not.coreavpn.net"
        mustReject { _ = try OfficialIKEProfile.parse(plist(ike)) }
        ike["RemoteAddress"] = host; ike["RemoteIdentifier"] = "other.example"
        mustReject { _ = try OfficialIKEProfile.parse(plist(ike)) }
        ike["RemoteIdentifier"] = host; ike["PayloadCertificateUUID"] = "unused"
        mustReject { _ = try OfficialIKEProfile.parse(plist(ike)) }
        mustReject { _ = try OfficialIKEProfile.parse(Data([0x30, 0x82, 1, 0])) }
        print("Network checks passed: DNS records, endpoint allowlist, echo replies, IKEv2 profile authentication.")
    }
}
