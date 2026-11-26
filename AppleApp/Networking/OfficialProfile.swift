import Foundation
import NetworkExtension

/// Imported authentication settings only. The app owns routing and On Demand.
struct OfficialIKEProfile: Codable {
    var version = UUID()
    let host: String
    let localID: String?
    let login: String?
    let extended: Bool
    let psk: Data?
    let password: Data?
    let dpd: String?
    let pfs: Bool?
    let disableMobike: Bool?
    let disableRedirect: Bool?
    let revocation: Bool?
    let issuer: String?
    let ikeSA: Association?
    let childSA: Association?

    private static let invalid = VPNNetworkError.message("지원되는 단일 CoreaVPN IKEv2 인증 프로필이 아닙니다.")

    struct Association: Codable {
        let encryption: Int?
        let integrity: Int?
        let dh: Int?
        let lifetimeMinutes: Int?

        init(_ input: [String: Any]) throws {
            let keys: Set<String> = ["EncryptionAlgorithm", "IntegrityAlgorithm", "DiffieHellmanGroup", "LifeTimeInMinutes"]
            guard Set(input.keys).isSubset(of: keys) else { throw invalid }
            let encryptions = ["AES-128": 3, "AES-256": 4, "AES-128-GCM": 5, "AES-256-GCM": 6, "ChaCha20Poly1305": 7]
            let hashes = ["SHA2-256": 3, "SHA2-384": 4, "SHA2-512": 5]
            func algorithm(_ key: String, _ dictionary: [String: Int]) throws -> Int? {
                guard let value = input[key] else { return nil }
                guard let name = value as? String, let translated = dictionary[name] else {
                    throw VPNNetworkError.message("프로필에 이 앱이 처리할 수 없는 IKEv2 알고리즘이 있습니다.")
                }
                return translated
            }
            encryption = try algorithm("EncryptionAlgorithm", encryptions)
            integrity = try algorithm("IntegrityAlgorithm", hashes)
            dh = try OfficialIKEProfile.integer(input["DiffieHellmanGroup"])
            if let dh, ![14, 15, 16, 17, 18, 19, 20, 21, 31].contains(dh) { throw invalid }
            lifetimeMinutes = try OfficialIKEProfile.integer(input["LifeTimeInMinutes"])
            if let minutes = lifetimeMinutes, !(10...1440).contains(minutes) { throw invalid }
        }
        func apply(to target: NEVPNIKEv2SecurityAssociationParameters) {
            if let encryption, let value = NEVPNIKEv2EncryptionAlgorithm(rawValue: encryption) { target.encryptionAlgorithm = value }
            if let integrity, let value = NEVPNIKEv2IntegrityAlgorithm(rawValue: integrity) { target.integrityAlgorithm = value }
            if let dh, let value = NEVPNIKEv2DiffieHellmanGroup(rawValue: dh) { target.diffieHellmanGroup = value }
            if let lifetimeMinutes { target.lifetimeMinutes = Int32(lifetimeMinutes) }
        }
    }

    private static func integer(_ value: Any?) throws -> Int? {
        guard let value else { return nil }
        guard let number = value as? NSNumber, number.doubleValue == Double(number.intValue) else { throw invalid }
        return number.intValue
    }
    static func parse(_ data: Data) throws -> Self {
        guard !data.isEmpty, data.count <= 1024 * 1024 else { throw invalid }
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let root = try? PropertyListSerialization.propertyList(from: data, options: [], format: &format) as? [String: Any],
              [.xml, .binary].contains(format) else {
            throw VPNNetworkError.message("XML 또는 바이너리 plist 프로필을 선택하십시오. 서명·암호화된 CMS는 가져올 수 없습니다.")
        }
        guard root["PayloadType"] as? String == "Configuration", let contents = root["PayloadContent"] as? [[String: Any]],
              contents.count == 1, let payload = contents.first, payload["PayloadType"] as? String == "com.apple.vpn.managed",
              payload["VPNType"] as? String == "IKEv2", let ike = payload["IKEv2"] as? [String: Any] else { throw invalid }
        let supported: Set<String> = ["RemoteAddress", "RemoteIdentifier", "LocalIdentifier", "AuthenticationMethod",
            "ExtendedAuthEnabled", "AuthName", "AuthPassword", "SharedSecret", "EnablePFS", "DisableMOBIKE",
            "DisableRedirect", "EnableCertificateRevocationCheck", "DeadPeerDetectionRate", "ServerCertificateIssuerCommonName",
            "IKESecurityAssociationParameters", "ChildSecurityAssociationParameters", "OnDemandEnabled", "OnDemandRules",
            "ServerCertificateCommonName"]
        guard Set(ike.keys).isSubset(of: supported) else {
            throw VPNNetworkError.message("이 프로필에는 앱이 보존할 수 없는 추가 IKEv2 설정이 있습니다.")
        }
        func string(_ key: String) throws -> String? {
            guard let value = ike[key] else { return nil }
            guard let s = value as? String, s.utf8.count <= 8192 else { throw invalid }
            return s.isEmpty ? nil : s
        }
        func flag(_ key: String) throws -> Bool? {
            guard let n = try integer(ike[key]) else { return nil }
            guard n == 0 || n == 1 else { throw invalid }
            return n == 1
        }
        func secret(_ key: String) throws -> Data? {
            guard let value = ike[key] else { return nil }
            if let b = value as? Data, !b.isEmpty, b.count <= 8192 { return b }
            return try string(key).map { Data($0.utf8) }
        }
        func association(_ key: String) throws -> Association? {
            guard let value = ike[key] else { return nil }
            guard let dictionary = value as? [String: Any] else { throw invalid }
            return try Association(dictionary)
        }
        guard let host = try string("RemoteAddress")?.lowercased(), VPNEndpoints.all.contains(host),
              try string("RemoteIdentifier")?.lowercased() == host else { throw invalid }
        // A distinct certificate name could weaken endpoint identity binding.
        if let common = try string("ServerCertificateCommonName"), common.lowercased() != host { throw invalid }
        let method = try string("AuthenticationMethod"), extended = try flag("ExtendedAuthEnabled") ?? false
        let psk = try secret("SharedSecret")
        switch method {
        case "None" where extended && psk == nil: break
        case "SharedSecret" where psk != nil: break
        default: throw VPNNetworkError.message("EAP 또는 공유 암호 IKEv2 프로필이 필요합니다.")
        }
        let dpd = try string("DeadPeerDetectionRate")
        if let dpd, !["None", "Low", "Medium", "High"].contains(dpd) { throw invalid }
        return try Self(host: host, localID: string("LocalIdentifier"), login: string("AuthName"), extended: extended,
                        psk: psk, password: secret("AuthPassword"), dpd: dpd, pfs: flag("EnablePFS"),
                        disableMobike: flag("DisableMOBIKE"), disableRedirect: flag("DisableRedirect"),
                        revocation: flag("EnableCertificateRevocationCheck"), issuer: string("ServerCertificateIssuerCommonName"),
                        ikeSA: association("IKESecurityAssociationParameters"), childSA: association("ChildSecurityAssociationParameters"))
    }

    func apply(to target: NEVPNProtocolIKEv2) {
        target.localIdentifier = localID
        target.useExtendedAuthentication = extended
        if let pfs { target.enablePFS = pfs }
        if let disableMobike { target.disableMOBIKE = disableMobike }
        if let disableRedirect { target.disableRedirect = disableRedirect }
        if let revocation { target.enableRevocationCheck = revocation }
        target.serverCertificateIssuerCommonName = issuer
        switch dpd {
        case "None": target.deadPeerDetectionRate = .none
        case "Low": target.deadPeerDetectionRate = .low
        case "Medium": target.deadPeerDetectionRate = .medium
        case "High": target.deadPeerDetectionRate = .high
        default: break
        }
        ikeSA?.apply(to: target.ikeSecurityAssociationParameters)
        childSA?.apply(to: target.childSecurityAssociationParameters)
    }
}
