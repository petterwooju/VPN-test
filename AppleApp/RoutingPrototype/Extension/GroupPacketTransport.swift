import Darwin
import Foundation
import LocalAuthentication
import Network
import Security
#if PROXY_TRANSPORT && canImport(CoreIPSec)
import CoreIPSec
#endif

protocol ScopedPacketIO: AnyObject {
    func read(into buffer: inout [UInt8]) -> Int
    func send(_ data: Data) -> Bool
    func close()
}

struct VerifiedProxyLeaf {
    let address: String
    var payload: Data

    static func load(reference: Data, group: String, uplink: String, resolver: VPNResolver) async throws -> Self {
        let context = LAContext()
        context.interactionNotAllowed = true
        var search: [String: Any] = [
            kSecValuePersistentRef as String: reference, kSecClass as String: kSecClassGenericPassword,
            kSecReturnAttributes as String: true, kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context, kSecMatchLimit as String: kSecMatchLimitOne
        ]
        #if os(macOS)
        search[kSecUseDataProtectionKeychain as String] = true
        #endif
        var raw: CFTypeRef?
        let status = SecItemCopyMatching(search as CFDictionary, &raw)
        guard status == errSecSuccess, let item = raw as? [String: Any] else {
            throw SplitRouteError.invalid("선택한 그룹의 기기 키체인 참조를 사용할 수 없습니다 (\(status)).")
        }
        guard let marker = uplink.firstIndex(of: "#") else { throw SplitRouteError.changedNetwork }
        let iface = String(uplink[..<marker])
        guard if_nametoindex(iface) != 0 else { throw SplitRouteError.changedNetwork }
        return try await decodeItem(item, group: group, physicalInterface: iface) { host in
            let peer = try await resolver.resolveProxyEndpoint(host, network: uplink, interface: iface)
            guard SplitUplink.fingerprint(to: peer) == uplink else { throw SplitRouteError.changedNetwork }
            return peer
        }
    }

    static func decodeItem(_ item: [String: Any], group: String, physicalInterface: String? = nil,
                           resolve: (String) async throws -> String) async throws -> Self {
        guard item[kSecAttrService as String] as? String == "net.petterwooju.coreavpn.lab.proxy-leaf.v1",
              item[kSecAttrAccount as String] as? String == group,
              let leaf = item[kSecAttrLabel as String] as? String, !leaf.isEmpty,
              let value = item[kSecValueData as String] as? Data,
              let envelope = try JSONSerialization.jsonObject(with: value) as? [String: Any],
              envelope["version"] as? Int == 1, envelope["group"] as? String == group, envelope["node"] as? String == leaf,
              var config = envelope["configuration"] as? [String: Any], config["name"] as? String == leaf,
              let name = config["server"] as? String, let kind = config["type"] as? String,
              ["ss", "anytls"].contains(kind), !name.utf8.contains(0) else {
            throw SplitRouteError.invalid("선택한 그룹의 기기 키체인 노드를 확인할 수 없습니다.")
        }

        // Pin the actual transport endpoint for this generation before installing
        // routes. Passing an unresolved hostname to an engine could otherwise
        // resolve to a captured address after its first connection.
        let peer = try await resolve(name)
        guard VPNEndpoints.isPublicIPv4(peer) else { throw SplitRouteError.invalid("기존 프록시의 공인 IPv4를 확인해 주세요.") }
        if IPv4Address(name) == nil {
            if kind == "anytls", config["sni"] == nil { config["sni"] = name }
            if kind == "ss", var options = config["plugin-opts"] as? [String: Any], options["host"] == nil {
                options["host"] = name
                config["plugin-opts"] = options
            }
        }
        config["server"] = peer
        // Only the verified uplink can select the OS interface for proxy sockets.
        config["interface-name"] = physicalInterface
        return try .init(address: peer, payload: JSONSerialization.data(withJSONObject: config))
    }

}

final class GroupPacketTransport: ScopedPacketIO {
    #if PROXY_TRANSPORT && canImport(CoreIPSec)
    private let handle: UInt64
    static let available = true
    #else
    static let available = false
    #endif

    init(configuration: inout Data) throws {
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        configuration.append(0)
        defer { configuration.resetBytes(in: 0..<configuration.count) }
        handle = configuration.withUnsafeMutableBytes { CProxyCreate($0.bindMemory(to: CChar.self).baseAddress) }
        guard handle != 0 else { throw SplitRouteError.invalid("이 프록시 노드의 설정 또는 프로토콜을 사용할 수 없습니다.") }
        #else
        throw SplitRouteError.invalid("이 빌드에는 기존 프록시의 암호화 전송 모듈이 연결되어 있지 않습니다.")
        #endif
    }

    func verify() throws {
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        guard CProxyPreflight(handle, 12000) == 0 else {
            throw SplitRouteError.invalid("선택한 프록시로 암호화된 왕복 통신을 확인하지 못했습니다.")
        }
        #else
        throw SplitRouteError.invalid("기존 프록시 검증을 사용할 수 없습니다.")
        #endif
    }

    func read(into buffer: inout [UInt8]) -> Int {
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        let cap = Int32(buffer.count)
        return Int(CProxyRead(handle, &buffer, cap, 750))
        #else
        return -1
        #endif
    }

    func send(_ data: Data) -> Bool {
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        return data.withUnsafeBytes {
            CProxyWrite(handle, UnsafeMutableRawPointer(mutating: $0.baseAddress), Int32($0.count)) == Int32(data.count)
        }
        #else
        return false
        #endif
    }

    func close() {
        #if PROXY_TRANSPORT && canImport(CoreIPSec)
        CProxyClose(handle)
        #endif
    }
}
