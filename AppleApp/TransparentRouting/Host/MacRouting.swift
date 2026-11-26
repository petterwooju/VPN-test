#if os(macOS) && DIRECT_ROUTING
import Darwin
import Foundation
import NetworkExtension
import Security
import SystemExtensions

/// Credentials stay in the user's login context. Only the running provider receives them.
private struct RoutingNodes {
    private let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "net.petterwooju.coreavpn.routing.node.v1",
        kSecUseDataProtectionKeychain as String: true
    ]
    func store(_ settings: [String: Any], name: String) throws {
        let key = query.merging([kSecAttrAccount as String: name]) { _, v in v }
        let value = try JSONSerialization.data(withJSONObject: settings)
        let attrs: [String: Any] = [kSecValueData as String: value, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var code = SecItemUpdate(key as CFDictionary, attrs as CFDictionary)
        if code == errSecItemNotFound { code = SecItemAdd(key.merging(attrs) { _, v in v } as CFDictionary, nil) }
        guard code == errSecSuccess else { throw ClientIssue.message("프록시 키체인 저장 오류 (\(code))") }
    }
    func remove(_ name: String) throws {
        let key = query.merging([kSecAttrAccount as String: name]) { _, v in v }
        let code = SecItemDelete(key as CFDictionary)
        guard code == errSecSuccess || code == errSecItemNotFound else { throw ClientIssue.message("이전 노드 설정을 지울 수 없습니다 (\(code)).") }
    }
    func load(_ names: Set<String>) throws -> (refs: [String: Data], configs: [String: Data]) {
        var refs = [String: Data](), configs = [String: Data]()
        for name in names {
            var lookup = query
            lookup[kSecAttrAccount as String] = name
            lookup[kSecReturnPersistentRef as String] = true
            lookup[kSecReturnData as String] = true
            var result: CFTypeRef?
            let code = SecItemCopyMatching(lookup as CFDictionary, &result)
            if code == errSecItemNotFound { continue }
            guard code == errSecSuccess, let row = result as? [String: Any],
                  let ref = row[kSecValuePersistentRef as String] as? Data,
                  let value = row[kSecValueData as String] as? Data else { throw ClientIssue.message("프록시 키체인을 열 수 없습니다 (\(code)).") }
            refs[name] = ref; configs[name] = value
        }
        return (refs, configs)
    }
}

private final class ExtensionApproval: NSObject, OSSystemExtensionRequestDelegate {
    var result: CheckedContinuation<Void, Error>?
    var approval: (() -> Void)?
    func activate(_ id: String) async throws {
        try await withCheckedThrowingContinuation { continuation in
            self.result = continuation
            let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: id, queue: .main)
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) { approval?() }
    func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension old: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction { .replace }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult outcome: OSSystemExtensionRequest.Result) {
        if outcome == .completed { result?.resume() }
        else { result?.resume(throwing: ClientIssue.message("다음 Mac 재시동 후 확장이 활성화됩니다.")) }
        result = nil
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) { result?.resume(throwing: error); result = nil }
}

@MainActor
final class MacRouting: ObservableObject {
    static let providerID = "net.petterwooju.coreavpn.client.routing"
    @Published private(set) var status = ""
    @Published private(set) var busy = false
    @Published private(set) var enabled = false
    private var manager: NETransparentProxyManager?
    private var sentBinding: [String: AnyHashable]?
    private var sentNodes = false
    private var lastBinding = Date.distantPast
    private var invalidatedPhysical = false
    private let activation = ExtensionApproval()
    private let nodes = RoutingNodes()

    func locate() async throws {
        manager = try await NETransparentProxyManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == Self.providerID
        }
        enabled = manager?.isEnabled == true
    }
    func importLeaf(_ leaf: ImportedProxyLeaf, name: String, fingerprint: String) throws {
        let config = try leaf.configuration(verifiedName: name, trustedPin: fingerprint)
        try nodes.store(config, name: leaf.name)
    }

    func importNodes(_ catalog: ProxyLeafCatalog) throws -> (saved: Int, failures: [String]) {
        var saved = 0, failures = [String]()
        for leaf in catalog.allLeaves {
            do { try nodes.store(try leaf.configuration(), name: leaf.name); saved += 1 }
            catch {
                try nodes.remove(leaf.name)
                failures.append(leaf.name + " · " + error.localizedDescription)
            }
        }
        return (saved, failures)
    }

    private func interfaceFields(_ name: String, prefix: String) -> [String: AnyHashable]? {
        let index = if_nametoindex(name)
        var first: UnsafeMutablePointer<ifaddrs>?
        guard index > 0, getifaddrs(&first) == 0, let first else { return nil }
        defer { freeifaddrs(first) }
        for entry in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let item = entry.pointee
            guard String(cString: item.ifa_name) == name, let address = item.ifa_addr,
                  item.ifa_flags & UInt32(IFF_UP | IFF_RUNNING) == UInt32(IFF_UP | IFF_RUNNING),
                  address.pointee.sa_family == AF_INET else { continue }
            var ip = UnsafeRawPointer(address).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ip, &buffer, socklen_t(buffer.count)) != nil else { return nil }
            return [prefix + "Interface": name, prefix + "Index": Int(index), prefix + "IPv4": String(cString: buffer)]
        }
        return nil
    }

    private static let geoURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("CoreaVPN", isDirectory: true).appendingPathComponent("routing-geoip.dat")

    func importCountries(from url: URL, document: RoutingDocument) throws {
        let scope = url.startAccessingSecurityScopedResource()
        defer { if scope { url.stopAccessingSecurityScopedResource() } }
        guard let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 64 * 1024 * 1024 else {
            throw ClientIssue.message("64MB 이하의 GEOIP.dat를 선택해 주세요.")
        }
        let subset = try RoutingGeoDatabase.subset(from: Data(contentsOf: url, options: .mappedIfSafe), for: document)
        try FileManager.default.createDirectory(at: Self.geoURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try subset.write(to: Self.geoURL, options: .atomic)
    }

    func apply(document: RoutingDocument, selections: [String: String], model: SessionModel) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        do {
            let link = model.link
            guard link.available, let physical = interfaceFields(link.interface, prefix: "physical"), !document.rules.isEmpty else {
                throw ClientIssue.message("물리 회선과 가져온 규칙을 확인해 주세요.")
            }
            activation.approval = { [weak self] in self?.status = "시스템 설정에서 CoreaVPN 네트워크 확장을 허용해 주세요." }
            try await activation.activate(Self.providerID)
            try await locate()
            let manager = self.manager ?? NETransparentProxyManager()
            let existing = manager.connection.status
            guard [.invalid, .disconnected, .connected].contains(existing) else {
                throw ClientIssue.message("현재 연결 전환이 끝난 후 다시 적용해 주세요.")
            }
            let data = try nodes.load(Set(document.nodeTypes?.keys.map { $0 } ?? []))
            var peers = [String: String]()
            for (name, blob) in data.configs {
                guard let item = try JSONSerialization.jsonObject(with: blob) as? [String: Any], let server = item["server"] as? String else { continue }
                if let address = try? await model.driver.resolver.resolveProxyEndpoint(server, network: link.prefix, interface: link.interface) {
                    peers[name] = address
                }
            }
            guard model.link == link, physical == interfaceFields(link.interface, prefix: "physical") else { throw BenchmarkError.wrongNetwork }
            var config: [String: Any] = physical
            config["version"] = 1
            config["physicalPrefix"] = link.prefix
            config["rules"] = try JSONEncoder().encode(document)
            if FileManager.default.fileExists(atPath: Self.geoURL.path) { config["geoIP"] = try Data(contentsOf: Self.geoURL) }
            config["nodes"] = data.refs
            config["selections"] = selections
            config["peers"] = peers
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerID
            proto.serverAddress = "CoreaVPN Routing"
            proto.providerConfiguration = config
            manager.localizedDescription = "CoreaVPN 라우팅"
            manager.protocolConfiguration = proto
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            self.manager = manager
            enabled = manager.isEnabled
            sentBinding = nil; sentNodes = false; invalidatedPhysical = false
            guard let session = manager.connection as? NETunnelProviderSession else { throw ClientIssue.message("투명 프록시 세션을 열 수 없습니다.") }
            if session.status == .connected {
                var replacement: [String: Any] = verifiedBinding(model)
                replacement["replaceConfiguration"] = config
                replacement["nodeConfigurations"] = data.configs
                let message = try PropertyListSerialization.data(fromPropertyList: replacement, format: .binary, options: 0)
                try await withCheckedThrowingContinuation { (completion: CheckedContinuation<Void, Error>) in
                    do {
                        try session.sendProviderMessage(message) { reply in
                            if reply == Data([1]) { completion.resume() }
                            else { completion.resume(throwing: ClientIssue.message("실행 중인 확장이 변경된 규칙을 적용하지 못했습니다.")) }
                        }
                    } catch { completion.resume(throwing: error) }
                }
            } else {
                try session.startTunnel(options: ["nodeConfigurations": data.configs as NSDictionary])
            }
            status = "규칙 적용 중 · 사용 가능한 프록시 노드 \(peers.count)개"
        } catch { status = error.localizedDescription }
    }

    private func verifiedBinding(_ model: SessionModel) -> [String: AnyHashable] {
        var binding = [String: AnyHashable]()
        if let selected = model.driver.vpn.routingSession,
           let tuple = interfaceFields(selected.interface, prefix: "vpn") {
            binding = tuple
            binding["selectedServer"] = selected.host
            binding["sessionDate"] = selected.date.timeIntervalSinceReferenceDate
        }
        return binding
    }

    /// Never persist a potentially reusable kernel interface name in the VPN configuration.
    func refreshBinding(_ model: SessionModel) {
        guard let manager else { return }
        guard manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession else {
            sentBinding = nil; sentNodes = false
            return
        }
        guard !busy else { return }
        if let config = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
           let name = config["physicalInterface"] as? String,
           let prefix = config["physicalPrefix"] as? String,
           model.link.available, (model.link.interface != name || model.link.prefix != prefix) {
            if !invalidatedPhysical {
                do {
                    let message = try PropertyListSerialization.data(fromPropertyList: ["invalidatePhysical": true], format: .binary, options: 0)
                    try session.sendProviderMessage(message) { [weak self] reply in
                        if reply != Data([1]) { Task { @MainActor in self?.invalidatedPhysical = false } }
                    }
                    invalidatedPhysical = true
                } catch { status = error.localizedDescription; return }
            }
            status = "회선이 변경되었습니다. 새 회선에서 규칙을 다시 적용해 주세요."
            return
        }
        guard !invalidatedPhysical else { return }
        let binding = verifiedBinding(model)
        guard sentBinding != binding || !sentNodes || (!binding.isEmpty && Date().timeIntervalSince(lastBinding) >= 5) else { return }
        do {
            var contents: [String: Any] = binding
            if !sentNodes, let config = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
               let refs = config["nodes"] as? [String: Data] {
                contents["nodeConfigurations"] = try nodes.load(Set(refs.keys)).configs
            }
            let message = try PropertyListSerialization.data(fromPropertyList: contents, format: .binary, options: 0)
            try session.sendProviderMessage(message) { [weak self] response in
                Task { @MainActor in
                    guard let self else { return }
                    if response == nil { self.sentBinding = nil; self.sentNodes = false; self.status = "확장 설정 전달을 확인하고 있습니다." }
                }
            }
            sentBinding = binding; sentNodes = true; lastBinding = Date()
            status = "규칙 적용 중 · " + (binding["selectedServer"] as? String ?? "CoreaVPN 출구 연결 대기")
        } catch { status = error.localizedDescription }
    }

    func disable() async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        do {
            try await locate()
            guard let manager else { return }
            manager.connection.stopVPNTunnel()
            manager.isEnabled = false
            try await manager.saveToPreferences()
            enabled = false; sentNodes = false; sentBinding = nil
            status = "라우팅 규칙 적용 해제됨"
        } catch { status = error.localizedDescription }
    }
}
#endif
