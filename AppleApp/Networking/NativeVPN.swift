import Foundation
import NetworkExtension
import Security
#if os(macOS)
import SystemConfiguration
#endif

struct VPNBaseline: Codable, Equatable {
    let host: String?
    let address: String?
    let connected: Bool
    let onDemand: Bool
    let usesSharedSecret: Bool
    let enabled: Bool
}

private enum VPNKeychain {
    private static let service = (Bundle.main.bundleIdentifier ?? "CoreaVPN") + ".IKEv2"
    private static let passwordSlot = "ike.password"
    private static let sharedSlot = "ike.psk"
    private static let usernameSlot = "ike.username"

    private static func query(_ slot: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service, kSecAttrAccount as String: slot]
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }

    private static func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            throw VPNNetworkError.message("VPN 키체인 접근 실패 (\(status)).")
        }
    }

    private static func put(_ data: Data, at slot: String) throws {
        let key = query(slot)
        let change: [String: Any] = [kSecValueData as String: data,
                                     kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let status = SecItemUpdate(key as CFDictionary, change as CFDictionary)
        if status == errSecItemNotFound {
            try check(SecItemAdd(key.merging(change) { _, new in new } as CFDictionary, nil))
        } else { try check(status) }
    }

    private static func value(_ slot: String, key: CFString) throws -> Data? {
        var q = query(slot)
        q[key as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = value as? Data else { throw VPNNetworkError.message("키체인 항목 형식을 확인하십시오.") }
        return data
    }

    static func save(username: String, password: String, sharedSecret: String?) throws {
        guard !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, !password.isEmpty else {
            throw VPNNetworkError.message("CoreaVPN 사용자 이름과 암호를 입력하십시오.")
        }
        // Keep secrets scoped to the exact account so a partial update or account switch
        // never pairs one account's identity with another account's password.
        try put(Data(password.utf8), at: passwordSlot + "." + username)
        if let secret = sharedSecret {
            if secret.isEmpty {
                let status = SecItemDelete(query(sharedSlot + "." + username) as CFDictionary)
                if status != errSecItemNotFound { try check(status) }
            } else { try put(Data(secret.utf8), at: sharedSlot + "." + username) }
        }
        try put(Data(username.utf8), at: usernameSlot)
    }

    static func username() throws -> String? {
        try value(usernameSlot, key: kSecReturnData).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func reference(username: String, shared: Bool) throws -> Data? {
        try value((shared ? sharedSlot : passwordSlot) + "." + username, key: kSecReturnPersistentRef)
    }

    static func hostSecret(_ host: String, user: String) throws -> Data? {
        try value(sharedSlot + "." + user + ":" + host, key: kSecReturnPersistentRef)
    }

    static func setHostSecret(_ host: String, user: String, secret: String) throws {
        let slot = sharedSlot + "." + user + ":" + host
        if secret.isEmpty {
            let status = SecItemDelete(query(slot) as CFDictionary)
            if status != errSecItemNotFound { try check(status) }
        } else { try put(Data(secret.utf8), at: slot) }
    }

    static func storeOfficial(_ profile: OfficialIKEProfile, user: String) throws {
        try put(try JSONEncoder().encode(profile), at: "ike.profile." + user + ":" + profile.host)
    }

    static func official(_ host: String, user: String) throws -> OfficialIKEProfile? {
        guard let data = try value("ike.profile." + user + ":" + host, key: kSecReturnData) else { return nil }
        return try JSONDecoder().decode(OfficialIKEProfile.self, from: data)
    }

    static func importedReference(_ data: Data, version: UUID, shared: Bool) throws -> Data {
        // Keep the reference of a still-installed profile valid if another import rotates a credential.
        let slot = "ike.import." + (shared ? "psk." : "password.") + version.uuidString
        if let ref = try value(slot, key: kSecReturnPersistentRef) { return ref }
        try put(data, at: slot)
        guard let ref = try value(slot, key: kSecReturnPersistentRef) else {
            throw VPNNetworkError.message("프로필 키체인 참조를 생성하지 못했습니다.")
        }
        return ref
    }
}

/// The app coordinator serializes configuration changes and awaits cancellation cleanup.
/// Only the configuration owned by this app is visible through the shared Personal VPN manager.
@MainActor final class NativeVPN {
    private let manager = NEVPNManager.shared()
    private var verifiedSession: (host: String, date: Date, interface: String)?
    private var profile: NEVPNProtocolIKEv2? { manager.protocolConfiguration as? NEVPNProtocolIKEv2 }
    var connectedHost: String? { manager.connection.status == .connected ? profile?.remoteIdentifier : nil }
    var currentStatus: NEVPNStatus { manager.connection.status }

    #if DIRECT_ROUTING && os(macOS)
    var routingSession: (host: String, date: Date, interface: String)? {
        guard manager.isOnDemandEnabled, let host = connectedHost, VPNEndpoints.all.contains(host),
              let date = manager.connection.connectedDate, let route = try? TunnelProbe.routeInterface(),
              route.hasPrefix("ipsec") else { return nil }
        if let verifiedSession, verifiedSession.host == host, verifiedSession.date == date, verifiedSession.interface == route {
            return verifiedSession
        }
        guard let saved = UserDefaults.standard.dictionary(forKey: "routing.verifiedIKEv2"),
              saved["host"] as? String == host, saved["date"] as? Date == date,
              saved["interface"] as? String == route else { return nil }
        return (host, date, route)
    }
    #endif

    func saveCredentials(username: String, password: String, sharedSecret: String? = nil) throws {
        try VPNKeychain.save(username: username, password: password, sharedSecret: sharedSecret)
        verifiedSession = nil
    }
    func configuredCredentialUsername() throws -> String? { try VPNKeychain.username() }
    func credentialHandle() throws -> (username: String, reference: Data) {
        guard let user = try VPNKeychain.username(),
              let ref = try VPNKeychain.reference(username: user, shared: false) else {
            throw VPNNetworkError.message("먼저 CoreaVPN 계정을 키체인에 저장하십시오.")
        }
        return (user, ref)
    }
    func hasSharedSecret() throws -> Bool {
        guard let user = try VPNKeychain.username() else { return false }
        return try VPNKeychain.reference(username: user, shared: true) != nil
    }

    func hasSharedSecret(for host: String) throws -> Bool {
        guard VPNEndpoints.all.contains(host), let user = try VPNKeychain.username() else { return false }
        return try VPNKeychain.hostSecret(host, user: user) != nil || hasSharedSecret()
    }

    func setSharedSecret(for host: String, secret: String) throws {
        guard VPNEndpoints.all.contains(host), let user = try VPNKeychain.username() else {
            throw VPNNetworkError.message("계정을 저장하고 CoreaVPN 서버를 선택하십시오.")
        }
        try VPNKeychain.setHostSecret(host, user: user, secret: secret)
        if verifiedSession?.host == host { verifiedSession = nil }
    }

    func importOfficialProfile(_ data: Data) throws -> String {
        let imported = try OfficialIKEProfile.parse(data)
        guard let user = try VPNKeychain.username() else {
            throw VPNNetworkError.message("먼저 CoreaVPN 계정을 저장하십시오.")
        }
        if let login = imported.login, login != user {
            throw VPNNetworkError.message("이 프로필은 현재 저장한 계정용이 아닙니다.")
        }
        try VPNKeychain.storeOfficial(imported, user: user)
        if verifiedSession?.host == imported.host { verifiedSession = nil }
        return imported.host
    }

    func hasOfficialProfile(for host: String) throws -> Bool {
        guard VPNEndpoints.all.contains(host), let user = try VPNKeychain.username() else { return false }
        return try VPNKeychain.official(host, user: user) != nil
    }

    /// Request the first system authorization while the network is still available.
    /// Enabling another Personal VPN can deactivate the user's enabled Personal VPN.
    func authorize(host: String) async throws {
        try await manager.loadFromPreferences()
        guard manager.protocolConfiguration == nil else { return }
        manager.protocolConfiguration = try build(host: host, address: host, shared: false)
        manager.localizedDescription = "CoreaVPN"
        manager.isEnabled = false
        manager.isOnDemandEnabled = false
        try await save()
    }

    func snapshot() async throws -> VPNBaseline {
        try await manager.loadFromPreferences()
        let status = manager.connection.status
        guard [.invalid, .disconnected, .connected].contains(status) else {
            throw VPNNetworkError.message("VPN 상태가 변경 중입니다. 전환이 끝난 뒤 다시 시도하십시오.")
        }
        return VPNBaseline(host: profile?.remoteIdentifier, address: profile?.serverAddress,
                           connected: status == .connected, onDemand: manager.isOnDemandEnabled,
                           usesSharedSecret: profile?.authenticationMethod == .sharedSecret, enabled: manager.isEnabled)
    }

    func checkExclusiveRoute() throws {
        #if os(macOS)
        if let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] {
            let keys = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable", "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"]
            if keys.contains(where: { (proxies[$0] as? NSNumber)?.boolValue == true }) {
                throw VPNNetworkError.message("시스템 프록시가 사용 중입니다. FlClash 복구가 준비된 로컬 절차에서 전환하십시오.")
            }
        }
        #endif
        let current = try TunnelProbe.routeInterface()
        #if os(macOS)
        if TunnelProbe.isTunnel(current), !current.hasPrefix("ipsec") {
            throw VPNNetworkError.message("다른 VPN이 측정 경로를 사용 중입니다. FlClash를 사용한다면 자동 복구가 있는 검사 앱을 여세요.")
        }
        #endif
        guard !TunnelProbe.isTunnel(current) || (connectedHost != nil && manager.connection.status == .connected) else {
            throw VPNNetworkError.message("다른 VPN이 측정 경로를 사용 중입니다. 현재 VPN을 그대로 유지했습니다.")
        }
    }

    private func save() async throws {
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
    }

    private func waitStopped() async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 12
        while ![.disconnected, .invalid].contains(manager.connection.status) {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw VPNNetworkError.message("이전 CoreaVPN 연결 종료를 확인하지 못했습니다.")
            }
            try await Task.sleep(nanoseconds: 150_000_000)
        }
    }

    func disconnect() async throws {
        try await manager.loadFromPreferences()
        guard manager.protocolConfiguration != nil else { return }
        let previousInterface = verifiedSession?.interface
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            try await save()
        }
        if ![.disconnected, .invalid].contains(manager.connection.status) {
            manager.connection.stopVPNTunnel()
            try await waitStopped()
        }
        verifiedSession = nil
        // Do not start the next candidate while the system still routes via the old IKEv2 session.
        if let previousInterface {
            let deadline = ProcessInfo.processInfo.systemUptime + 4
            while (try? TunnelProbe.routeInterface()) == previousInterface {
                guard ProcessInfo.processInfo.systemUptime < deadline else {
                    throw VPNNetworkError.message("이전 IKEv2 터널 경로가 해제되지 않았습니다.")
                }
                try await Task.sleep(nanoseconds: 120_000_000)
            }
        }
    }

    private func build(host: String, address: String, shared: Bool) throws -> NEVPNProtocolIKEv2 {
        guard VPNEndpoints.all.contains(host), address == host || VPNEndpoints.isPublicIPv4(address) else {
            throw VPNNetworkError.message("CoreaVPN 서버 주소를 확인하십시오.")
        }
        guard let user = try VPNKeychain.username(),
              let password = try VPNKeychain.reference(username: user, shared: false) else {
            throw VPNNetworkError.message("먼저 CoreaVPN 계정을 키체인에 저장하십시오.")
        }
        let session = NEVPNProtocolIKEv2()
        session.serverAddress = address
        session.remoteIdentifier = host
        session.deadPeerDetectionRate = .medium
        session.disconnectOnSleep = false
        let imported = try VPNKeychain.official(host, user: user)
        let usesSecret = imported.map { $0.psk != nil } ?? shared
        session.authenticationMethod = usesSecret ? .sharedSecret : .none
        session.useExtendedAuthentication = imported?.extended ?? true
        if session.useExtendedAuthentication {
            session.username = imported?.login ?? user
            if let imported, let supplied = imported.password {
                session.passwordReference = try VPNKeychain.importedReference(supplied, version: imported.version, shared: false)
            } else { session.passwordReference = password }
        }
        if let imported, let supplied = imported.psk {
            session.sharedSecretReference = try VPNKeychain.importedReference(supplied, version: imported.version, shared: true)
        } else if usesSecret {
            guard let ref = try VPNKeychain.hostSecret(host, user: user) ?? VPNKeychain.reference(username: user, shared: true) else {
                throw VPNNetworkError.message("이 서버용 CoreaVPN 공식 공유 암호가 필요합니다.")
            }
            session.sharedSecretReference = ref
        }
        imported?.apply(to: session)
        return session
    }

    private func setOnDemand(_ value: Bool) async throws {
        if value {
            manager.onDemandRules = [NEOnDemandRuleConnect()]
        }
        manager.isOnDemandEnabled = value
        try await save()
    }

    private func waitConnected(host: String) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 28
        let start = ProcessInfo.processInfo.systemUptime
        var wasStarting = false
        while ProcessInfo.processInfo.systemUptime < deadline {
            try Task.checkCancellation()
            let status = manager.connection.status
            if status == .connected, let date = manager.connection.connectedDate,
               let route = try? TunnelProbe.routeInterface(), TunnelProbe.isTunnel(route) {
                #if os(macOS)
                // This app's system IKEv2 uses ipsecN on macOS. Never attribute FlClash utunN to it.
                guard route.hasPrefix("ipsec") else {
                    throw VPNNetworkError.message("목적지가 macOS IKEv2 경로를 사용하지 않습니다.")
                }
                #endif
                verifiedSession = (host, date, route)
                #if DIRECT_ROUTING && os(macOS)
                if manager.isOnDemandEnabled {
                    UserDefaults.standard.set(["host": host, "date": date, "interface": route], forKey: "routing.verifiedIKEv2")
                }
                #endif
                return
            }
            if status == .connecting || status == .reasserting { wasStarting = true }
            if status == .invalid || (status == .disconnected && (wasStarting || ProcessInfo.processInfo.systemUptime - start > 2)) {
                // A pre-existing disconnect reason can belong to another attempt. Consult it only
                // after observing this connection transition from connecting to disconnected.
                if wasStarting, status == .disconnected {
                    let failure: NSError? = await withCheckedContinuation { continuation in
                        manager.connection.fetchLastDisconnectError { continuation.resume(returning: $0 as NSError?) }
                    }
                    if let failure, failure.domain == NEVPNConnectionErrorDomain {
                        if failure.code == NEVPNConnectionError.authenticationFailed.rawValue {
                            throw VPNNetworkError.message("\(host) IKEv2 인증 거부. 계정 또는 서버 인증 방식을 확인해 주세요.")
                        }
                        throw VPNNetworkError.message("\(host) IKEv2 연결 실패 · " + failure.localizedDescription)
                    }
                }
                throw VPNNetworkError.message("\(host) IKEv2 연결을 확인하지 못했습니다.")
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        throw VPNNetworkError.message("\(host) IKEv2 연결 또는 터널 경로 확인 시간이 초과되었습니다.")
    }

    func connect(host: String, address: String, onDemand: Bool, usesSharedSecret: Bool = false) async throws {
        // Materialize credentials and validate input before interrupting the user's own active connection.
        let session = try build(host: host, address: address, shared: usesSharedSecret)
        try await manager.loadFromPreferences()
        try checkExclusiveRoute()
        try Task.checkCancellation()
        if connectedHost == host, profile?.serverAddress == address,
           profile?.authenticationMethod == session.authenticationMethod,
           let verified = verifiedSession, verified.host == host,
           manager.connection.connectedDate == verified.date, try TunnelProbe.routeInterface() == verified.interface {
            if manager.isOnDemandEnabled != onDemand {
                try await setOnDemand(onDemand)
                try await waitConnected(host: host)
            }
            return
        }
        try await disconnect()
        // Delayed route teardown is common even after NEVPNStatus.disconnected.
        var physicalRoute = false
        for _ in 0..<20 {
            if let route = try? TunnelProbe.routeInterface(), !TunnelProbe.isTunnel(route) { physicalRoute = true; break }
            try await Task.sleep(nanoseconds: 150_000_000)
        }
        guard physicalRoute else { throw VPNNetworkError.message("다른 VPN을 경유하여 연결할 수 없습니다.") }
        try Task.checkCancellation()
        manager.localizedDescription = "CoreaVPN"
        manager.protocolConfiguration = session
        manager.isEnabled = true
        manager.isOnDemandEnabled = false
        try await save()
        try Task.checkCancellation()
        try manager.connection.startVPNTunnel()
        do {
            try await waitConnected(host: host)
            if onDemand {
                try await setOnDemand(true)
                try await waitConnected(host: host)
            }
        } catch {
            // The coordinator subsequently restores its saved baseline or performs explicit disconnect.
            manager.connection.stopVPNTunnel()
            try? await Task { @MainActor in try await waitStopped() }.value
            verifiedSession = nil
            throw error
        }
    }

    func measure(host: String) async throws -> [Double] {
        guard let session = verifiedSession, session.host == host else {
            throw VPNNetworkError.message("현재 서버의 터널을 확인한 뒤 측정하십시오.")
        }
        return try await TunnelProbe.measure(interface: session.interface) {
            guard self.connectedHost == host, self.manager.connection.connectedDate == session.date,
                  try TunnelProbe.routeInterface() == session.interface else {
                throw VPNNetworkError.message("측정 중 터널 경로가 변경되었습니다.")
            }
        }
    }

    #if os(macOS)
    func measureSpeed(host: String, checkpoint: @escaping (HTTPSBenchmarkSample) throws -> Void) async throws -> HTTPSBenchmarkSample {
        guard let session = verifiedSession, session.host == host else {
            throw VPNNetworkError.message("현재 서버의 터널을 확인한 뒤 측정하십시오.")
        }
        return try await NativeSpeedProbe.measure(interface: session.interface, validate: { _ in
            guard self.connectedHost == host, self.manager.connection.connectedDate == session.date else {
                throw VPNNetworkError.message("측정 중 IKEv2 세션이 변경되었습니다.")
            }
        }, checkpoint: checkpoint)
    }
    #endif

    func restore(_ baseline: VPNBaseline) async throws {
        if let current = try? await snapshot(), current == baseline { return }
        try await disconnect()
        guard let host = baseline.host, let address = baseline.address else {
            if manager.protocolConfiguration != nil, manager.isEnabled != baseline.enabled {
                manager.isEnabled = baseline.enabled
                try await save()
            }
            return
        }
        if baseline.connected {
            try await connect(host: host, address: address, onDemand: baseline.onDemand, usesSharedSecret: baseline.usesSharedSecret)
        } else {
            manager.protocolConfiguration = try build(host: host, address: address, shared: baseline.usesSharedSecret)
            manager.isEnabled = baseline.enabled
            try await setOnDemand(baseline.onDemand)
        }
    }
}
