import Darwin
import Foundation
import LocalAuthentication
import Network
import NetworkExtension
import Security
#if canImport(CoreIPSec)
import CoreIPSec
#endif

struct ScopedConfiguration {
    let address: String
    let host: String
    let username: String
    let credentialReference: Data
    let uplink: String
    let plan: SplitRoutePlan
    let leases: [SplitRouteLease]
    let groupReferences: [String: Data]

    init(_ config: NEVPNProtocol) throws {
        guard let proto = config as? NETunnelProviderProtocol, !proto.includeAllNetworks, proto.enforceRoutes,
              let fields = proto.providerConfiguration,
              let addr = proto.serverAddress, VPNEndpoints.isPublicIPv4(addr),
              let remote = fields["remoteHost"] as? String, VPNEndpoints.all.contains(remote),
              let user = proto.username, !user.isEmpty, !user.utf8.contains(0),
              let credential = proto.passwordReference, !credential.isEmpty,
              fields["authentication"] as? String == "eap-cert",
              let leaseData = fields["leases"] as? Data, leaseData.count <= 1024 * 1024,
              let generation = fields["networkID"] as? String,
              let uplink = fields["uplinkFingerprint"] as? String, !uplink.isEmpty else {
            throw SplitRouteError.invalid("실험 프로필에 허용된 서버·인증 방식·계정 또는 제한된 경로가 없습니다.")
        }
        #if os(iOS)
        guard CoreaServer.catalog.contains(where: { $0.host == remote && $0.iPhoneSupported }) else {
            throw SplitRouteError.invalid("공식 목록에서 iPhone 지원을 확인할 수 없는 서버입니다.")
        }
        #endif
        let declared = try JSONDecoder().decode([SplitRouteLease].self, from: leaseData)
        guard (1...256).contains(declared.count) else { throw SplitRouteError.invalid("한 번에 목적지 IP 또는 대역을 1~256개 지정할 수 있습니다.") }
        // Exclude transport datagrams explicitly. Conflicting capture of the IKE
        // gateway is detected before passwords are accessed or OS routes changed.
        let gateway = SplitRouteLease(label: "IKEv2 서버", cidr: addr + "/32", policy: .direct, networkID: generation, expiresAt: nil)
        let plan = try SplitRoutePlanner.make(leases: declared + [gateway], networkID: generation)
        let groups = Set(plan.requiredTransports.compactMap { policy -> String? in
            if case .group(let name) = policy { return name }
            return nil
        })
        let refs = fields["groupReferences"] as? [String: Data] ?? [:]
        for name in groups where !GroupPacketTransport.available || refs[name]?.isEmpty != false {
            throw SplitRouteError.missingTransport(.group(name))
        }
        guard Set(refs.keys).isSubset(of: groups) else { throw SplitRouteError.invalid("지정된 목적지에 없는 그룹 참조입니다.") }
        guard plan.requiredTransports.contains(.coreaVPN) else { throw SplitRouteError.invalid("CoreaVPN을 사용할 IP 경로가 필요합니다.") }
        self.address = addr
        self.host = remote
        self.username = user
        self.credentialReference = credential
        self.uplink = uplink
        self.plan = plan
        self.leases = declared + [gateway]
        self.groupReferences = refs
    }
}

private final class PacketTransport: ScopedPacketIO {
    #if canImport(CoreIPSec)
    private let handle: UInt64
    #endif

    init() throws {
        #if canImport(CoreIPSec)
        handle = CVPNCreate()
        guard handle != 0 else { throw SplitRouteError.invalid("IPsec 전송 엔진을 초기화할 수 없습니다.") }
        #else
        throw SplitRouteError.invalid("이 빌드에는 CoreIPSec 전송 엔진이 연결되어 있지 않습니다.")
        #endif
    }

    func connect(_ config: ScopedConfiguration) throws -> (String?, String?) {
        #if canImport(CoreIPSec)
        let context = LAContext()
        context.interactionNotAllowed = true
        var search: [String: Any] = [kSecValuePersistentRef as String: config.credentialReference,
                                     kSecClass as String: kSecClassGenericPassword,
                                     kSecReturnData as String: true,
                                     kSecMatchLimit as String: kSecMatchLimitOne,
                                     kSecUseAuthenticationContext as String: context]
        #if os(macOS)
        search[kSecUseDataProtectionKeychain as String] = true
        #endif
        var item: CFTypeRef?
        let status = SecItemCopyMatching(search as CFDictionary, &item)
        guard status == errSecSuccess, var password = item as? Data, !password.isEmpty, !password.contains(0) else {
            throw SplitRouteError.invalid("확장 프로그램이 계정 키체인 참조를 사용할 수 없습니다 (\(status)).")
        }
        item = nil
        password.append(0)
        defer { password.resetBytes(in: 0..<password.count) }
        var addr = Array(config.address.utf8CString), host = Array(config.host.utf8CString), user = Array(config.username.utf8CString)
        let connected = password.withUnsafeMutableBytes {
            CVPNConnect(handle, &addr, &host, &user, $0.bindMemory(to: CChar.self).baseAddress, 20_000)
        }
        guard connected == 0 else { throw SplitRouteError.invalid("IKEv2 서버 신원 확인 또는 EAP 인증에 실패했습니다 (\(connected)).") }
        var v4 = [CChar](repeating: 0, count: 48), v6 = [CChar](repeating: 0, count: 64)
        guard CVPNAddresses(handle, &v4, 48, &v6, 64) == 0 else { throw SplitRouteError.invalid("IKEv2 내부 주소를 얻을 수 없습니다.") }
        let a = String(cString: v4), b = String(cString: v6)
        return (IPv4Address(a) == nil ? nil : a, IPv6Address(b) == nil ? nil : b)
        #else
        throw SplitRouteError.invalid("CoreIPSec을 사용할 수 없습니다.")
        #endif
    }

    func read(into buffer: inout [UInt8]) -> Int {
        #if canImport(CoreIPSec)
        let capacity = Int32(buffer.count)
        return Int(CVPNRead(handle, &buffer, capacity, 750))
        #else
        return -1
        #endif
    }

    func send(_ data: Data) -> Bool {
        #if canImport(CoreIPSec)
        return data.withUnsafeBytes {
            CVPNWrite(handle, UnsafeMutableRawPointer(mutating: $0.baseAddress), Int32($0.count)) == Int32(data.count)
        }
        #else
        return false
        #endif
    }

    func close() {
        #if canImport(CoreIPSec)
        CVPNClose(handle)
        #endif
    }
}

private final class ProviderSession {
    let config: ScopedConfiguration
    let transport: PacketTransport
    let monitor = NWPathMonitor()
    var startReply: ((Error?) -> Void)?
    var connecting = false
    var deadline: DispatchWorkItem?
    var expiry: DispatchWorkItem?
    var discovery: Task<Void, Never>?
    let writes = DispatchQueue(label: "CoreaVPN.prototype.outbound")
    var virtualDestinations: Set<Data> = []
    var currentPlan: SplitRoutePlan?
    private let registry = NSLock()
    private var transports: [RoutingPolicy: ScopedPacketIO]
    private var closed = false
    init(config: ScopedConfiguration, reply: ((Error?) -> Void)?) throws {
        self.config = config
        self.transport = try PacketTransport()
        transports = [.coreaVPN: transport]
        startReply = reply
    }

    func register(_ group: GroupPacketTransport, as name: String) throws {
        registry.lock()
        if closed {
            registry.unlock()
            group.close()
            throw CancellationError()
        }
        transports[.group(name)] = group
        registry.unlock()
    }

    func dataPlanes() -> [RoutingPolicy: ScopedPacketIO] {
        registry.lock()
        defer { registry.unlock() }
        return transports
    }

    func close() {
        registry.lock()
        closed = true
        let all = transports
        transports = [:]
        registry.unlock()
        for transport in all.values { transport.close() }
    }
}

struct PacketEnvelope {
    let family: Int32
    let destination: Data
    let address: String
    let sourceAddress: String

    init?(_ packet: Data) {
        let data = [UInt8](packet)
        guard let first = data.first else { return nil }
        switch first >> 4 {
        case 4:
            let header = Int(first & 0xf) * 4
            guard header >= 20, data.count >= header, (Int(data[2]) << 8 | Int(data[3])) == data.count else { return nil }
            destination = Data(data[16..<20])
            guard let ip = IPv4Address(destination) else { return nil }
            family = AF_INET
            address = ip.debugDescription
            sourceAddress = data[12..<16].map(String.init).joined(separator: ".")
        case 6:
            guard data.count >= 40, (Int(data[4]) << 8 | Int(data[5])) + 40 == data.count else { return nil }
            destination = Data(data[24..<40])
            guard let ip = IPv6Address(destination), let source = IPv6Address(Data(data[8..<24])) else { return nil }
            family = AF_INET6
            address = ip.debugDescription
            sourceAddress = source.debugDescription
        default: return nil
        }
    }
}

/// Development extension for the scoped, authenticated CoreaVPN path. A proxy
/// group without a packet transport causes startTunnel to fail before capture.
final class ScopedPacketTunnelProvider: NEPacketTunnelProvider {
    private let state = DispatchQueue(label: "CoreaVPN.prototype.provider")
    private var active: ProviderSession?
    private var closing = false
    private var heldConfiguration: ScopedConfiguration?
    private var heldPlan: SplitRoutePlan?
    private var retry: DispatchWorkItem?
    private var retryDelay: Double = 2
    private var pendingRead = false
    private var lastIssue: String?
    private var stopReplies: [() -> Void] = []

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        state.async {
            guard let extensionInfo = Bundle.main.object(forInfoDictionaryKey: "NSExtension") as? [String: Any],
                  extensionInfo["NSExtensionPointIdentifier"] as? String == "com.apple.networkextension.packet-tunnel",
                  let bundleID = Bundle.main.bundleIdentifier,
                  (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == bundleID else {
                completionHandler(SplitRouteError.invalid("이 빌드는 서명된 터널 확장 프로그램으로 실행해야 합니다."))
                return
            }
            guard self.active == nil, self.heldConfiguration == nil, !self.closing else { completionHandler(SplitRouteError.invalid("기존 실험 터널의 종료를 기다리십시오.")); return }
            do {
                self.lastIssue = nil
                let session = try ProviderSession(config: ScopedConfiguration(self.protocolConfiguration), reply: completionHandler)
                self.begin(session)
            } catch { completionHandler(error) }
        }
    }

    private func begin(_ session: ProviderSession) {
        self.active = session
        let deadline = DispatchWorkItem { [weak self, weak session] in
            guard let self, let session else { return }
            self.fail(session, SplitRouteError.invalid("터널 시작 시간이 초과되었습니다."))
        }
        session.deadline = deadline
        self.state.asyncAfter(deadline: .now() + SplitRoutePlanner.startupLimit(proxyGroups: session.config.groupReferences.count), execute: deadline)
        if let expiry = session.config.plan.validUntil {
            let stop = DispatchWorkItem { [weak self, weak session] in
                guard let self, let session else { return }
                self.fail(session, SplitRouteError.expired("실험 터널"))
            }
            session.expiry = stop
            self.state.asyncAfter(deadline: .now() + max(0, expiry.timeIntervalSinceNow), execute: stop)
        }
        session.monitor.pathUpdateHandler = { [weak self, weak session] _ in
            guard let self, let session, self.active === session else { return }
            guard SplitUplink.fingerprint(to: session.config.address) == session.config.uplink else {
                self.fail(session, SplitRouteError.changedNetwork)
                return
            }
            if !session.connecting {
                session.connecting = true
                self.authenticate(session)
            }
        }
        session.monitor.start(queue: self.state)
    }

    private func authenticate(_ session: ProviderSession) {
        typealias Discovery = (plan: SplitRoutePlan, leaves: [(String, VerifiedProxyLeaf)])
        let config = session.config
        // Discovery owns only its input values. Lifecycle and cancellation are
        // checked again on the provider's serial queue before starting native I/O.
        let deliver: (Result<Discovery, Error>) -> Void = { [weak self, weak session] result in
            guard let self, let session else { return }
            self.state.async {
                guard self.active === session else { return }
                switch result {
                case .success(let ready): self.connectTransports(session, plan: ready.plan, resolvedLeaves: ready.leaves)
                case .failure(let error): self.fail(session, error)
                }
            }
        }
        session.discovery = Task.detached(priority: .userInitiated) {
            do {
                var leases = config.leases
                var leaves: [(String, VerifiedProxyLeaf)] = []
                if !config.groupReferences.isEmpty {
                    let resolver = VPNResolver()
                    for (name, ref) in config.groupReferences {
                        let leaf = try await VerifiedProxyLeaf.load(reference: ref, group: name, uplink: config.uplink, resolver: resolver)
                        leases.append(.init(label: name + " 서버", cidr: leaf.address + "/32", policy: .direct,
                                            networkID: config.plan.networkID, expiresAt: nil))
                        leaves.append((name, leaf))
                    }
                }
                let plan = try SplitRoutePlanner.make(leases: leases, networkID: config.plan.networkID)
                try Task.checkCancellation()
                deliver(.success((plan, leaves)))
            } catch { deliver(.failure(error)) }
        }
    }

    private func connectTransports(_ session: ProviderSession, plan: SplitRoutePlan, resolvedLeaves: [(String, VerifiedProxyLeaf)]) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result {
                var leaves = resolvedLeaves
                let config = session.config
                let (a4, a6) = try session.transport.connect(config)
                for index in leaves.indices {
                    let transport = try GroupPacketTransport(configuration: &leaves[index].1.payload)
                    try session.register(transport, as: leaves[index].0)
                    try transport.verify()
                }
                return (a4, a6, plan)
            }
            self.state.async {
                guard self.active === session else { return }
                do {
                    let (a4, a6, plan) = try result.get()
                    let planes = session.dataPlanes()
                    let routes = try plan.appleRoutes(networkID: plan.networkID, readyPolicies: Set(planes.keys))
                    guard routes.includedIPv4.isEmpty || a4 != nil, routes.includedIPv6.isEmpty || a6 != nil else {
                        throw SplitRouteError.invalid("인증된 서버가 요청한 IP 버전의 터널 주소를 할당하지 않았습니다.")
                    }
                    let network = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: session.config.address)
                    network.mtu = 1280
                    if let a4, let local = IPv4Address(a4) {
                        session.virtualDestinations.insert(local.rawValue)
                        let ipv4 = NEIPv4Settings(addresses: [a4], subnetMasks: ["255.255.255.255"])
                        ipv4.includedRoutes = routes.includedIPv4; ipv4.excludedRoutes = routes.excludedIPv4
                        network.ipv4Settings = ipv4
                    }
                    if let a6, let local = IPv6Address(a6) {
                        session.virtualDestinations.insert(local.rawValue)
                        let ipv6 = NEIPv6Settings(addresses: [a6], networkPrefixLengths: [128])
                        ipv6.includedRoutes = routes.includedIPv6; ipv6.excludedRoutes = routes.excludedIPv6
                        network.ipv6Settings = ipv6
                    }
                    self.setTunnelNetworkSettings(network) { error in
                        self.state.async {
                            guard self.active === session else { return }
                            if let error { self.fail(session, error); return }
                            guard session.config.plan.validUntil.map({ $0 > Date() }) ?? true else {
                                self.fail(session, SplitRouteError.expired("실험 경로"))
                                return
                            }
                            session.currentPlan = plan
                            session.deadline?.cancel()
                            self.reasserting = false
                            self.lastIssue = nil
                            self.heldConfiguration = nil
                            self.heldPlan = nil
                            self.retryDelay = 2
                            let reply = session.startReply; session.startReply = nil
                            reply?(nil)
                            self.readOperatingSystem(session)
                            for (policy, transport) in planes { self.readTransport(session, from: transport, policy: policy) }
                        }
                    }
                } catch { self.fail(session, error) }
            }
        }
    }

    private func readOperatingSystem(_ session: ProviderSession) {
        guard !pendingRead, active === session else { return }
        pendingRead = true
        packetFlow.readPackets { packets, families in
            self.state.async {
                self.pendingRead = false
                guard self.active === session else {
                    if let current = self.active, current.startReply == nil, !self.reasserting { self.readOperatingSystem(current) }
                    return
                }
                do {
                    guard packets.count == families.count else { throw SplitRouteError.invalid("패킷 형식이 일치하지 않습니다.") }
                    guard let plan = session.currentPlan else { throw SplitRouteError.invalid("검증된 IP 경로가 없습니다.") }
                    let planes = session.dataPlanes()
                    var batches: [(RoutingPolicy, ScopedPacketIO, Data)] = []
                    for (bytes, family) in zip(packets, families) {
                        guard let packet = PacketEnvelope(bytes), packet.family == family.int32Value else {
                            throw SplitRouteError.invalid("유효한 IP 패킷이 아닙니다.")
                        }
                        guard let policy = try plan.policy(for: packet.address, networkID: plan.networkID),
                              let transport = planes[policy] else {
                            throw SplitRouteError.invalid("선택된 목적지 경로가 변경되었습니다.")
                        }
                        batches.append((policy, transport, bytes))
                    }
                    // Never block stopTunnel or expiry handling on transport I/O.
                    // Only one batch is outstanding, so no unbounded packet queue.
                    let transfers = batches
                    session.writes.async {
                        let failed = transfers.first { !$0.1.send($0.2) }?.0
                        self.state.async {
                            guard self.active === session else { return }
                            if let failed { self.fail(session, SplitRouteError.invalid("\(failed.title) 패킷 전송 실패")) }
                            else { self.readOperatingSystem(session) }
                        }
                    }
                } catch { self.fail(session, error) }
            }
        }
    }

    private func readTransport(_ session: ProviderSession, from transport: ScopedPacketIO, policy: RoutingPolicy) {
        DispatchQueue.global(qos: .userInitiated).async {
            var buffer = [UInt8](repeating: 0, count: 65575)
            while true {
                let count = transport.read(into: &buffer)
                if count == 0 { continue }
                let data = (1...buffer.count).contains(count) ? Data(buffer.prefix(count)) : Data()
                let keepReading = self.state.sync {
                    guard self.active === session else { return false }
                    guard let packet = PacketEnvelope(data), let plan = session.currentPlan,
                          session.virtualDestinations.contains(packet.destination) else {
                        self.fail(session, SplitRouteError.invalid("\(policy.title) 데이터 경로가 중단되었습니다."))
                        return false
                    }
                    // Only an exit assigned this destination may send its response.
                    // A different exit cannot inject a response into another policy's flow.
                    guard (try? plan.policy(for: packet.sourceAddress, networkID: plan.networkID)) == policy else { return true }
                    guard self.packetFlow.writePackets([data], withProtocols: [NSNumber(value: packet.family)]) else {
                        self.fail(session, SplitRouteError.invalid("터널 패킷 수신 실패"))
                        return false
                    }
                    return true
                }
                if !keepReading { break }
            }
        }
    }

    private func fail(_ session: ProviderSession, _ error: Error) {
        guard active === session else { return }
        lastIssue = error.localizedDescription
        let reply = session.startReply
        session.startReply = nil
        if let reply {
            release(session) { reply(error) }
            return
        }

        // Keep the already-installed, explicit capture routes in place during
        // reconnect. Removing them here would expose these destinations on Direct.
        reasserting = true
        heldConfiguration = session.config
        if let installed = session.currentPlan { heldPlan = installed }
        let permanent: Bool
        switch error {
        case SplitRouteError.changedNetwork, SplitRouteError.expired: permanent = true
        default: permanent = false
        }
        release(session) {
            if !permanent { self.scheduleReconnect() }
        }
    }

    private func scheduleReconnect() {
        guard let config = heldConfiguration,
              config.plan.validUntil.map({ $0 > Date() }) ?? true else { return }
        // If the physical route changed, the app must submit fresh leases.
        guard SplitUplink.fingerprint(to: config.address) == config.uplink else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.heldConfiguration != nil, self.active == nil,
                  !self.closing, config.plan.validUntil.map({ $0 > Date() }) ?? true else { return }
            do { self.begin(try ProviderSession(config: config, reply: nil)) }
            catch { self.scheduleReconnect() }
        }
        retry = work
        state.asyncAfter(deadline: .now() + retryDelay, execute: work)
        retryDelay = min(30, retryDelay * 2)
    }

    private func release(_ session: ProviderSession, completion: @escaping () -> Void) {
        active = nil
        closing = true
        session.monitor.cancel()
        session.deadline?.cancel()
        session.expiry?.cancel()
        session.discovery?.cancel()
        DispatchQueue.global(qos: .userInitiated).async {
            session.close()
            self.state.async {
                self.closing = false
                completion()
                let replies = self.stopReplies
                self.stopReplies = []
                replies.forEach { $0() }
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        state.async {
            self.heldConfiguration = nil
            self.heldPlan = nil
            self.retry?.cancel()
            self.retry = nil
            self.reasserting = false
            if self.closing { self.stopReplies.append(completionHandler); return }
            guard let session = self.active else { completionHandler(); return }
            let reply = session.startReply
            session.startReply = nil
            self.release(session) {
                reply?(CancellationError())
                completionHandler()
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        state.async {
            guard messageData == Data("status".utf8) else { completionHandler?(nil); return }
            var report: [String: Any] = ["reasserting": self.reasserting,
                                         "installedRoutes": self.active?.currentPlan?.routeCount ?? self.heldPlan?.routeCount ?? 0]
            if let issue = self.lastIssue { report["issue"] = issue }
            completionHandler?(try? JSONSerialization.data(withJSONObject: report))
        }
    }
}
