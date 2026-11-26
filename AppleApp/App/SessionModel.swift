import Foundation
import Combine

enum ClientIssue: LocalizedError {
    case message(String)
    var errorDescription: String? { if case let .message(text) = self { return text }; return nil }
}

@MainActor
final class DeviceDriver: BenchmarkDriver {
    let vpn = NativeVPN()
    let resolver = VPNResolver()
    let uplink: UplinkMonitor
    private var invalidation: Task<Void, Never>?
    var sharedSecretHosts: Set<String> = []

    init(uplink: UplinkMonitor) { self.uplink = uplink }

    func invalidateAddresses() {
        invalidation = Task { await resolver.flush() }
    }

    func snapshot() async throws -> ScanBaseline {
        let old = try await vpn.snapshot()
        guard old.host != nil else { throw ClientIssue.message("설정에서 이 앱의 VPN 구성을 최초 승인해 주세요.") }
        try vpn.checkExclusiveRoute()
        return ScanBaseline(host: old.host, connected: old.connected, onDemand: old.onDemand,
                            endpoint: old.address, authentication: old.usesSharedSecret ? "sharedSecret" : "certificate", enabled: old.enabled)
    }

    func endpoint(_ host: String) async throws -> String {
        guard CoreaServer.catalog.contains(where: { $0.host == host }) else { throw ClientIssue.message("목록에 없는 서버입니다.") }
        let link = uplink.link
        guard link.available else { throw ClientIssue.message("물리 네트워크 연결을 확인해 주세요.") }
        await invalidation?.value
        try Task.checkCancellation()
        guard link == uplink.link else { throw BenchmarkError.wrongNetwork }
        let address = try await resolver.resolve(host, network: link.interface + "/" + link.prefix, interface: link.interface)
        try Task.checkCancellation()
        guard link == uplink.link else { throw BenchmarkError.wrongNetwork }
        return address
    }

    func establish(_ host: String, retain: Bool) async throws {
        let address = try await endpoint(host)
        try await vpn.connect(host: host, address: address, onDemand: retain, usesSharedSecret: sharedSecretHosts.contains(host))
    }

    func begin(host: String) async throws { try await establish(host, retain: false) }

    func ping(host: String) async throws -> PingSample {
        let replies = try await vpn.measure(host: host)
        return try PingSample(sent: PingSample.probeCount, received: replies.count,
                              meanMS: replies.isEmpty ? nil : replies.reduce(0,+) / Double(replies.count),
                              minimumMS: replies.min(), maximumMS: replies.max())
    }
    func speed(host: String, checkpoint: @escaping (HTTPSBenchmarkSample) throws -> Void) async throws -> HTTPSBenchmarkSample {
        #if os(macOS)
        return try await vpn.measureSpeed(host: host, checkpoint: checkpoint)
        #else
        throw ClientIssue.message("이 기기에서는 FAST 측정을 지원하지 않습니다.")
        #endif
    }
    func select(host: String) async throws { try await establish(host, retain: true) }
    func restore(_ baseline: ScanBaseline) async throws {
        let expected = VPNBaseline(host: baseline.host, address: baseline.endpoint,
                                   connected: baseline.connected, onDemand: baseline.onDemand,
                                   usesSharedSecret: baseline.authentication == "sharedSecret", enabled: baseline.enabled)
        try await vpn.restore(expected)
        #if os(macOS)
        // NEVPN can report "disconnected" while the old ipsec route is still being removed.
        let deadline = ProcessInfo.processInfo.systemUptime + 8
        while true {
            try Task.checkCancellation()
            if let state = try? await vpn.snapshot(), state == expected, let route = try? TunnelProbe.routeInterface(),
               expected.connected ? route.hasPrefix("ipsec") : !TunnelProbe.isTunnel(route) { break }
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw ClientIssue.message("이전 VPN 설정 또는 경로 복구를 확인하지 못했습니다.")
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [:]
        config.timeoutIntervalForResource = 6
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let endpoint = URL(string: "https://speed.cloudflare.com/__down?bytes=0&nonce=\(UUID().uuidString)")!
        let (body, response) = try await session.data(from: endpoint)
        guard let http = response as? HTTPURLResponse, http.url?.host == HTTPSBenchmarkSample.target,
              http.statusCode == 200, body.isEmpty else {
            throw ClientIssue.message("이전 연결에서 HTTPS 응답을 확인하지 못했습니다.")
        }
        #endif
    }
    func disconnect() async throws { try await vpn.disconnect() }
}

@MainActor
final class SessionModel: ObservableObject {
    let store: BenchmarkStore
    let uplink: UplinkMonitor
    let driver: DeviceDriver
    let scanner: BenchmarkScanner
    let deviceID: String
    @Published var link = PhysicalLink()
    @Published private(set) var work = ""
    @Published private(set) var shuttingDown = false
    @Published private(set) var stoppingScan = false
    @Published var message = ""
    @Published var connectedHost: String?
    @Published private(set) var relayEnabled = false
    @Published var addresses: [String: String] = [:]
    @Published var dnsErrors: [String: String] = [:]
    @Published var routeLabel: String
    @Published var allowDE: Bool
    @Published var excludedGroup: String
    @Published var credentialName = ""
    @Published var sharedHosts: Set<String> = []
    @Published var active: BenchmarkRun?
    private var observing: Set<AnyCancellable> = []
    private var lookup: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var renewal: Task<Void, Never>?
    private var renewalToken = UUID()
    private var isForeground = true
    private var refreshPending = false
    private var lookupGeneration = UUID()
    private let defaults = UserDefaults.standard
    private let baselineCSV: String

    init() throws {
        let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask,
                                              appropriateFor: nil, create: true).appendingPathComponent("CoreaVPN", isDirectory: true)
        store = try BenchmarkStore(fileURL: dir.appendingPathComponent("measurements.json"))
        let monitor = UplinkMonitor()
        uplink = monitor
        driver = DeviceDriver(uplink: monitor)
        scanner = BenchmarkScanner(store: store, driver: driver)
        let id = defaults.string(forKey: "installationID") ?? UUID().uuidString
        deviceID = id
        defaults.set(id, forKey: "installationID")
        routeLabel = ""
        allowDE = defaults.bool(forKey: "allowDE")
        excludedGroup = defaults.string(forKey: "excludedGroup") ?? ""
        sharedHosts = Set(defaults.stringArray(forKey: "sharedHosts") ?? [])
        guard let file = Bundle.main.url(forResource: "BeijingOfficeBaseline", withExtension: "csv") else {
            throw ClientIssue.message("앱에 베이징 기준선이 포함되지 않았습니다.")
        }
        baselineCSV = try String(contentsOf: file, encoding: .utf8)
        driver.sharedSecretHosts = sharedHosts
        try store.importBeijingBaseline(csv: baselineCSV)
        monitor.$link.removeDuplicates().sink { [weak self] link in self?.changed(to: link) }.store(in: &observing)
    }

    private func changed(to new: PhysicalLink) {
        guard new != link else { return }
        let wasScanning = work == "scan"
        driver.invalidateAddresses()
        link = new
        routeLabel = defaults.string(forKey: nameKey) ?? ""
        addresses = [:]; dnsErrors = [:]
        lookupGeneration = UUID()
        lookup?.cancel()
        if work == "lookup" { work = "" }
        if wasScanning { Task { await pauseScan() } }
        expiryTask?.cancel()
        if relayEnabled, new.available { queueRefresh() }
        scheduleOnDemandCheck()
    }
    private var nameKey: String { "networkName.\(link.transport).\(link.interface).\(link.prefix)" }
    var network: BenchmarkNetwork {
        BenchmarkNetwork(deviceID: deviceID, label: routeLabel.trimmingCharacters(in: .whitespacesAndNewlines),
                         interface: link.interface, transport: link.transport, fingerprint: link.prefix)
    }
    func saveSettings() {
        defaults.set(routeLabel, forKey: nameKey)
        defaults.set(allowDE, forKey: "allowDE"); defaults.set(excludedGroup, forKey: "excludedGroup")
    }

    func exclusion(_ server: CoreaServer) -> String? {
        #if os(iOS)
        guard server.iPhoneSupported else { return "iPhone 미지원" }
        if Self.needsProviderAuth(server), !sharedHosts.contains(server.host) { return "공식 프로필 인증 설정 필요" }
        #endif
        if server.requiresExtendedAccount && !allowDE { return "D/E 계정 사용 설정 필요" }
        if !excludedGroup.isEmpty && (server.group == excludedGroup ||
            (["D","E"].contains(excludedGroup) && server.requiresExtendedAccount)) { return "다른 기기의 사용 그룹" }
        return nil
    }
    static func needsProviderAuth(_ server: CoreaServer) -> Bool {
        server.iPhoneSupported && (server.host == "eagle.coreavpn.net" || server.requiresExtendedAccount)
    }
    var candidates: [CoreaServer] { CoreaServer.catalog.filter { exclusion($0) == nil } }
    var busy: Bool { !work.isEmpty || shuttingDown }

    var previewBuild: Bool {
        #if targetEnvironment(simulator)
        true
        #else
        Bundle.main.bundleIdentifier?.hasSuffix(".preview") == true
        #endif
    }
    func refreshStatus() async {
        if previewBuild {
            #if targetEnvironment(simulator)
            message = "iPhone 시뮬레이터 · VPN 연결과 지연 측정은 실제 iPhone에서 사용할 수 있습니다."
            #else
            if message.isEmpty { message = "CoreaVPN_TEST에서 선택한 방식으로 서버를 측정합니다. 연결을 해제하면 FlClash를 복구합니다." }
            #endif
            return
        }
        do {
            credentialName = try driver.vpn.configuredCredentialUsername() ?? ""
            let state = try await driver.vpn.snapshot()
            connectedHost = state.connected ? state.host : nil
        } catch { if message.isEmpty { message = error.localizedDescription } }
    }
    func saveAccount(_ name: String, _ password: String) throws {
        guard !busy, !name.trimmingCharacters(in:.whitespaces).isEmpty, !password.isEmpty else {
            throw ClientIssue.message("검사가 끝난 후 계정과 암호를 입력해 주세요.")
        }
        try driver.vpn.saveCredentials(username: name, password: password)
        if credentialName != name {
            sharedHosts = Set(CoreaServer.catalog.compactMap { (try? driver.vpn.hasOfficialProfile(for: $0.host)) == true ? $0.host : nil })
            defaults.set(Array(sharedHosts).sorted(), forKey: "sharedHosts")
            driver.sharedSecretHosts = sharedHosts
        }
        credentialName = name
    }
    func importOfficial(_ data: Data) throws -> String {
        guard !busy else { throw BenchmarkError.busy }
        let host = try driver.vpn.importOfficialProfile(data)
        sharedHosts.insert(host)
        defaults.set(Array(sharedHosts).sorted(), forKey: "sharedHosts")
        driver.sharedSecretHosts = sharedHosts
        return host
    }
    func recover() async {
        guard !busy, store.runs.contains(where: { $0.recoveryNeeded == true }) else { return }
        work = "recovery"; defer { work = "" }
        do {
            try await scanner.recoverInterrupted()
            message = "중단 당시의 연결 상태를 복구했습니다."
        } catch { message = error.localizedDescription }
    }
    func authorize() async {
        guard !busy else { return }; work = "permission"; defer { work = "" }
        do {
            try await driver.vpn.authorize(host: "puma.coreavpn.net")
            message = "이 앱의 VPN 구성을 저장했습니다."
        } catch { message = error.localizedDescription }
    }

    func scheduleOnDemandCheck() {
        guard !previewBuild, !shuttingDown, isForeground, link.available else { return }
        // A live, healthy tunnel may continue to use an address whose DNS TTL
        // expired. Only repair an OS-selected endpoint after a real disconnect.
        if work == "reconnect" { return }
        renewal?.cancel()
        let token = UUID(); renewalToken = token
        renewal = Task {
            do {
                try await Task.sleep(nanoseconds: 1_500_000_000)
                guard renewalToken == token, !busy, isForeground, link.available else { return }
                let old = try await driver.vpn.snapshot()
                try Task.checkCancellation()
                guard renewalToken == token, !busy, isForeground else { return }
                guard old.onDemand, !old.connected, old.enabled, let host = old.host,
                      host.hasSuffix(".net"), CoreaServer.catalog.contains(where: { $0.host == host }) else { return }
                try driver.vpn.checkExclusiveRoute()
                work = "reconnect"
                defer { if work == "reconnect" { work = "" } }
                let address = try await driver.endpoint(host)
                try Task.checkCancellation()
                guard address != old.address else { return }
                do {
                    try await driver.vpn.connect(host: host, address: address, onDemand: true, usesSharedSecret: old.usesSharedSecret)
                    connectedHost = host
                } catch {
                    if !Task.isCancelled {
                        message = error.localizedDescription
                        try await driver.vpn.restore(old)
                    }
                    throw error
                }
            } catch is CancellationError { }
            catch { if work == "reconnect" { message = error.localizedDescription } }
        }
    }
    func foreground(_ active: Bool) {
        isForeground = active
        if active { scheduleOnDemandCheck() }
        if active, relayEnabled { queueRefresh() }
        else if !active { expiryTask?.cancel() }
    }
    private func queueRefresh() {
        guard isForeground, link.available else { return }
        if busy { refreshPending = true; return }
        warmResolver()
    }
    private func rescheduleRefresh() async {
        expiryTask?.cancel()
        guard relayEnabled, isForeground else { return }
        let expiry = await driver.resolver.nextExpiry()
        let seconds = max(2, min(expiry?.timeIntervalSinceNow ?? 60, dnsErrors.isEmpty ? 3600 : 60))
        expiryTask = Task {
            do { try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000)) } catch { return }
            queueRefresh()
        }
    }
    func warmResolver() {
        guard !busy, link.available else { return }
        relayEnabled = true
        refreshPending = false
        expiryTask?.cancel()
        let token = UUID(); lookupGeneration = token
        work = "lookup"; addresses = [:]; dnsErrors = [:]
        let hosts = CoreaServer.catalog.map(\.host).filter { $0.hasSuffix(".net") }
        lookup = Task {
            for host in hosts {
                guard !Task.isCancelled, lookupGeneration == token else { return }
                do {
                    let address = try await driver.endpoint(host)
                    guard lookupGeneration == token else { return }; addresses[host] = address
                } catch { guard lookupGeneration == token else { return }; dnsErrors[host] = error.localizedDescription }
            }
            guard lookupGeneration == token else { return }
            message = ".net 주소 \(addresses.count)/\(hosts.count)개 확인"; work = ""
            await rescheduleRefresh()
        }
    }
    func canResume(_ run: BenchmarkRun) -> Bool {
        guard run.canResume, run.network == network, run.recoveryNeeded != true else { return false }
        #if os(macOS)
        return run.mode != .all || run.paired == true
        #else
        return true
        #endif
    }
    func start(_ mode: ScanMode, resume: UUID? = nil) async {
        guard !busy else { return }
        guard link.available, !network.label.isEmpty else { message = "설정에서 현재 회선 이름을 지정해 주세요."; return }
        guard !credentialName.isEmpty else { message = "설정에서 CoreaVPN 계정을 저장해 주세요."; return }
        let original = link, scope = network
        saveSettings()
        active = nil
        work = "scan"; defer {
            stoppingScan = false
            work = ""
            if refreshPending { queueRefresh() }
        }
        do {
            #if os(macOS)
            let paired = true
            #else
            let paired = false
            #endif
            let finished = try await scanner.run(mode: mode, network: scope, candidates: candidates, resumeID: resume, paired: paired,
                isNetworkCurrent: { self.link == original && self.network == scope },
                onProgress: { self.active = $0 })
            active = finished
            message = finished.message ?? (finished.selectedHost.map { "\($0)에 연결했습니다." } ?? "검사를 종료했습니다.")
        } catch is CancellationError where stoppingScan {
            message = "검사를 중지했습니다."
        } catch { message = error.localizedDescription }
        await refreshStatus()
    }
    func connectSelected(host: String, in run: BenchmarkRun) async {
        guard !busy, !previewBuild, link.available, candidates.contains(where: { $0.host == host }) else { return }
        let original = link, scope = network
        work = "selection"
        defer { work = "" }
        do {
            active = try await scanner.connectSelected(host: host, runID: run.id, network: scope,
                isNetworkCurrent: { self.link == original && self.network == scope })
            message = "\(host)에 연결했습니다."
        } catch { message = error.localizedDescription }
        await refreshStatus()
    }
    func stopScan() async {
        guard work == "scan", !stoppingScan, !shuttingDown else { return }
        stoppingScan = true
        do { try await scanner.stopScan() }
        catch is CancellationError { /* Stopped before the baseline snapshot completed. */ }
        catch { message = error.localizedDescription }
    }
    func pauseScan() async {
        guard work == "scan" else { return }
        do { try await scanner.pause() } catch { message = error.localizedDescription }
    }
    func disconnect() async {
        guard !shuttingDown, work != "permission" else { return }
        shuttingDown = true; defer { shuttingDown = false }
        renewalToken = UUID()
        renewal?.cancel()
        await renewal?.value
        lookupGeneration = UUID(); lookup?.cancel()
        if work == "lookup" { work = "" }
        relayEnabled = false; expiryTask?.cancel(); refreshPending = false
        do {
            try await scanner.disconnect()
            connectedHost = nil
            message = "CoreaVPN 연결과 자동 재연결을 해제했습니다."
        } catch { message = error.localizedDescription }
    }
    func bindBaseline() {
        #if os(macOS)
        do {
            guard !busy, !network.label.isEmpty else { throw ClientIssue.message("현재 회선 이름을 먼저 저장해 주세요.") }
            try store.importBeijingBaseline(csv: baselineCSV, into: network)
            message = "기존 23개 측정값을 이 Mac의 현재 회선에 연결했습니다."
        } catch { message = error.localizedDescription }
        #endif
    }
}
