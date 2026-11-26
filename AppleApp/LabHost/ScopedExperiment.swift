#if ROUTE_LAB
import SwiftUI
import Network
import NetworkExtension

/// This host and its embedded packet provider are built only by the lab scheme.
struct ScopedExperiment: View {
    @ObservedObject var model: SessionModel
    @AppStorage("scopedExperimentDestinations") private var input = ""
    @State private var text = ""
    @State private var running = false
    @State private var chosen = "puma.coreavpn.net"
    private let providerID = (Bundle.main.bundleIdentifier ?? "") + ".tunnel"

    private var eligible: [CoreaServer] {
        model.candidates.filter { server in
            #if os(iOS)
            if SessionModel.needsProviderAuth(server) { return false }
            #endif
            return !model.sharedHosts.contains(server.host)
        }
    }
    var body: some View {
        NavigationStack {
            Form {
                Section("한정된 IP 경로 실험") {
                    NavigationLink("기존 프록시 그룹 연결 설정") { ProxyLeafSettings() }
                    Picker("IKEv2 서버", selection: $chosen) {
                        ForEach(eligible) { server in Text(server.host).tag(server.host) }
                    }
                    TextField("검증할 도메인·IP·CIDR (줄마다 한 개)", text: $input, axis: .vertical)
                        .lineLimit(3...8)
                    Button("편집한 규칙의 목적지 추가") {
                        do {
                            var entries = destinations
                            for rule in try savedDocument().rules where rule.original == nil &&
                                ["DOMAIN", "IP-CIDR", "IP-CIDR6"].contains(rule.kind) && !entries.contains(rule.value) {
                                entries.append(rule.value)
                            }
                            input = entries.joined(separator: "\n")
                        } catch { text = error.localizedDescription }
                    }
                    Text("도메인 접미사 규칙은 시험할 호스트 이름을 입력하세요. IP 대역은 전체 대역의 경로가 일치할 때 적용합니다.").font(.caption)
                }
                Section {
                    Button("규칙 대조 후 실험 터널 시작") { execute { try await start() } }
                    Button("실험 터널 해제", role: .destructive) {
                        execute {
                            if let manager = try await managed() { manager.connection.stopVPNTunnel() }
                            text = "해제를 요청했습니다."
                        }
                    }
                }.disabled(running || model.busy)
                if !text.isEmpty { Text(text).textSelection(.enabled) }
            }.navigationTitle("터널 실험")
            .onAppear {
                if let latest = model.store.runs.last(where: { $0.selectedHost != nil && $0.network == model.network })?.selectedHost,
                   eligible.contains(where: { $0.host == latest }) { chosen = latest }
            }
        }
    }
    private func execute(_ task: @escaping @MainActor () async throws -> Void) {
        guard !running else { return }
        running = true
        Task { @MainActor in
            defer { running = false }
            do { try await task() } catch { text = error.localizedDescription }
        }
    }
    @MainActor private func managed() async throws -> NETunnelProviderManager? {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        return managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID }
    }
    private var destinations: [String] {
        input.split(whereSeparator: { $0.isWhitespace || $0 == "," }).map(String.init)
    }
    private func savedDocument() throws -> RoutingDocument {
        let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CoreaVPN/routing-v1.json")
        return try RoutingDocument.decode(Data(contentsOf: file))
    }
    @MainActor private func start() async throws {
        let link = model.link
        guard link.available, !model.driver.sharedSecretHosts.contains(chosen), eligible.contains(where: { $0.host == chosen }) else {
            throw ClientIssue.message("이 회선의 EAP 인증 지원 서버를 선택해 주세요.")
        }
        let current = try await model.driver.vpn.snapshot()
        guard !current.connected, !current.onDemand else { throw ClientIssue.message("먼저 현재 CoreaVPN을 해제해 주세요.") }
        try model.driver.vpn.checkExclusiveRoute()
        let previously = try await managed()
        if let previously, ![.disconnected,.invalid].contains(previously.connection.status) {
            throw ClientIssue.message("기존 실험 터널을 해제한 뒤 다시 시작해 주세요.")
        }
        let document = try savedDocument()
        let entries = destinations
        guard (1...128).contains(entries.count) else { throw ClientIssue.message("검증할 목적지 1–128개를 입력해 주세요.") }
        let generation = UUID().uuidString
        var leases: [SplitRouteLease] = []
        for entry in entries {
            if entry.contains("/") {
                let policy = try SplitRoutePlanner.policy(forCIDR: entry, document: document)
                leases.append(SplitRouteLease(label: entry, cidr: entry, policy: policy,
                                              networkID: generation, expiresAt: nil))
                continue
            }
            let answers = try await DestinationDNS.addresses(for: entry)
            for answer in answers {
                var query = RouteQuery(); query.ip = answer.ip
                if answer.expires != nil { query.domain = entry }
                let decision = document.preview(query)
                guard decision.undecided.isEmpty, let policy = decision.match?.policy else {
                    throw SplitRouteError.invalid("\(entry)에 확정적으로 일치하는 규칙을 확인해 주세요.")
                }
                let cidr = answer.ip + (answer.ip.contains(":") ? "/128" : "/32")
                leases.append(SplitRouteLease(label: entry, cidr: cidr, policy: policy,
                                              networkID: generation, expiresAt: answer.expires))
            }
        }
        guard leases.count <= 256 else { throw SplitRouteError.invalid("한 번에 최대 256개 IP 경로를 검증할 수 있습니다.") }
        let routing = try SplitRoutePlanner.make(leases: leases, networkID: generation)
        guard routing.requiredTransports.contains(.coreaVPN) else { throw ClientIssue.message("CoreaVPN으로 보낼 목적지가 한 개 이상 필요합니다.") }
        var references: [String: Data] = [:]
        for case let .group(group) in routing.requiredTransports {
            references[group] = try ExperimentalProxyStore().reference(for: group)
        }
        let endpoint = try await model.driver.endpoint(chosen)
        let addr: String
        if VPNEndpoints.isPublicIPv4(endpoint) {
            addr = endpoint
        } else {
            let candidates = try await DestinationDNS.addresses(for: chosen)
            guard let answer = candidates.first(where: { VPNEndpoints.isPublicIPv4($0.ip) }) else {
                throw ClientIssue.message("실험 서버의 공인 IPv4 주소를 확인할 수 없습니다.")
            }
            addr = answer.ip
        }
        guard let uplink = SplitUplink.fingerprint(to: addr) else { throw ClientIssue.message("서버까지의 물리 경로를 확인할 수 없습니다.") }
        let account = try model.driver.vpn.credentialHandle()
        guard link == model.link else { throw BenchmarkError.wrongNetwork }
        let cfg = NETunnelProviderProtocol()
        cfg.providerBundleIdentifier = providerID
        cfg.username = account.username
        cfg.passwordReference = account.reference
        cfg.serverAddress = addr
        cfg.enforceRoutes = true
        cfg.includeAllNetworks = false
        cfg.providerConfiguration = ["authentication":"eap-cert","remoteHost":chosen,"networkID":generation,
                                     "uplinkFingerprint":uplink,"groupReferences":references,"leases":try JSONEncoder().encode(leases)]
        let manager = previously ?? NETunnelProviderManager()
        manager.localizedDescription = "CoreaVPN · 경로 실험"
        manager.protocolConfiguration = cfg
        manager.isOnDemandEnabled = false
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.connection.startVPNTunnel()
        let end = Date().addingTimeInterval(SplitRoutePlanner.startupLimit(proxyGroups: references.count))
        while Date() < end {
            try await Task.sleep(nanoseconds: 350_000_000)
            switch manager.connection.status {
            case .connected: text = "\(chosen) 연결 · 검증 경로 \(leases.count)개"; return
            case .invalid,.disconnected: throw ClientIssue.message("실험 터널 연결 실패")
            default: continue
            }
        }
        manager.connection.stopVPNTunnel()
        throw ClientIssue.message("실험 터널 연결 시간이 초과되었습니다.")
    }
}
#endif
