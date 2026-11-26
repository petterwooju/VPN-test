#if os(macOS)
import AppKit
import SwiftUI

struct ConnectionView: View {
    @ObservedObject var model: SessionModel
    @ObservedObject private var store: BenchmarkStore
    @ObservedObject var quick: LocalQuickSearch
    @ObservedObject var pilot: LocalPilot
    @State private var comparing = false
    @State private var directExpanded = true
    @State private var importMessage = ""

    init(model: SessionModel, quick: LocalQuickSearch, pilot: LocalPilot) {
        self.model = model
        self.store = model.store
        self.quick = quick
        self.pilot = pilot
    }

    private var blocked: Bool {
        if model.busy || !model.link.available || model.network.label.isEmpty { return true }
        if model.previewBuild { return !quick.available || quick.running || quick.canRelease || pilot.running }
        return false
    }

    private var activeComparison: BenchmarkRun? {
        store.runs.last(where: { $0.mode == .all && $0.paired == true && $0.network == model.network })
    }
    private var comparisonID: UUID? {
        if model.previewBuild { return quick.comparisonNetwork == model.network ? quick.comparisonID : nil }
        return activeComparison?.id
    }
    private var showComparison: Bool { comparing && comparisonID != nil }
    private var comparisonTitle: String {
        let count = model.previewBuild ? quick.comparisonHostCount : activeComparison?.order.count ?? 0
        return count == CoreaServer.catalog.count ? "전체 검사 결과" : "최근 비교 결과 · \(count)개"
    }
    private var connectedHost: String? { model.previewBuild ? quick.retainedHost : model.connectedHost }
    private var canConnectDirect: Bool { model.canConnectMacServer(quick: quick, pilot: pilot) }
    private var comparisonReady: Bool {
        if model.previewBuild { return quick.comparisonReady && quick.comparisonNetwork == model.network }
        return activeComparison?.phase == .completed && activeComparison?.recoveryNeeded != true
    }
    private var recentResults: [BenchmarkAttempt] {
        var latest = [String: BenchmarkAttempt]()
        let stored = store.runs.filter { $0.network == model.network && $0.mode != .direct }.flatMap(\.rows)
        let current = model.previewBuild ? quick.results : []
        for row in stored + current where ![.skipped, .notRun, .stopped].contains(row.outcome) {
            if latest[row.host].map({ $0.time <= row.time }) ?? true {
                latest[row.host] = row
            }
        }
        return Array(latest.values)
    }
    private var comparisonRows: [BenchmarkAttempt] {
        guard model.previewBuild else { return activeComparison?.rows ?? [] }
        let savedRows = store.runs.first { $0.id == quick.comparisonID }?.rows ?? []
        return quick.comparisonRows.map { attempt in
            var row = attempt
            row.selectionError = row.host == quick.failedSelectionHost ? quick.selectionFailure :
                savedRows.first(where: { $0.host == row.host })?.selectionError
            return row
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            controls
            Divider()
            List {
                DirectServerGrid(expanded: $directExpanded, enabled: canConnectDirect,
                                 connectedHost: connectedHost, connect: connectDirect)
                MacServerDirectory(rows: showComparison ? comparisonRows : recentResults, comparing: showComparison,
                    activeHost: model.previewBuild ? quick.activeHost : model.active?.activeHost,
                    selectedHost: showComparison ? store.runs.first(where: { $0.id == comparisonID })?.selectedHost : connectedHost,
                    canConnect: canConnectDirect && (!showComparison || comparisonReady),
                    addresses: model.addresses, dnsErrors: model.dnsErrors, connect: connect)
                if model.previewBuild {
                    LocalPilotSection(model: model, pilot: pilot).disabled(quick.running || quick.canRelease)
                }
            }
            .listStyle(.inset)
        }
        .controlSize(.large)
        .onChange(of: showComparison) { _, showing in directExpanded = !showing }
        .onChange(of: comparisonID) { _, id in
            if id != nil && (quick.running || model.work == "scan") { comparing = true }
        }
        .onAppear {
            if model.previewBuild { quick.refresh(); saveCompleted() }
        }
        .onChange(of: quick.running) { _, running in if !running { saveCompleted() } }
        .onChange(of: quick.retainedHost) { _, host in if host != nil { saveCompleted() } }
        .onChange(of: quick.phase) { _, _ in saveCompleted() }
        .onChange(of: quick.recoveryVerified) { _, recovered in if recovered { saveCompleted() } }
    }

    private var controls: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("서버 연결").font(.title2.weight(.semibold))
                Spacer()
                if let host = connectedHost {
                    Label(host, systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green).lineLimit(1).truncationMode(.head)
                }
            }

            HStack(spacing: 6) {
                scanButton("168.126.63.1 100ms 이하 서버 연결", shortTitle: "Ping ≤ 100ms", icon: "waveform.path.ecg",
                           id: "quick-start", mode: .quick)
                scanButton(HTTPSBenchmarkSample.quickConnectionTitle, shortTitle: "FAST ≥ 50 Mbps", icon: "arrow.down.circle",
                           id: "quick-fast-start", mode: .fastQuick)
                scanButton("전체 테스트 후 서버 선택", shortTitle: "\(CoreaServer.catalog.count)개 전체 검사", icon: "list.number",
                           id: "comparison-start", mode: .all)
                Spacer(minLength: 0)
                Menu {
                    Button(model.relayEnabled ? ".net 주소 갱신" : ".net 주소 중계 켜기") { model.warmResolver() }
                        .disabled(model.busy || !model.link.available || (model.previewBuild && (quick.running || pilot.running)))
                    if let run = quick.latestDirectory, model.previewBuild {
                        Button("검사 기록 열기") { NSWorkspace.shared.open(run) }
                    }
                    if !model.previewBuild {
                        if store.runs.contains(where: { $0.recoveryNeeded == true }) {
                            Button("중단 당시 연결 상태 복구") { Task { await model.recover() } }.disabled(model.busy)
                        }
                        if model.work == "scan" {
                            Button("일시 정지") { Task { await model.pauseScan() } }.disabled(model.stoppingScan)
                        } else if let pending = store.runs.last(where: model.canResume) {
                            Button("중단한 검사 이어가기") { Task { await model.start(pending.mode, resume: pending.id) } }
                                .disabled(model.busy)
                        }
                    }
                } label: { Image(systemName: "ellipsis.circle").accessibilityLabel("추가 작업") }
                .fixedSize()
            }

            operationStatus
            if comparisonID != nil {
                Picker("서버 목록", selection: $comparing) {
                    Text("바로 연결").tag(false)
                    Text(comparisonTitle).tag(true)
                }.pickerStyle(.segmented).labelsHidden().fixedSize()
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 13)
        .background(.background)
    }

    private func scanButton(_ title: String, shortTitle: String, icon: String, id: String, mode: ScanMode) -> some View {
        Button { start(mode) } label: {
            ViewThatFits(in: .horizontal) {
                Label(title, systemImage: icon)
                Label(shortTitle, systemImage: icon)
            }.lineLimit(1)
        }
        .buttonStyle(.bordered)
        .controlSize(.large)
        .help(title).accessibilityLabel(title).accessibilityIdentifier(id)
        .disabled(blocked || (mode != .all && model.candidates.isEmpty))
    }

    @ViewBuilder private var operationStatus: some View {
        if model.previewBuild, quick.running || quick.canRelease {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    if let progress = quick.comparisonProgress, quick.phase == "searching", quick.canRelease {
                        ProgressView(value: Double(progress.finished), total: Double(progress.total)) {
                            Text(quick.status)
                        }.frame(maxWidth: 475)
                    } else {
                        Text(quick.status).textSelection(.enabled)
                    }
                }
                Spacer(minLength: 4)
                QuickReleaseButton(title: quick.releaseButtonTitle, enabled: quick.canRelease) { quick.release() }
                    .frame(width: 176, height: 32)
            }.font(.callout)
        } else if !model.previewBuild, model.work == "scan" {
            HStack {
                if model.stoppingScan {
                    ProgressView("검사 중지 및 이전 VPN 상태 복구 중")
                } else if let run = model.active, run.phase == .scanning {
                    let finished = run.rows.filter { ![.skipped, .notRun, .stopped].contains($0.outcome) }.count
                    ProgressView(value: Double(finished), total: Double(max(1, run.order.count))) {
                        Text("\(finished)/\(run.order.count) · \(run.activeHost ?? "결과 확인 중")")
                    }.frame(maxWidth: 475)
                } else {
                    ProgressView("검사 준비 중")
                }
                Spacer(minLength: 4)
                Button("검사 중지", role: .destructive) { Task { await model.stopScan() } }
                    .disabled(model.stoppingScan || model.shuttingDown || (model.active.map { $0.phase != .scanning } ?? false))
                    .accessibilityIdentifier("scan-stop")
            }.font(.callout)
        } else {
            if !model.previewBuild, connectedHost != nil {
                Button("CoreaVPN 해제", role: .destructive) { Task { await model.disconnect() } }
                    .disabled(model.shuttingDown || model.work == "permission")
            }
            if model.work == "lookup" {
                ProgressView("서버 주소 조회 중", value: Double(model.addresses.count + model.dnsErrors.count), total: 17)
            }
            if model.network.label.isEmpty {
                Text("설정에서 현재 회선 이름을 입력하세요.").font(.caption).foregroundStyle(.secondary)
            }
            if model.previewBuild && !quick.available {
                Text("이 Mac의 검사 도구와 FlClash 설정을 확인하세요.").font(.caption).foregroundStyle(.secondary)
            }
            let note = model.previewBuild ? (quick.status.isEmpty ? model.message : quick.status) : model.message
            if !note.isEmpty {
                Text(note).font(.callout).foregroundStyle(.secondary).lineLimit(3).help(note).textSelection(.enabled)
            }
            if !importMessage.isEmpty {
                Text(importMessage).font(.caption).foregroundStyle(.secondary)
            }
            if showComparison {
                Text(comparisonReady ? "복구 완료 · 결과를 보고 연결할 서버를 선택하세요." : "검사와 복구가 끝나면 서버를 선택할 수 있습니다.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            if !model.previewBuild, !NSRunningApplication.runningApplications(withBundleIdentifier: "com.follow.clash").isEmpty,
               let guardian = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "net.petterwooju.coreavpn.preview") {
                Button("FlClash 자동 복구가 있는 검사 앱 열기") {
                    NSWorkspace.shared.openApplication(at: guardian, configuration: .init()) { _, error in
                        if let error { Task { @MainActor in model.message = error.localizedDescription } }
                    }
                }.disabled(model.busy)
            }
        }
    }

    private func start(_ mode: ScanMode) {
        importMessage = ""
        if model.previewBuild {
            if mode == .all {
                if quick.startAll(network: model.network) { comparing = true }
            } else {
                let method: LocalMeasurement = mode == .fastQuick ? .https : .icmp
                let candidates = model.candidates.map(\.host)
                let ranked = method == .https ? store.httpsRankings(for: model.network).map(\.host) :
                    store.rankings(for: model.network).filter { $0.received > 0 }.map(\.host)
                var seen = Set<String>()
                let hosts = (["leo.coreavpn.net"] + ranked + candidates).filter { candidates.contains($0) && seen.insert($0).inserted }
                if quick.start(hosts: hosts, network: model.network, measurement: method) { comparing = false }
            }
        } else {
            comparing = mode == .all
            Task { await model.start(mode) }
        }
    }

    private func connect(_ server: CoreaServer) {
        guard showComparison else { connectDirect(server); return }
        guard canConnectDirect, comparisonReady else { return }
        importMessage = ""
        if model.previewBuild {
            do {
                if try !quick.select(host: server.host, network: model.network, store: store) {
                    importMessage = "현재 검사에서 이 서버를 선택할 수 없습니다."
                }
            } catch { importMessage = error.localizedDescription }
        } else {
            Task { await model.connectSelected(host: server.host, in: activeComparison) }
        }
    }

    private func connectDirect(_ server: CoreaServer) {
        guard canConnectDirect else { return }
        importMessage = ""
        model.connectMacServer(server, quick: quick, pilot: pilot)
    }

    private func saveCompleted() {
        guard model.previewBuild else { return }
        do {
            _ = try quick.updateImportedScope(in: store)
            if try quick.importCompleted(into: store) { importMessage = "이 회선의 측정 기록에 저장했습니다." }
        } catch { importMessage = error.localizedDescription }
    }
}

extension SessionModel {
    func canConnectMacServer(quick: LocalQuickSearch, pilot: LocalPilot) -> Bool {
        guard !busy, link.available, !network.label.isEmpty else { return false }
        if previewBuild {
            return quick.retainedHost == nil && quick.available && !quick.running && !quick.canRelease && !pilot.running
        }
        return connectedHost == nil && !store.runs.contains { $0.recoveryNeeded == true }
    }

    func connectMacServer(_ server: CoreaServer, quick: LocalQuickSearch, pilot: LocalPilot) {
        guard canConnectMacServer(quick: quick, pilot: pilot) else { return }
        if previewBuild {
            quick.connectDirect(server, network: network)
        } else {
            Task { await connectSelected(host: server.host) }
        }
    }
}
#endif
