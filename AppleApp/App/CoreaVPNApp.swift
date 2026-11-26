import SwiftUI
import NetworkExtension
#if os(macOS)
import AppKit
import Security
#endif

@main
enum CoreaEntry {
    @MainActor static func main() async {
        #if os(macOS)
        if let action = CommandLine.arguments.dropFirst().first, action.hasPrefix("--pilot-") {
            do {
                let result = try await NativePilot.run(action, arguments: Array(CommandLine.arguments.dropFirst(2)))
                print(String(decoding: try JSONSerialization.data(withJSONObject: result), as: UTF8.self))
                exit(0)
            } catch {
                FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
                exit(1)
            }
        }
        #endif
        CoreaApplication.main()
    }
}

struct CoreaApplication: App {
    var body: some Scene {
        #if os(macOS)
        Window("CoreaVPN", id: "main") { LaunchView() }
            .defaultSize(width: 1100, height: 740)
        #else
        WindowGroup { LaunchView() }
        #endif
    }
}

struct LaunchView: View {
    @State private var session: SessionModel?
    @State private var error: String?
    var body: some View {
        Group {
            if let session { ClientTabs(model: session) }
            else if let error { ContentUnavailableView("기록을 열 수 없습니다", systemImage: "externaldrive.badge.exclamationmark", description: Text(error)) }
            else { ProgressView() }
        }.task {
            guard session == nil, error == nil else { return }
            do { session = try SessionModel() } catch { self.error = error.localizedDescription }
        }
    }
}

struct ClientTabs: View {
    @ObservedObject var model: SessionModel
    #if os(macOS) && DIRECT_ROUTING
    @StateObject private var routing = MacRouting()
    #endif
    @Environment(\.scenePhase) var phase
    var body: some View {
        Group {
            #if os(macOS)
            MacDashboardShell(model: model)
            #else
            mobileTabs
            #endif
        }
        #if os(macOS) && DIRECT_ROUTING
        .environmentObject(model)
        .environmentObject(routing)
        .task {
            do { try await routing.locate() } catch { model.message = error.localizedDescription }
            while !Task.isCancelled {
                routing.refreshBinding(model)
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in routing.refreshBinding(model) }
        #endif
        .task { await model.recover(); await model.refreshStatus() }
        .onReceive(NotificationCenter.default.publisher(for: .NEVPNStatusDidChange)) { _ in
            model.connectedHost = model.driver.vpn.connectedHost
            if model.driver.vpn.currentStatus == .disconnected { model.scheduleOnDemandCheck() }
        }
        .onChange(of: phase) { _, phase in
            model.foreground(phase == .active)
            if phase == .active, !model.busy { Task { await model.refreshStatus() } }
            #if os(iOS)
            if phase == .background, model.work == "scan" {
                // Checkpoints are already on disk. Request only enough runtime to
                // release the current tunnel and restore the previous connection.
                let token = UIApplication.shared.beginBackgroundTask(withName: "Pause CoreaVPN scan")
                Task {
                    await model.pauseScan()
                    if token != .invalid { UIApplication.shared.endBackgroundTask(token) }
                }
            }
            #endif
        }
        #if os(macOS)
        .frame(minWidth: 790, minHeight: 500)
        #endif
    }

    #if !os(macOS)
    private var mobileTabs: some View {
        TabView {
            ConnectionView(model: model).tabItem { Label("연결", systemImage: "network") }
            HistoryView(store: model.store, model: model).tabItem { Label("측정 기록", systemImage: "chart.bar.xaxis") }
            RulesView().tabItem { Label("규칙", systemImage: "arrow.triangle.branch") }
            #if ROUTE_LAB
            ScopedExperiment(model: model).tabItem { Label("터널 실험", systemImage: "point.3.connected.trianglepath.dotted") }
            #endif
            AccountView(model: model).tabItem { Label("설정", systemImage: "gearshape") }
        }
    }
    #endif
}

#if !os(macOS)
struct ConnectionView: View {
    @ObservedObject var model: SessionModel
    @ObservedObject private var store: BenchmarkStore

    init(model: SessionModel) { self.model = model; store = model.store }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label(displayHost ?? "CoreaVPN 연결 해제됨", systemImage: displayHost == nil ? "circle" : "checkmark.circle.fill")
                        .font(.title3.weight(.semibold))
                    if model.link.available {
                        LabeledContent("현재 회선", value: [model.routeLabel, model.link.interface].filter { !$0.isEmpty }.joined(separator: " · "))
                    }
                    if !model.message.isEmpty { Text(model.message).foregroundStyle(.secondary).textSelection(.enabled) }
                }
                Section("서버 연결") {
                    action(model.relayEnabled ? ".net 중계 켜짐 · 주소 갱신" : ".net 주소 중계 켜기", "point.3.connected.trianglepath.dotted") { model.warmResolver() }
                    action("168.126.63.1 100ms 이하 서버 연결", "bolt.horizontal", needsVPN: true) { Task { await model.start(.quick) } }
                    action("전체 테스트 후 최적 서버 연결", "list.number", needsVPN: true) { Task { await model.start(.all) } }
                    Button(role: .destructive) { Task { await model.disconnect() } } label: { Label("CoreaVPN 해제", systemImage: "stop.circle") }
                        .disabled(model.previewBuild || model.shuttingDown || model.stoppingScan || model.work == "permission")
                }
                if store.runs.contains(where: { $0.recoveryNeeded == true }) {
                    Button("중단 당시 연결 상태 복구") { Task { await model.recover() } }.disabled(model.busy)
                }
                if model.work == "lookup" { ProgressView("서버 주소 조회 중", value: Double(model.addresses.count + model.dnsErrors.count), total: 17) }
                if model.work == "scan" {
                    Section {
                        if model.stoppingScan {
                            ProgressView("검사 중지 및 이전 VPN 상태 복구 중")
                        } else if let run = model.active {
                            let finished = run.rows.filter { ![.skipped, .notRun, .stopped].contains($0.outcome) }.count
                            ProgressView(run.activeHost ?? "검사 중", value: Double(finished), total: Double(max(1,run.order.count)))
                        } else {
                            ProgressView("검사 준비 중")
                        }
                        Button("검사 중지", role: .destructive) { Task { await model.stopScan() } }
                            .accessibilityIdentifier("scan-stop")
                        Button("일시 정지") { Task { await model.pauseScan() } }
                    }
                    .disabled(model.stoppingScan || model.shuttingDown || (model.active.map { $0.phase != .scanning } ?? false))
                } else if let pending = store.runs.last(where: model.canResume) {
                    Section { Button("중단한 검사 이어가기") { Task { await model.start(pending.mode, resume: pending.id) } }.disabled(model.busy) }
                }
                Section("서버 \(CoreaServer.catalog.count)개") {
                    ForEach(CoreaServer.catalog) { server in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(server.host).font(.system(.body, design: .monospaced))
                                Spacer()
                                Text(server.group).foregroundStyle(.secondary)
                            }
                            let exclusion = model.exclusion(server)
                            if let status = exclusion ?? model.dnsErrors[server.host] ?? model.addresses[server.host] {
                                Text(status).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }.navigationTitle("CoreaVPN")
        }
    }
    private var displayHost: String? {
        model.connectedHost
    }
    private func action(_ title: String, _ icon: String, needsVPN: Bool = false, go: @escaping () -> Void) -> some View {
        Button(action: go) { Label(title, systemImage: icon) }.disabled(model.busy || !model.link.available || (needsVPN && model.previewBuild))
    }
}

#endif
