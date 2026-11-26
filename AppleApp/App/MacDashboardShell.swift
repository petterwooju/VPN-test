#if os(macOS)
import SwiftUI

enum MacDashboardDestination: String, CaseIterable, Identifiable {
    case dashboard, servers, history, rules, settings
    #if ROUTE_LAB
    case experiment
    #endif

    var id: Self { self }

    var title: String {
        switch self {
        case .dashboard: "대시보드"
        case .servers: "서버 연결"
        case .history: "측정 기록"
        case .rules: "라우팅 규칙"
        case .settings: "설정"
        #if ROUTE_LAB
        case .experiment: "터널 실험"
        #endif
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: "rectangle.grid.2x2"
        case .servers: "server.rack"
        case .history: "chart.bar.xaxis"
        case .rules: "arrow.triangle.branch"
        case .settings: "gearshape"
        #if ROUTE_LAB
        case .experiment: "point.3.connected.trianglepath.dotted"
        #endif
        }
    }
}

struct MacDashboardShell: View {
    @ObservedObject var model: SessionModel
    @StateObject private var quick = LocalQuickSearch()
    @StateObject private var pilot = LocalPilot()
    @State private var destination = MacDashboardDestination.dashboard
    @State private var focusedRuleID: UUID?
    @Environment(\.colorScheme) private var colorScheme

    private let teal = Color(red: 0.08, green: 0.55, blue: 0.51)
    private var selectedInk: Color {
        colorScheme == .dark ? Color(red: 0.57, green: 0.88, blue: 0.82) :
            Color(red: 0.02, green: 0.36, blue: 0.32)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Divider()
            ZStack {
                // Keep the existing measurement and recovery observers mounted across navigation.
                ConnectionView(model: model, quick: quick, pilot: pilot)
                    .opacity(destination == .servers ? 1 : 0)
                    .allowsHitTesting(destination == .servers)
                    .disabled(destination != .servers)
                    .accessibilityHidden(destination != .servers)
                switch destination {
                case .dashboard:
                    MacDashboardView(model: model, quick: quick, pilot: pilot, store: model.store,
                                     navigate: { destination = $0 },
                                     showRule: { focusedRuleID = $0; destination = .rules })
                case .servers: EmptyView()
                case .history: HistoryView(store: model.store, model: model)
                case .rules: RulesView(focusedRuleID: focusedRuleID)
                case .settings: AccountView(model: model)
                #if ROUTE_LAB
                case .experiment: ScopedExperiment(model: model)
                #endif
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .onAppear { if model.previewBuild { pilot.refresh() } }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 33, height: 33)
                    .background(Color(red: 0.07, green: 0.25, blue: 0.29), in: RoundedRectangle(cornerRadius: 9))
                    .accessibilityHidden(true)
                Text("CoreaVPN").font(.system(size: 19, weight: .bold))
            }
            .padding(.leading, 17)
            .padding(.top, 20)
            .padding(.bottom, 26)

            ForEach(MacDashboardDestination.allCases.filter { $0 != .settings }) { item in
                navigationButton(item)
            }
            Spacer(minLength: 16)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 7) {
                    Circle()
                        .fill(connectionHost == nil ? Color.secondary.opacity(0.6) : teal)
                        .frame(width: 7, height: 7)
                    Text(connectionHost ?? activityTitle)
                        .font(.caption)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .help(connectionHost ?? activityTitle)
                sidebarActions.controlSize(.large)
            }
            .padding(.horizontal, 15)
            Divider().padding(.horizontal, 13).padding(.vertical, 9)
            navigationButton(.settings)
                .padding(.bottom, 10)
        }
        .frame(width: 192)
        .frame(maxHeight: .infinity)
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var connectionHost: String? {
        model.previewBuild ? quick.retainedHost : model.connectedHost
    }

    private var activityTitle: String {
        if model.previewBuild {
            if quick.phase == "recovering" && quick.running { return "FlClash 복구 중" }
            if quick.running || pilot.running { return "검사 진행 중" }
            if quick.canRelease { return "복구 필요" }
        } else if model.work == "scan" {
            return "검사 진행 중"
        }
        return "VPN 연결 해제됨"
    }

    private func navigationButton(_ item: MacDashboardDestination) -> some View {
        let selected = destination == item
        return Button {
            if item == .rules { focusedRuleID = nil }
            destination = item
        } label: {
            HStack(spacing: 11) {
                Image(systemName: item.symbol)
                    .font(.system(size: 15, weight: .medium))
                    .frame(width: 22)
                Text(item.title).font(.system(size: 14, weight: selected ? .semibold : .medium))
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 11)
            .frame(height: 43)
            .contentShape(Rectangle())
            .foregroundStyle(selected ? selectedInk : .primary)
            .background(selected ? teal.opacity(0.14) : .clear, in: RoundedRectangle(cornerRadius: 7))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 9)
        .padding(.bottom, 3)
        .accessibilityIdentifier("nav-" + item.rawValue)
        .accessibilityLabel(item.title)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    @ViewBuilder private var sidebarActions: some View {
        if model.previewBuild && (quick.running || quick.canRelease) {
            Button(quick.releaseButtonTitle) { quick.release() }
                .disabled(!quick.canRelease)
                .accessibilityIdentifier("sidebar-quick-release")
        } else if model.previewBuild && pilot.running {
            Button("검사 중지") { pilot.stopMeasurement() }
                .disabled(!pilot.canStop)
                .accessibilityIdentifier("sidebar-puma-stop")
        } else if !model.previewBuild && model.work == "scan" {
            Button("검사 중지") { Task { await model.stopScan() } }
                .disabled(model.stoppingScan || model.shuttingDown)
        } else if !model.previewBuild && model.connectedHost != nil {
            Button("CoreaVPN 해제") { Task { await model.disconnect() } }
                .disabled(model.stoppingScan || model.shuttingDown || model.work == "permission")
        }
    }
}
#endif
