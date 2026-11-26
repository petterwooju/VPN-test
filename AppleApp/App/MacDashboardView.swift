#if os(macOS)
import SwiftUI

struct MacDashboardView: View {
    @ObservedObject var model: SessionModel
    @ObservedObject var quick: LocalQuickSearch
    @ObservedObject var pilot: LocalPilot
    @ObservedObject var store: BenchmarkStore
    let navigate: (MacDashboardDestination) -> Void
    let showRule: (UUID) -> Void
    @StateObject private var metrics = MacDashboardMetrics()
    @State private var proxyGroups: [RoutingGroup] = []
    @State private var reconnectTarget: String?
    @Environment(\.scenePhase) private var scenePhase
    #if DIRECT_ROUTING
    @EnvironmentObject private var routing: MacRouting
    #endif

    private let teal = Color(red: 0.10, green: 0.57, blue: 0.52)
    private let blue = Color(red: 0.27, green: 0.45, blue: 0.79)
    private var host: String? { model.previewBuild ? quick.retainedHost : model.connectedHost }
    private var recovering: Bool {
        (quick.running && quick.phase == "recovering") || (pilot.running && pilot.latest?.recovering == true)
    }
    private var quickActive: Bool { model.previewBuild && (quick.running || quick.canRelease) }
    private var lastServer: CoreaServer? {
        let stored = store.latestServerConnection(deviceID: model.deviceID)
        guard model.previewBuild, let local = quick.lastConnection else { return stored?.server }
        return [local, stored].compactMap { $0 }.max { $0.date < $1.date }?.server
    }
    private var networkTitle: String {
        if !model.routeLabel.isEmpty { return model.routeLabel }
        switch model.link.transport {
        case "ethernet": return "유선 네트워크"
        case "wifi": return "Wi-Fi"
        default: return model.link.available ? "현재 네트워크" : "회선 연결 안 됨"
        }
    }
    private var mode: String {
        #if DIRECT_ROUTING
        if routing.enabled { return "규칙 사용 설정됨" }
        #endif
        return model.previewBuild ? "로컬 VPN 프로필" : "시스템 IKEv2"
    }
    private var samplerInterface: String? {
        guard scenePhase == .active else { return nil }
        return model.link.available ? model.link.interface : ""
    }

    var body: some View {
        GeometryReader { bounds in
            ScrollView {
                let wide = bounds.size.width >= 880
                let compact = bounds.size.width < 770 || bounds.size.height < 790
                let contentWidth = min(1480, bounds.size.width) - (compact ? 32 : 42)
                VStack(alignment: .leading, spacing: 15) {
                    header
                    overview(width: contentWidth, compact: compact)
                    if let notice = recoveryNotice, !notice.isEmpty {
                        Label(notice, systemImage: "exclamationmark.triangle")
                            .font(.callout).foregroundStyle(.orange).textSelection(.enabled)
                    }
                    networkControls(width: contentWidth)
                    networkCards(compact: compact)
                    activityCards(proxyWidth: wide ? contentWidth * 0.38 : nil,
                                  height: min(470, max(195, bounds.size.height - 580)))
                }
                .padding(compact ? 16 : 21)
                .frame(maxWidth: 1480)
                .frame(maxWidth: .infinity)
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
        .controlSize(.large)
        .task {
            if let data = try? Data(contentsOf: RulesView.storage),
               let rules = try? RoutingDocument.decode(data) {
                proxyGroups = rules.groups
            }
        }
        .task(id: samplerInterface) {
            if let samplerInterface { await metrics.observe(interface: samplerInterface) }
        }
    }

    private var connectionTitle: String {
        if recovering { return "FlClash 복구 중" }
        if model.shuttingDown { return "VPN 해제 중" }
        if let host { return host }
        if quickActive {
            if !quick.running { return "FlClash 복구 필요" }
            return quick.activeHost.map { "작업 중 · " + $0 } ?? "연결 준비 중"
        }
        if pilot.running { return "Puma 검사 중" }
        if model.work == "scan" { return model.active?.activeHost.map { "검사 중 · " + $0 } ?? "검사 중" }
        if model.work == "selection", let reconnectTarget { return reconnectTarget + " 연결 중" }
        if model.work == "recovery" { return "네트워크 복구 중" }
        return "CoreaVPN 연결 해제됨"
    }

    private var recoveryNotice: String? {
        if model.previewBuild {
            if quick.canRelease && !quick.running { return quick.status }
            if !pilot.running && pilot.latest?.recovered == false { return pilot.status }
        }
        if model.store.runs.contains(where: { $0.recoveryNeeded == true }) && !model.busy {
            return "중단된 검사의 네트워크 상태를 복구하세요."
        }
        return nil
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            Text("대시보드").font(.system(size: 26, weight: .bold))
            Spacer()
            let line = [networkTitle, model.link.interface].filter { !$0.isEmpty }.joined(separator: " · ")
            Label(line, systemImage: model.link.transport == "wifi" ? "wifi" : "network")
                .font(.callout).foregroundStyle(.secondary).lineLimit(1).help(line)
        }
    }

    private func overview(width: CGFloat, compact: Bool) -> some View {
        let height: CGFloat = compact ? 174 : 202
        let gap: CGFloat = 14
        let statusWidth = (width - gap * 2) / 2
        return HStack(spacing: gap) {
            statusCard(compact: compact)
                .frame(width: statusWidth, height: height)
                .dashboardPanel()
            trafficCard(upload: true, height: height)
            trafficCard(upload: false, height: height)
        }
    }

    private func statusCard(compact: Bool) -> some View {
        HStack(spacing: compact ? 9 : 16) {
            VStack(alignment: .leading, spacing: 12) {
                Label("상태", systemImage: "waveform.path")
                    .font(.callout.weight(.semibold)).foregroundStyle(.secondary)
                Text(connectionTitle).font(.system(size: compact ? 19 : 25, weight: .bold))
                    .lineLimit(2).truncationMode(.middle).help(connectionTitle)
                Spacer(minLength: 1)
                if host == nil, !quickActive, !pilot.running, let lastServer {
                    Text("최근 연결 · " + lastServer.host)
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        .help(lastServer.host)
                } else {
                    Text(model.previewBuild ? "CoreaVPN_TEST · IKEv2" : "CoreaVPN · IKEv2")
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                }
                if let reconnectTarget, host == nil, !model.busy, !quickActive {
                    let message = model.previewBuild ? quick.status : model.message
                    if !message.isEmpty {
                        Text(message).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                            .help(reconnectTarget + " · " + message)
                    }
                }
            }
            Spacer(minLength: 0)
            connectionAction(diameter: compact ? 80 : 94)
                .frame(width: compact ? 85 : 105)
        }
        .padding(compact ? 13 : 20)
    }

    @ViewBuilder private func connectionAction(diameter: CGFloat) -> some View {
        if quickActive {
            if recovering || !quick.canRelease {
                VStack(spacing: 7) {
                    ProgressView().controlSize(.regular)
                    Text(quick.releaseButtonTitle).font(.caption).lineLimit(2).multilineTextAlignment(.center)
                }.foregroundStyle(.secondary)
            } else if !quick.running {
                powerButton("복구 재시도", symbol: "arrow.clockwise", diameter: diameter) { quick.release() }
            } else {
                powerButton(host != nil ? "연결 해제" : "검사 중지", symbol: "stop.fill", diameter: diameter) { quick.release() }
            }
        } else if pilot.running {
            powerButton("검사 중지", symbol: "stop.fill", diameter: diameter, disabled: !pilot.canStop) { pilot.stopMeasurement() }
        } else if !model.previewBuild && model.work == "scan" {
            powerButton("검사 중지", symbol: "stop.fill", diameter: diameter, disabled: model.stoppingScan || model.shuttingDown) {
                Task { await model.stopScan() }
            }
        } else if !model.previewBuild && (host != nil || model.shuttingDown) {
            powerButton("연결 해제", symbol: "stop.fill", diameter: diameter, disabled: model.shuttingDown || model.work == "permission") {
                Task { await model.disconnect() }
            }
        } else if model.store.runs.contains(where: { $0.recoveryNeeded == true }) && !model.busy {
            powerButton("네트워크 복구", symbol: "arrow.clockwise", diameter: diameter) { Task { await model.recover() } }
        } else if let lastServer {
            VStack(spacing: 5) {
                powerButton("서버 바로 연결", symbol: "play.fill", diameter: diameter,
                            disabled: !model.canConnectMacServer(quick: quick, pilot: pilot)) {
                    reconnectTarget = lastServer.host
                    model.connectMacServer(lastServer, quick: quick, pilot: pilot)
                }
                .help(lastServer.host + "에 바로 연결")
                .accessibilityIdentifier("dashboard-reconnect")
                Button("서버 선택") { navigate(.servers) }.buttonStyle(.link)
                    .accessibilityIdentifier("dashboard-server-selection")
            }
        } else {
            powerButton("서버 선택", symbol: "play.fill", diameter: diameter) { navigate(.servers) }
                .accessibilityIdentifier("dashboard-server-selection")
        }
    }

    private func powerButton(_ name: String, symbol: String, diameter: CGFloat, disabled: Bool = false,
                             action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 7) {
                Image(systemName: symbol)
                    .font(.system(size: 22, weight: .semibold)).foregroundStyle(.white)
                    .frame(width: diameter, height: diameter)
                    .background(disabled ? Color.secondary : teal, in: Circle())
                Text(name).font(.callout.weight(.medium)).lineLimit(2).multilineTextAlignment(.center)
            }
            .contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(disabled).accessibilityLabel(name)
    }

    private func trafficCard(upload: Bool, height: CGFloat) -> some View {
        let color = upload ? blue : teal
        let rate = upload ? metrics.uploadBytesPerSecond : metrics.downloadBytesPerSecond
        let maximum = metrics.traffic.map { upload ? $0.uploadBytesPerSecond : $0.downloadBytesPerSecond }.max()
        return VStack(alignment: .leading, spacing: 9) {
            Label(upload ? "업로드" : "다운로드", systemImage: upload ? "arrow.up" : "arrow.down")
                .font(.callout.weight(.semibold)).foregroundStyle(color)
            Text(rate.map(Self.rate) ?? "—")
                .font(.system(size: 29, weight: .bold)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.68)
            Text("최고 " + (maximum.map(Self.rate) ?? "—"))
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            TrafficSparkline(points: metrics.traffic, upload: upload, color: color)
                .frame(maxHeight: .infinity).accessibilityHidden(true)
            Text("회선 전체 · 최근 60초").font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading).frame(height: height)
        .dashboardPanel()
    }

    private func networkControls(width: CGFloat) -> some View {
        HStack(spacing: 12) {
            HStack(spacing: 9) {
                controlIcon("arrow.triangle.branch", color: .indigo)
                VStack(alignment: .leading, spacing: 3) {
                    Text("아웃바운드 모드").font(.callout.weight(.semibold))
                    Text(mode).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer(minLength: 0)
                Button("규칙 보기") { navigate(.rules) }.buttonStyle(.bordered)
            }
            .padding(.horizontal, 11).frame(width: (width - 24) / 2, height: 58)
            .dashboardPanel(radius: 24)
            let proxy = metrics.proxyServices.map { !$0.isEmpty }
            controlStatus("시스템 프록시", detail: metrics.proxyServices?.joined(separator: " · ") ?? "",
                          active: proxy, icon: "arrow.left.arrow.right", tint: teal)
            let tunnel = metrics.routeInterface.map(TunnelProbe.isTunnel)
            controlStatus("TUN", detail: metrics.routeInterface ?? "",
                          active: tunnel, icon: "shield", tint: blue)
        }
    }

    private func controlStatus(_ title: String, detail: String, active: Bool?, icon: String, tint: Color) -> some View {
        HStack(spacing: 8) {
            controlIcon(icon, color: tint)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.callout.weight(.semibold)).lineLimit(1)
                Text(detail.isEmpty ? (active == false ? "꺼짐" : "확인 중") : detail)
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 1)
            if let active {
                Image(systemName: active ? "checkmark.circle.fill" : "minus.circle.fill")
                    .foregroundStyle(active ? tint : .secondary)
                    .accessibilityLabel(active ? "켜짐" : "꺼짐")
            }
        }
        .padding(.horizontal, 10).frame(maxWidth: .infinity, alignment: .leading).frame(height: 58)
        .dashboardPanel(radius: 24)
    }

    private func controlIcon(_ symbol: String, color: Color) -> some View {
        Image(systemName: symbol).font(.callout.weight(.semibold)).foregroundStyle(color)
            .frame(width: 29, height: 29).background(color.opacity(0.13), in: Circle())
            .accessibilityHidden(true)
    }

    private func networkCards(compact: Bool) -> some View {
        let height: CGFloat = compact ? 114 : 142
        return HStack(spacing: 12) {
            tile("내부망 IP", metrics.localIPv4 ?? "—", model.link.interface, "network", height: height)
            tile("프로필", model.previewBuild ? "CoreaVPN_TEST" : "CoreaVPN", "IKEv2", "person.text.rectangle", height: height) {
                Button("주소 관리") { navigate(.servers) }.buttonStyle(.bordered)
            }
            tile("서비스 상태", metrics.flClashRunning ? "FlClash 실행 중" : "FlClash 종료됨",
                 model.relayEnabled ? ".net 조회 \(model.addresses.count)/17" : ".net 주소 중계 꺼짐", "bolt.horizontal", height: height)
            tile("메모리 정보", metrics.memoryBytes.map { ByteCountFormatter.string(fromByteCount: $0, countStyle: .memory) } ?? "—",
                 "CoreaVPN 앱 사용량", "memorychip", height: height)
        }
    }

    @ViewBuilder private func activityCards(proxyWidth: CGFloat?, height: CGFloat) -> some View {
        let activity = DashboardActivity(model: model, store: model.store, listHeight: height,
                                         navigate: navigate, showRule: showRule)
        if let proxyWidth {
            HStack(alignment: .top, spacing: 14) {
                activity.layoutPriority(1)
                proxyCard.frame(width: proxyWidth)
            }
        } else {
            activity
            proxyCard
        }
    }

    private var proxyCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("프록시 그룹", systemImage: "square.3.layers.3d")
                    .font(.headline)
                Spacer()
                Text(proxyGroups.count.formatted()).font(.caption.weight(.semibold)).monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            if proxyGroups.isEmpty {
                Text("가져온 프록시 그룹이 없습니다.").font(.callout).foregroundStyle(.secondary)
            } else {
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 7), count: 2), spacing: 7) {
                    ForEach(proxyGroups.prefix(6), id: \.name) { group in
                        HStack(spacing: 6) {
                            Image(systemName: "point.3.connected.trianglepath.dotted").foregroundStyle(teal)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(group.name).font(.callout.weight(.medium)).lineLimit(1).help(group.name)
                                Text(group.type).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }.padding(7).frame(maxWidth: .infinity, alignment: .leading)
                         .background(.primary.opacity(0.045), in: RoundedRectangle(cornerRadius: 10))
                    }
                }
            }
            Button("라우팅 규칙 열기") { navigate(.rules) }.buttonStyle(.bordered)
        }
        .padding(15).frame(maxWidth: .infinity, alignment: .leading).dashboardPanel()
    }

    private static func rate(_ bytes: Double) -> String {
        if bytes >= 1_000_000 { return String(format: "%.1f MB/s", bytes / 1_000_000) }
        if bytes >= 1_000 { return String(format: "%.1f kB/s", bytes / 1_000) }
        return String(format: "%.0f B/s", bytes)
    }

    private func tile(_ title: String, _ value: String, _ detail: String, _ symbol: String, height: CGFloat) -> some View {
        tile(title, value, detail, symbol, height: height) { EmptyView() }
    }

    private func tile<Accessory: View>(_ title: String, _ value: String, _ detail: String, _ symbol: String, height: CGFloat,
                                      @ViewBuilder accessory: () -> Accessory) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Label(title, systemImage: symbol).font(.callout.weight(.semibold)).foregroundStyle(.secondary).lineLimit(1)
            Text(value).font(.system(size: 20, weight: .bold)).lineLimit(1).minimumScaleFactor(0.65).help(value)
            Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            Spacer(minLength: 0)
            accessory()
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading).frame(height: height).dashboardPanel()
    }
}

private extension View {
    func dashboardPanel(radius: CGFloat = 26) -> some View {
        background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: radius))
            .overlay { RoundedRectangle(cornerRadius: radius).strokeBorder(.primary.opacity(0.07)) }
    }
}

private struct TrafficSparkline: View {
    let points: [MacDashboardMetrics.TrafficPoint]
    let upload: Bool
    let color: Color

    var body: some View {
        Canvas { context, size in
            let bottom = size.height - 2
            for y in [bottom * 0.5, bottom] {
                var line = Path()
                line.move(to: CGPoint(x: 0, y: y))
                line.addLine(to: CGPoint(x: size.width, y: y))
                context.stroke(line, with: .color(.secondary.opacity(0.20)), style: StrokeStyle(lineWidth: 0.6, dash: [3, 3]))
            }
            guard let last = points.last else { return }
            let values = points.map { upload ? $0.uploadBytesPerSecond : $0.downloadBytesPerSecond }
            let peak = max(values.max() ?? 0, 1)
            var path = Path()
            var firstX: CGFloat = 0
            for (index, sample) in points.enumerated() {
                let x = size.width * max(0, 1 - last.date.timeIntervalSince(sample.date) / 60)
                let point = CGPoint(x: x, y: bottom - values[index] / peak * (bottom - 3))
                if index == 0 { path.move(to: point); firstX = x } else { path.addLine(to: point) }
            }
            var area = path
            area.addLine(to: CGPoint(x: size.width, y: bottom))
            area.addLine(to: CGPoint(x: firstX, y: bottom))
            area.closeSubpath()
            context.fill(area, with: .color(color.opacity(0.14)))
            context.stroke(path, with: .color(color), style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
        }
    }
}

private struct DashboardActivity: View {
    @ObservedObject var model: SessionModel
    @ObservedObject var store: BenchmarkStore
    let listHeight: CGFloat
    let navigate: (MacDashboardDestination) -> Void
    let showRule: (UUID) -> Void
    private enum Tab: String, CaseIterable {
        case live = "실시간 연결"
        case recent = "최근 서버 측정"
        case dns = "CoreaVPN DNS 조회"
    }
    @State private var tab = Tab.live

    private var recent: [BenchmarkAttempt] {
        store.runs.filter { $0.network == model.network && $0.mode != .direct }
            .flatMap(\.rows).filter { $0.sample != nil || $0.httpsSample != nil || $0.outcome == .failed }
            .sorted { $0.time > $1.time }.prefix(4).map { $0 }
    }
    private var dnsHosts: [String] { Set(model.addresses.keys).union(model.dnsErrors.keys).sorted() }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                HStack(spacing: 6) {
                    ForEach(Tab.allCases, id: \.self) { item in
                        Button { tab = item } label: {
                            Text(item.rawValue).font(.callout.weight(.semibold)).lineLimit(1)
                                .padding(.horizontal, 12).frame(minHeight: 35)
                                .contentShape(Rectangle())
                                .background(item == tab ? Color.accentColor.opacity(0.20) : .primary.opacity(0.065),
                                            in: RoundedRectangle(cornerRadius: 10))
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(item == tab ? .isSelected : [])
                    }
                }
                Spacer()
                if tab != .live {
                    Button(tab == .dns ? "서버 주소 관리" : "전체 기록") { navigate(tab == .dns ? .servers : .history) }
                        .buttonStyle(.bordered)
                }
            }
            Divider()
            if tab == .live {
                MacLiveConnectionsView(listHeight: listHeight, showRule: showRule)
            } else if tab == .dns {
                if dnsHosts.isEmpty {
                    Text("현재 회선에서 조회한 .net 주소가 없습니다.").foregroundStyle(.secondary).padding(.vertical, 7)
                } else {
                    ForEach(dnsHosts, id: \.self) { host in
                        LabeledContent(host, value: model.addresses[host] ?? model.dnsErrors[host] ?? "—")
                    }
                }
            } else if recent.isEmpty {
                Text("현재 회선에 저장된 측정 기록이 없습니다.").foregroundStyle(.secondary).padding(.vertical, 7)
            } else {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                    GridRow {
                        Text("서버"); Spacer().gridCellUnsizedAxes(.horizontal); Text("Ping 평균"); Text("FAST 다운로드"); Text("측정 시각")
                    }.font(.caption).foregroundStyle(.secondary)
                    ForEach(Array(recent.enumerated()), id: \.offset) { _, row in
                        GridRow {
                            Text(row.host).lineLimit(1).truncationMode(.middle)
                            Spacer(minLength: 0)
                            Text(row.sample?.meanMS.map { String(format: "%.1f ms", $0) } ?? "—")
                            Text(row.httpsSample?.downloadMbps.map { String(format: "%.1f Mbps", $0) } ?? (row.downloadFailed ? "측정 실패" : "—"))
                            Text(row.time, format: .dateTime.month().day().hour().minute())
                        }.font(.callout).monospacedDigit()
                    }
                }.textSelection(.enabled)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading).dashboardPanel()
    }
}
#endif
