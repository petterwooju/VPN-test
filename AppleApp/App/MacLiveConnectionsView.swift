#if os(macOS)
import SwiftUI

private enum LiveSource: String, CaseIterable, Identifiable {
    #if DIRECT_ROUTING
    case provider = "CoreaVPN 라우팅 확장"
    #endif
    case sockets = "Mac 소켓"
    case clash = "FlClash 컨트롤러"
    var id: Self { self }
}

private struct ControllerSettings: Equatable {
    let port: UInt16
    let token: String
}

struct MacLiveConnectionsView: View {
    let listHeight: CGFloat
    let showRule: (UUID) -> Void
    #if DIRECT_ROUTING
    @EnvironmentObject private var routing: MacRouting
    #endif
    @State private var source = LiveSource.sockets
    @Environment(\.scenePhase) private var scenePhase
    @State private var controller: ControllerSettings?
    @State private var configuring = false
    @State private var filter = ""
    @State private var expandedApps = Set<String>()
    @State private var snapshot: LiveConnectionSnapshot?
    @State private var snapshotSource: LiveSource?
    @State private var snapshotController: ControllerSettings?
    @State private var sampleDate: Date?
    @State private var problem: String?

    private struct PollKey: Equatable {
        let source: LiveSource
        let active: Bool
        let controller: ControllerSettings?
    }
    private var key: PollKey {
        PollKey(source: source, active: scenePhase == .active, controller: source == .clash ? controller : nil)
    }
    private var explanation: String {
        switch source {
        #if DIRECT_ROUTING
        case .provider: return "확장이 연결한 TCP·UDP 흐름의 최초 일치 규칙과 실제 사용한 출구입니다."
        #endif
        case .sockets: return "macOS에서 관측한 앱별 TCP·UDP 연결입니다."
        case .clash: return "FlClash가 보고한 규칙과 최종 노드입니다. Direct는 FlClash 내부의 출구입니다."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Picker("관측 소스", selection: $source) {
                    ForEach(LiveSource.allCases) { Text($0.rawValue).tag($0) }
                }.fixedSize()
                if source == .clash {
                    Button("컨트롤러 설정") { configuring = true }
                        .popover(isPresented: $configuring) {
                            ControllerEditor(current: controller) { settings in
                                controller = settings
                                configuring = false
                            }
                        }
                }
                Spacer()
                if let snapshot, snapshotSource == source {
                    Text("연결 \(snapshot.total)개").font(.callout.weight(.semibold)).monospacedDigit()
                }
            }
            if let snapshot, snapshotSource == source {
                connectionList(snapshot)
                if let problem {
                    Label(problem, systemImage: "exclamationmark.triangle")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else if let problem {
                Label(problem, systemImage: "info.circle")
                    .font(.callout).foregroundStyle(.secondary).textSelection(.enabled).padding(.vertical, 6)
            } else if source == .clash && controller == nil {
                Text("컨트롤러 설정에서 FlClash의 로컬 HTTP 제어 포트를 입력하세요.")
                    .font(.callout).foregroundStyle(.secondary).padding(.vertical, 6)
            } else if scenePhase == .active {
                HStack { ProgressView().controlSize(.small); Text("연결 조회 중").foregroundStyle(.secondary) }
            } else {
                Text("창이 활성화되면 갱신합니다.").foregroundStyle(.secondary)
            }
        }
        .task(id: key) { await observe(key) }
        .onChange(of: source) { expandedApps.removeAll() }
        .accessibilityHint(explanation)
    }

    @ViewBuilder private func connectionList(_ snapshot: LiveConnectionSnapshot) -> some View {
        let term = filter.trimmingCharacters(in: .whitespacesAndNewlines)
        let rows = snapshot.connections.filter { $0.matches(term) }
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(source == .sockets ? "앱·IP·포트·인터페이스 검색" : "앱·목적지·규칙·출구 검색", text: $filter)
                .textFieldStyle(.plain).accessibilityLabel("실시간 연결 검색")
            if !filter.isEmpty {
                Button { filter = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).accessibilityLabel("검색어 지우기")
            }
        }
        .padding(.horizontal, 10).frame(minHeight: 35)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 9))
        if rows.isEmpty {
            Text(snapshot.total == 0 ? "현재 관측된 연결이 없습니다." : "표시 범위에서 검색 결과가 없습니다.")
                .foregroundStyle(.secondary).padding(.vertical, 8)
        } else {
            groupedList(rows)

        }
        HStack {
            if !term.isEmpty || snapshot.total > snapshot.connections.count {
                Text("\(snapshot.total)개 중 \(rows.count)개 표시")
            }
            Spacer()
            if let sampleDate {
                Text((problem != nil || scenePhase != .active ? "마지막 조회 " : "최근 갱신 ") + sampleDate.formatted(date: .omitted, time: .standard))
            }
        }.font(.caption).foregroundStyle(.secondary)
    }

    private struct AppGroup: Identifiable {
        let id: String
        let name: String
        let connections: [MacLiveConnection]
    }

    private func groupedList(_ connections: [MacLiveConnection]) -> some View {
        let groups = Dictionary(grouping: connections) { $0.bundleID ?? $0.app }.map { id, rows in
            let sorted = rows.sorted {
                if $0.destination != $1.destination { return $0.destination < $1.destination }
                return $0.id < $1.id
            }
            return AppGroup(id: id, name: sorted[0].app, connections: sorted)
        }.sorted {
            let order = $0.name.localizedStandardCompare($1.name)
            return order == .orderedSame ? $0.id < $1.id : order == .orderedAscending
        }
        return VStack(alignment: .leading, spacing: 0) {
            columns(
                peer: { Text("상대 IP·포트") },
                protocolLabel: { Text("프로토콜") },
                final: { Text(source == .sockets ? "인터페이스" : "관측된 출구") },
                rule: { Text("적용된 규칙") }
            )
            .font(.caption.weight(.medium)).foregroundStyle(.secondary)
            .padding(.leading, 28).padding(.trailing, 12).padding(.vertical, 6)
            Divider()
            List {
                ForEach(groups) { group in
                    Button {
                        if expandedApps.contains(group.id) { expandedApps.remove(group.id) }
                        else { expandedApps.insert(group.id) }
                    } label: {
                        HStack(spacing: 7) {
                            Image(systemName: expandedApps.contains(group.id) ? "chevron.down" : "chevron.right")
                                .font(.caption2.weight(.semibold)).frame(width: 12).foregroundStyle(.secondary)
                            Text(group.name).lineLimit(1).fontWeight(.medium)
                            Spacer(minLength: 6)
                            Text("\(group.connections.count)개").font(.caption).monospacedDigit().foregroundStyle(.secondary)
                        }.frame(minHeight: 29).contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("\(group.name) 연결 \(group.connections.count)개")
                    .accessibilityValue(expandedApps.contains(group.id) ? "펼쳐짐" : "접힘")
                    .listRowInsets(EdgeInsets(top: 3, leading: 8, bottom: 3, trailing: 8))
                    if expandedApps.contains(group.id) {
                        ForEach(group.connections) { connectionRow($0) }
                    }
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .frame(height: listHeight)
    }

    private func connectionRow(_ row: MacLiveConnection) -> some View {
        columns(
            peer: {
                Text(row.destination).lineLimit(1).truncationMode(.middle)
                    .monospacedDigit().help(row.destination)
            },
            protocolLabel: { Text(row.transport).foregroundStyle(.secondary) },
            final: {
                if source == .sockets {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.interface.isEmpty ? "—" : row.interface).lineLimit(1)
                        if row.egress == "coreaVPN" {
                            Text(row.outbound).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(row.outbound).fontWeight(.medium)
                        if !row.routeDetail.isEmpty {
                            Text(row.routeDetail).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    }.help(row.routeDetail.isEmpty ? row.outbound : row.outbound + " · " + row.routeDetail)
                }
            },
            rule: {
                if let id = row.ruleID {
                    Button { showRule(id) } label: {
                        Label(row.rule, systemImage: "arrow.up.right.square").lineLimit(1)
                    }.buttonStyle(.link).help("적용된 규칙 보기 · " + row.rule)
                     .accessibilityLabel("적용된 규칙 보기 · " + row.rule)
                } else {
                    Text(row.rule.isEmpty ? "미확인" : row.rule).lineLimit(1).help(row.rule)
                }
            }
        )
        .font(.callout)
        .listRowInsets(EdgeInsets(top: 4, leading: 28, bottom: 4, trailing: 12))
    }

    private func columns<Peer: View, Transport: View, Final: View, Rule: View>(
        @ViewBuilder peer: () -> Peer, @ViewBuilder protocolLabel: () -> Transport,
        @ViewBuilder final: () -> Final, @ViewBuilder rule: () -> Rule
    ) -> some View {
        HStack(alignment: .top, spacing: 8) {
            peer().frame(maxWidth: .infinity, alignment: .leading)
            protocolLabel().frame(width: 60, alignment: .leading)
            if source != .sockets {
                rule().frame(maxWidth: .infinity, alignment: .leading)
            }
            final().frame(width: source == .sockets ? 92 : 130, alignment: .leading)
        }
    }

    @MainActor private func observe(_ request: PollKey) async {
        guard request.active else { return }
        if snapshotSource != request.source || (request.source == .clash && snapshotController != request.controller) {
            snapshot = nil; problem = nil; sampleDate = nil
        }
        snapshotSource = request.source
        snapshotController = request.controller
        guard request.source != .clash || request.controller != nil else { return }
        while !Task.isCancelled {
            do {
                let value: LiveConnectionSnapshot
                switch request.source {
                #if DIRECT_ROUTING
                case .provider: value = try await routing.liveConnections()
                #endif
                case .sockets: value = try await MacSocketConnections.snapshot()
                case .clash:
                    guard let settings = request.controller else { return }
                    value = try await MacMihomoConnections.snapshot(port: settings.port, token: settings.token)
                }
                try Task.checkCancellation()
                snapshot = value; sampleDate = Date(); problem = nil
            } catch {
                guard !Task.isCancelled else { return }
                problem = error.localizedDescription
            }
            do { try await Task.sleep(for: .seconds(problem == nil ? 2 : 5)) } catch { return }
        }
    }
}

private struct ControllerEditor: View {
    let apply: (ControllerSettings?) -> Void
    @State private var port: String
    @State private var token: String
    init(current: ControllerSettings?, apply: @escaping (ControllerSettings?) -> Void) {
        _port = State(initialValue: current.map { String($0.port) } ?? "")
        _token = State(initialValue: current?.token ?? "")
        self.apply = apply
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("FlClash 로컬 컨트롤러").font(.headline)
            Text("FlClash에서 이미 활성화한 HTTP 제어 포트를 사용합니다. 토큰은 이 화면을 사용하는 동안만 메모리에 보관합니다.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack { Text("127.0.0.1"); TextField("제어 포트", text: $port) }
            SecureField("인증 토큰 (설정한 경우)", text: $token)
            HStack {
                Button("연결 설정 지우기") { apply(nil) }
                Spacer()
                Button("연결 목록 읽기") {
                    if let port = UInt16(port), port > 0 { apply(ControllerSettings(port: port, token: token)) }
                }.disabled((UInt16(port) ?? 0) == 0).keyboardShortcut(.defaultAction)
            }
        }.padding(16).frame(width: 320)
    }
}
#endif
