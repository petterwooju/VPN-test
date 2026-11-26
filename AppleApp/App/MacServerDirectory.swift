#if os(macOS)
import AppKit
import SwiftUI

struct DirectServerGrid: View {
    @Binding var expanded: Bool
    let enabled: Bool
    let connectedHost: String?
    let connect: (CoreaServer) -> Void

    private let columns = [GridItem(.adaptive(minimum: 169), spacing: 9)]

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                Button {
                    expanded.toggle()
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: expanded ? "chevron.down" : "chevron.right")
                            .font(.caption.weight(.semibold))
                        Text("서버 바로 연결").font(.headline)
                        Text("\(CoreaServer.catalog.count)개").foregroundStyle(.secondary)
                        Spacer(minLength: 0)
                    }
                    .frame(minHeight: 32)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("server-direct-grid-toggle")
                .accessibilityValue(expanded ? "펼쳐짐" : "접힘")

                if expanded {
                    LazyVGrid(columns: columns, spacing: 7) {
                        ForEach(CoreaServer.catalog) { server in
                            let selected = connectedHost == server.host
                            let hostname = server.host.replacingOccurrences(of: ".coreavpn.", with: ".")
                            ServerConnectButton(title: hostname + " · " + server.group,
                                label: server.host + (selected ? " 연결됨" : " 바로 연결"),
                                identifier: "direct-connect-" + server.host,
                                enabled: enabled) { connect(server) }
                                .frame(maxWidth: .infinity).frame(height: 38)
                                .help(server.host)
                        }
                    }
                }
            }
            .padding(.vertical, 8)
        }
    }
}

struct MacServerDirectory: View {
    let rows: [BenchmarkAttempt]
    let comparing: Bool
    let activeHost: String?
    let selectedHost: String?
    let canConnect: Bool
    let addresses: [String: String]
    let dnsErrors: [String: String]
    let connect: (CoreaServer) -> Void

    @State private var search = ""
    @State private var group = ""
    @State private var sort = Sort.catalog
    @State private var expanded: String?

    private enum Sort: String, CaseIterable {
        case catalog = "기본 순서"
        case download = "FAST 다운로드"
        case upload = "FAST 업로드"
        case ping = "ping 평균"
        case replies = "ping 응답 수"

        func number(_ row: BenchmarkAttempt?) -> Double? {
            switch self {
            case .catalog: return nil
            case .download: return row?.httpsSample?.downloadMbps
            case .upload: return row?.httpsSample?.uploadMbps
            case .ping: return row?.sample?.meanMS
            case .replies: return row?.sample.map { Double($0.received) }
            }
        }

        func precedes(_ lhs: (Int, BenchmarkAttempt?), _ rhs: (Int, BenchmarkAttempt?)) -> Bool {
            switch (number(lhs.1), number(rhs.1)) {
            case let (a?, b?) where a != b: return self == .ping ? a < b : a > b
            case (_?, nil): return true
            case (nil, _?): return false
            default: return lhs.0 < rhs.0
            }
        }
    }

    var body: some View {
        let results = Dictionary(rows.map { ($0.host, $0) }, uniquingKeysWith: { _, last in last })
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let servers = CoreaServer.catalog.enumerated()
            .filter { _, server in
                (group.isEmpty || server.group == group) &&
                (query.isEmpty || server.host.localizedCaseInsensitiveContains(query))
            }
            .sorted { a, b in sort.precedes((a.offset, results[a.element.host]), (b.offset, results[b.element.host])) }
            .map(\.element)
        Section {
            HStack(spacing: 12) {
                TextField("서버 검색", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("server-search")
                    .frame(minWidth: 105, maxWidth: 240)
                Picker("그룹", selection: $group) {
                    Text("모든 그룹").tag("")
                    ForEach(["A", "B", "C", "D", "E"], id: \.self) { Text("\($0) 그룹").tag($0) }
                }.labelsHidden().fixedSize()
                Picker("결과 정렬", selection: $sort) {
                    ForEach(Sort.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.labelsHidden().fixedSize().accessibilityIdentifier("comparison-sort")
                Spacer(minLength: 0)
                Text("\(servers.count) / \(CoreaServer.catalog.count)")
                    .monospacedDigit().foregroundStyle(.secondary)
            }.padding(.vertical, 3)
            if servers.isEmpty {
                Text("검색 조건에 맞는 서버가 없습니다.").foregroundStyle(.secondary).padding(.vertical, 8)
            } else {
                headings
                ForEach(servers) { server in
                    row(server, result: results[server.host])
                }
            }
        }
        .onChange(of: comparing, initial: true) { _, comparing in
            sort = comparing ? .download : .catalog
        }
    }

    private var headings: some View {
        HStack(spacing: 8) {
            Text("서버").frame(maxWidth: .infinity, alignment: .leading)
            Text("ping 평균 · 응답").frame(width: 97, alignment: .trailing)
            Text("FAST ↓ Mbps").frame(width: 73, alignment: .trailing)
            Text("FAST ↑ Mbps").frame(width: 73, alignment: .trailing)
            Text("동작").frame(width: 92, alignment: .center)
        }
        .padding(.leading, 20)
        .font(.caption)
        .foregroundStyle(.secondary)
        .accessibilityHidden(true)
    }

    private func row(_ server: CoreaServer, result: BenchmarkAttempt?) -> some View {
        let host = server.host
        let open = expanded == host
        let tested = result.map { ![.skipped, .notRun, .stopped].contains($0.outcome) } ?? false
        let enabled = canConnect && (!comparing || tested)
        let status = activeHost == host ? "연결 중 또는 측정 중" :
            selectedHost == host ? "선택한 서버" : result?.outcome.displayName

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    expanded = open ? nil : host
                } label: {
                    HStack(spacing: 7) {
                        Image(systemName: open ? "chevron.down" : "chevron.right")
                            .font(.caption).foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(host).font(.system(.callout, design: .monospaced))
                                .lineLimit(1).minimumScaleFactor(0.8).truncationMode(.head).help(host)
                            Text([server.group + " 그룹", status].compactMap { $0 }.joined(separator: " · "))
                                .font(.caption).foregroundStyle(activeHost == host ? Color.accentColor : .secondary)
                        }
                    }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                }.buttonStyle(.plain)
                    .accessibilityLabel(host + (open ? " 숨기기" : " 상세 보기"))
                    .accessibilityIdentifier("server-detail-" + host)
                VStack(alignment: .trailing, spacing: 2) {
                    Text(format(result?.sample?.meanMS, unit: " ms"))
                    if let ping = result?.sample { Text("\(ping.received)/\(ping.sent)").foregroundStyle(.secondary) }
                }.frame(width: 97, alignment: .trailing).accessibilityLabel("평균 지연 " +
                    format(result?.sample?.meanMS, unit: " 밀리초") + (result?.sample.map { ", \($0.sent)회 중 \($0.received)회 응답" } ?? ""))
                Text(result?.downloadFailed == true ? "측정 실패" : format(result?.httpsSample?.downloadMbps))
                    .frame(width: 73, alignment: .trailing)
                    .accessibilityLabel("FAST 다운로드 " + (result?.downloadFailed == true ? "측정 실패" : format(result?.httpsSample?.downloadMbps, unit: " 메가비트 매초")))
                Text(format(result?.httpsSample?.uploadMbps)).frame(width: 73, alignment: .trailing)
                    .accessibilityLabel("FAST 업로드 " + format(result?.httpsSample?.uploadMbps, unit: " 메가비트 매초"))
                let title = comparing ? "연결" : "바로 연결"
                let identifier = (comparing ? "comparison-connect-" : "directory-connect-") + host
                ServerConnectButton(title: title, label: host + " " + title, identifier: identifier,
                                    enabled: enabled) { connect(server) }
                    .frame(width: 92, height: 32)
            }.font(.callout).monospacedDigit()
            if open { details(host, result: result) }
        }.padding(.vertical, 5)
    }

    private func details(_ host: String, result: BenchmarkAttempt?) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            if let row = result {
                let https = row.httpsSample
                if row.sample != nil || https != nil || row.outcome == .failed {
                    Text("측정 \(row.time.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 5) {
                    if let ping = row.sample {
                        GridRow {
                            Text("ping 손실"); Text(format(ping.lossPercent, unit: "%"))
                        }
                    }
                    if let https {
                        GridRow { Text("FAST 평상시 지연"); Text(format(https.averageMS, unit: " ms")) }
                        GridRow { Text("다운로드 중 지연"); Text(format(https.downloadLoadedMS, unit: " ms")) }
                        GridRow { Text("업로드 중 지연"); Text(format(https.uploadLoadedMS, unit: " ms")) }
                    }
                }.monospacedDigit()
                let messages = [row.selectionError, row.pingError, row.httpsError, row.detail].compactMap { $0 }
                ForEach(messages.indices, id: \.self) { index in
                    Text(messages[index]).foregroundStyle(.secondary).textSelection(.enabled)
                }
            } else {
                Text("현재 회선에 측정 기록이 없습니다.").foregroundStyle(.secondary)
            }
            if let address = addresses[host] { Text("DNS · \(address)").textSelection(.enabled) }
            if let error = dnsErrors[host] { Text("DNS · \(error)").foregroundStyle(.secondary).textSelection(.enabled) }
        }.font(.callout).padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(.quaternary.opacity(0.32), in: RoundedRectangle(cornerRadius: 7))
            .padding(.leading, 20)
    }

    private func format(_ number: Double?, unit: String = "") -> String {
        number.map { $0.formatted(.number.precision(.fractionLength(1))) + unit } ?? "—"
    }
}

/// NSButton keeps each connect action independently accessible inside a List row.
private struct ServerConnectButton: NSViewRepresentable {
    let title: String
    let label: String
    let identifier: String
    let enabled: Bool
    let action: () -> Void

    final class Coordinator: NSObject {
        var action: () -> Void
        init(_ action: @escaping () -> Void) { self.action = action }
        @objc func press() { action() }
    }

    func makeCoordinator() -> Coordinator { Coordinator(action) }
    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(title: "", target: context.coordinator, action: #selector(Coordinator.press))
        button.bezelStyle = .rounded
        button.controlSize = .large
        button.setAccessibilityElement(true)
        button.setAccessibilityRole(.button)
        return button
    }
    func updateNSView(_ button: NSButton, context: Context) {
        context.coordinator.action = action
        button.title = title
        button.setAccessibilityLabel(label)
        button.setAccessibilityIdentifier(identifier)
        button.isEnabled = enabled
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSButton, context: Context) -> CGSize? {
        CGSize(width: proposal.width ?? nsView.intrinsicContentSize.width,
               height: proposal.height ?? nsView.intrinsicContentSize.height)
    }
}
#endif
