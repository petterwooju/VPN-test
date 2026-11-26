#if os(macOS)
import SwiftUI
import AppKit

/// One row per server for this run. Sorting is local to the view and never triggers a connection.
struct ServerComparisonTable: View {
    let rows: [BenchmarkAttempt]
    let selectedHost: String?
    let selectionEnabled: Bool
    let onConnect: (String) -> Void

    fileprivate enum Metric: String, CaseIterable {
        case download = "FAST 다운로드"
        case ping = "ping 평균"
        case replies = "ping 응답/송신"
        case upload = "FAST 업로드"
        case idle = "FAST 평상시 지연"
        case loadedDown = "다운로드 중 지연"
        case loadedUp = "업로드 중 지연"

        func value(_ row: BenchmarkAttempt) -> Double? {
            switch self {
            case .download: return row.httpsSample?.downloadMbps
            case .ping: return row.sample?.meanMS
            case .replies: return row.sample.map { Double($0.received) }
            case .upload: return row.httpsSample?.uploadMbps
            case .idle: return row.httpsSample?.averageMS
            case .loadedDown: return row.httpsSample?.downloadLoadedMS
            case .loadedUp: return row.httpsSample?.uploadLoadedMS
            }
        }

        var ascending: Bool { [.ping, .idle, .loadedDown, .loadedUp].contains(self) }

        func comesBefore(_ left: BenchmarkAttempt, _ right: BenchmarkAttempt) -> Bool {
            switch (value(left), value(right)) {
            case (let a?, let b?) where a != b: return ascending ? a < b : a > b
            case (.some, nil): return true
            case (nil, .some): return false
            default: return left.host < right.host
            }
        }

        func cell(_ row: BenchmarkAttempt) -> String {
            if self == .replies, let p = row.sample {
                return "\(p.received)/\(p.sent) (\(p.lossPercent.formatted())%)"
            }
            guard let number = value(row) else { return "—" }
            return number.formatted(.number.precision(.fractionLength(2)))
        }

        var heading: String {
            switch self {
            case .download, .upload: return rawValue + " (Mbps)"
            case .replies: return rawValue + " (손실)"
            default: return rawValue + " (ms)"
            }
        }
    }

    @State private var sort: Metric = .download
    @State private var pickedHost = ""

    private var options: [String] { rows.filter(Self.tested).map(\.host).sorted() }
    private static func tested(_ row: BenchmarkAttempt) -> Bool {
        ![.skipped, .notRun, .stopped].contains(row.outcome)
    }

    var body: some View {
        Picker("결과 정렬", selection: $sort) {
            ForEach(Metric.allCases, id: \.self) { Text($0.rawValue).tag($0) }
        }
        .accessibilityIdentifier("comparison-sort")
        if !options.isEmpty {
            HStack {
                Picker("연결할 서버", selection: $pickedHost) {
                    Text("서버 선택").tag("")
                    ForEach(options, id: \.self) { Text($0).tag($0) }
                }
                .accessibilityIdentifier("comparison-server-picker")
                Button("선택한 서버 연결") { onConnect(pickedHost) }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("comparison-picked-connect")
                    .disabled(!selectionEnabled || !options.contains(pickedHost))
            }
        }
        ComparisonGrid(rows: rows.sorted(by: sort.comesBefore), selectedHost: selectedHost,
                       enabled: selectionEnabled, connect: onConnect)
            .frame(minWidth: 200, maxWidth: .infinity)
            .frame(height: min(CGFloat(rows.count) * 46 + 50, 360))
    }
}

/// AppKit keeps a separate accessible row, cell and button, including inside a SwiftUI List.
private struct ComparisonGrid: NSViewRepresentable {
    let rows: [BenchmarkAttempt]
    let selectedHost: String?
    let enabled: Bool
    let connect: (String) -> Void

    struct Column {
        let id: String
        let title: String
        let width: CGFloat
        let metric: ServerComparisonTable.Metric?
        init(_ id: String, _ title: String, _ width: CGFloat, metric: ServerComparisonTable.Metric? = nil) {
            self.id = id
            self.title = title
            self.width = width
            self.metric = metric
        }
    }

    private static let metrics: [ServerComparisonTable.Metric] = [.ping, .replies, .download, .upload, .idle, .loadedDown, .loadedUp]
    private static let columns = [Column("connect", "동작", 72), Column("host", "서버", 165), Column("status", "상태", 193)] +
        metrics.map { Column($0.rawValue, $0.heading, $0.heading.count > 13 ? 155 : 135, metric: $0) }

    final class Coordinator: NSObject, NSTableViewDelegate, NSTableViewDataSource {
        var owner: ComparisonGrid
        init(_ owner: ComparisonGrid) { self.owner = owner }
        func numberOfRows(in tableView: NSTableView) -> Int { owner.rows.count }
        @objc func press(_ sender: NSButton) {
            guard owner.enabled, let id = sender.identifier?.rawValue,
                  let row = owner.rows.first(where: { "comparison-connect-" + $0.host == id }),
                  ![.skipped, .notRun, .stopped].contains(row.outcome) else { return }
            owner.connect(row.host)
        }

        func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row index: Int) -> NSView? {
            guard let key = tableColumn?.identifier.rawValue,
                  let column = ComparisonGrid.columns.first(where: { $0.id == key }) else { return nil }
            let row = owner.rows[index]
            switch key {
            case "connect":
                let button = NSButton(title: "연결", target: self, action: #selector(press(_:)))
                button.bezelStyle = .rounded
                button.controlSize = .small
                button.identifier = NSUserInterfaceItemIdentifier("comparison-connect-" + row.host)
                button.setAccessibilityIdentifier("comparison-connect-" + row.host)
                button.setAccessibilityLabel(row.host + " 연결")
                button.setAccessibilityElement(true)
                button.setAccessibilityRole(.button)
                button.isEnabled = owner.enabled && ![.skipped, .notRun, .stopped].contains(row.outcome)
                let cell = NSTableCellView()
                button.translatesAutoresizingMaskIntoConstraints = false
                cell.addSubview(button)
                NSLayoutConstraint.activate([
                    button.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 3),
                    button.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
                ])
                return cell
            case "host":
                return cell(row.host, detail: row.host == owner.selectedHost ? "사용자가 선택한 서버" : nil)
            case "status":
                let stage = row.detail.flatMap { $0.hasPrefix("ipsec") ? "IKEv2 연결 확인" : $0 }
                let detail = [row.selectionError.map { "연결 · " + $0 }, row.pingError.map { "ping · " + $0 },
                              row.httpsError.map { "FAST · " + $0 }, stage].compactMap { $0 }.joined(separator: " · ")
                return cell(row.outcome.displayName, detail: detail.isEmpty ? nil : detail)
            default:
                return cell(column.metric?.cell(row) ?? "—", numeric: true)
            }
        }

        private func cell(_ text: String, detail: String? = nil, numeric: Bool = false) -> NSTableCellView {
            let cell = NSTableCellView()
            let label = NSTextField(labelWithString: detail.map { text + "\n" + $0 } ?? text)
            label.font = numeric ? .monospacedDigitSystemFont(ofSize: 12, weight: .regular) : .systemFont(ofSize: 12)
            label.maximumNumberOfLines = detail == nil ? 1 : 2
            label.lineBreakMode = .byTruncatingTail
            label.toolTip = label.stringValue
            label.alignment = numeric ? .right : .left
            label.translatesAutoresizingMaskIntoConstraints = false
            cell.addSubview(label)
            cell.textField = label
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 3),
                label.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -3),
                label.centerYAnchor.constraint(equalTo: cell.centerYAnchor)
            ])
            return cell
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.setAccessibilityIdentifier("comparison-table")
        table.delegate = context.coordinator
        table.dataSource = context.coordinator
        table.rowHeight = 44
        table.intercellSpacing = NSSize(width: 4, height: 2)
        table.usesAlternatingRowBackgroundColors = true
        table.allowsColumnReordering = false
        table.columnAutoresizingStyle = .noColumnAutoresizing
        for column in Self.columns {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.id))
            col.title = column.title
            col.width = column.width
            col.minWidth = 65
            table.addTableColumn(col)
        }
        let scroll = NSScrollView()
        scroll.hasHorizontalScroller = true
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.documentView = table
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let table = scroll.documentView as? NSTableView else { return }
        let old = context.coordinator.owner
        context.coordinator.owner = self
        if old.rows != rows || old.enabled != enabled || old.selectedHost != selectedHost || table.numberOfRows != rows.count {
            table.reloadData()
        }
    }
}
#endif
