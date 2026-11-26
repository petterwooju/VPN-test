import AppKit
import SwiftUI

@main
enum ComparisonLayoutChecks {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let host = "puma.coreavpn.net"
        var clicked: [String] = []
        let rows = [BenchmarkAttempt(host: host, time: Date(), outcome: .measured),
                    BenchmarkAttempt(host: "leo.coreavpn.net", time: Date(), outcome: .notRun)]
        let fixture = List {
            Section("결과") {
                ServerComparisonTable(rows: rows, selectedHost: nil, selectionEnabled: true) { clicked.append($0) }
            }
        }
        let content = NSHostingView(rootView: fixture)
        let window = NSWindow(contentRect: NSRect(x: -2_000, y: -2_000, width: 620, height: 420),
                              styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.contentView = content
        window.orderBack(nil)

        func comparison(in view: NSView) -> NSTableView? {
            if let table = view as? NSTableView, table.accessibilityIdentifier() == "comparison-table" { return table }
            return view.subviews.lazy.compactMap { comparison(in: $0) }.first
        }
        let deadline = Date().addingTimeInterval(3)
        while comparison(in: content) == nil && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.02))
            content.layoutSubtreeIfNeeded()
        }
        guard let table = comparison(in: content), let scroll = table.enclosingScrollView else {
            fatalError("The comparison table must be an AppKit descendant of the SwiftUI List.")
        }
        precondition(table.numberOfRows == 2 && table.tableColumns.first?.identifier.rawValue == "connect")
        precondition(table.accessibilityRole() == .table)
        var enabledButton: NSButton?
        for row in 0..<table.numberOfRows {
            guard let cell = table.view(atColumn: 0, row: row, makeIfNecessary: true),
                  let button = cell.subviews.first(where: { $0 is NSButton }) as? NSButton else {
                fatalError("A native connection button is required in every row.")
            }
            precondition(button.accessibilityRole() == .button, "Expected AXButton, got \(String(describing: button.accessibilityRole()))")
            precondition((button.accessibilityIdentifier()).hasPrefix("comparison-connect-"))
            precondition(scroll.contentView.documentVisibleRect.intersects(table.frameOfCell(atColumn: 0, row: row)))
            if button.isEnabled { enabledButton = button }
        }
        enabledButton?.performClick(nil)
        precondition(clicked == [host])
        print("620-point SwiftUI List: native AXTable, two AXButtons visible at horizontal origin, only Puma invokes the test callback.")
        window.orderOut(nil)
    }
}
