import AppKit
import SwiftUI

@main
enum ComparisonLayoutChecks {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let host = "lynx.coreavpn.net"
        var clicked: [String] = []
        let rows = [BenchmarkAttempt(host: host, time: Date(), outcome: .measured)]
        let fixture = List {
            MacServerDirectory(rows: rows, comparing: true, activeHost: nil, selectedHost: nil, canConnect: true,
                               addresses: [:], dnsErrors: [:]) { clicked.append($0.host) }
        }
        let content = NSHostingView(rootView: fixture)
        let window = NSWindow(contentRect: NSRect(x: -2_000, y: -2_000, width: 620, height: 420),
                              styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.contentView = content
        window.orderBack(nil)

        func buttons(in view: NSView, prefix: String) -> [NSButton] {
            if let button = view as? NSButton, button.accessibilityIdentifier().hasPrefix(prefix) {
                return [button]
            }
            return view.subviews.flatMap { buttons(in: $0, prefix: prefix) }
        }

        let deadline = Date().addingTimeInterval(3)
        while buttons(in: content, prefix: "comparison-connect-").count < 2 && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.02))
            content.layoutSubtreeIfNeeded()
        }
        let visible = buttons(in: content, prefix: "comparison-connect-")
        precondition(visible.count >= 2)
        let target = visible.first { $0.accessibilityIdentifier() == "comparison-connect-" + host }
        precondition(target != nil, "The expected server button must be in the visible rows.")
        precondition(target?.isEnabled == true, "A measured server can be selected after recovery.")
        precondition(target?.accessibilityRole() == .button, "Expected a native accessible button.")
        precondition(visible.contains { !$0.isEnabled })
        for button in visible {
            let frame = button.convert(button.bounds, to: content)
            precondition(frame.minX >= 0 && frame.maxX <= content.bounds.width)
        }
        target?.performClick(nil)
        precondition(clicked == [host])
        print("620-point server list: native connection buttons are horizontally visible and the tested host invokes its callback.")
        window.orderOut(nil)

        let direct = NSHostingView(rootView: List {
            DirectServerGrid(expanded: .constant(true), enabled: true, connectedHost: nil) { clicked.append($0.host) }
        })
        let gridWindow = NSWindow(contentRect: NSRect(x: -2_000, y: -2_000, width: 620, height: 500),
                                  styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        gridWindow.contentView = direct
        gridWindow.orderBack(nil)
        let gridDeadline = Date().addingTimeInterval(3)
        let expected = Set(CoreaServer.catalog.map { "direct-connect-" + $0.host })
        var gridButtons = buttons(in: direct, prefix: "direct-connect-")
        while gridButtons.count < expected.count && Date() < gridDeadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.02))
            direct.layoutSubtreeIfNeeded()
            gridButtons = buttons(in: direct, prefix: "direct-connect-")
        }
        precondition(Set(gridButtons.map { $0.accessibilityIdentifier() }) == expected)
        for button in gridButtons {
            let frame = button.convert(button.bounds, to: direct)
            precondition(frame.minX >= 0 && frame.maxX <= direct.bounds.width && frame.height >= 32,
                         "Invalid frame \(frame) for \(button.accessibilityIdentifier()) in \(direct.bounds).")
        }
        let puma = gridButtons.first { $0.accessibilityIdentifier() == "direct-connect-puma.coreavpn.com" }
        precondition(puma?.isEnabled == true)
        puma?.performClick(nil)
        precondition(clicked == [host, "puma.coreavpn.com"])
        print("620-point server grid: all catalog buttons fit and a .com action invokes the corresponding host.")
        gridWindow.orderOut(nil)
    }
}
