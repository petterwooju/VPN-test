#if os(macOS)
import SwiftUI
import AppKit

struct QuickReleaseButton: NSViewRepresentable {
    let title: String
    let enabled: Bool
    let release: () -> Void

    class Coordinator: NSObject {
        var release: () -> Void
        init(_ release: @escaping () -> Void) { self.release = release }
        @objc func pressed() { release() }
    }
    func makeCoordinator() -> Coordinator { Coordinator(release) }
    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(title: title, target: context.coordinator,
                              action: #selector(Coordinator.pressed))
        button.setAccessibilityIdentifier("quick-release")
        button.bezelStyle = .rounded
        button.controlSize = .large
        return button
    }
    func updateNSView(_ button: NSButton, context: Context) {
        context.coordinator.release = release
        button.title = title
        button.isEnabled = enabled
    }
    func sizeThatFits(_ proposal: ProposedViewSize, nsView: NSButton, context: Context) -> CGSize? {
        CGSize(width: proposal.width ?? nsView.intrinsicContentSize.width,
               height: proposal.height ?? nsView.intrinsicContentSize.height)
    }
}
#endif
