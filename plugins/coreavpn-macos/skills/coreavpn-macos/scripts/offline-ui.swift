// Build once while online: swiftc offline-ui.swift -o /absolute/path/offline-ui
// Local AX automation for an explicitly authorized offline test. Never reads passwords.
import AppKit
import ApplicationServices
import Foundation

enum Failure: Error { case message(String) }
func fail(_ message: String) throws -> Never { throw Failure.message(message) }
func attr(_ e: AXUIElement, _ name: String) -> AnyObject? {
    var value: CFTypeRef?
    guard AXUIElementCopyAttributeValue(e, name as CFString, &value) == .success else { return nil }
    return value
}
func str(_ e: AXUIElement, _ name: String) -> String { attr(e, name) as? String ?? "" }
func nodes(_ root: AXUIElement, depth: Int = 0) -> [AXUIElement] {
    if depth > 25 { return [] }
    return [root] + ((attr(root, kAXChildrenAttribute) as? [AXUIElement]) ?? []).flatMap { nodes($0, depth: depth + 1) }
}
func window(_ bundle: String) throws -> AXUIElement {
    guard AXIsProcessTrusted() else { try fail("Accessibility access missing; no settings changed") }
    guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundle).first else {
        try fail("Required application is not running: " + bundle)
    }
    let ax = AXUIElementCreateApplication(app.processIdentifier)
    AXUIElementSetMessagingTimeout(ax, 2)
    guard let windows = attr(ax, kAXWindowsAttribute) as? [AXUIElement], windows.count == 1 else {
        try fail("Expected exactly one application window")
    }
    return windows[0]
}
func press(_ element: AXUIElement) throws {
    guard AXUIElementPerformAction(element, kAXPressAction as CFString) == .success else {
        try fail("AXPress failed")
    }
}
func switches(_ root: AXUIElement) -> [AXUIElement] {
    nodes(root).filter { ["AXCheckBox", "AXSwitch"].contains(str($0, kAXRoleAttribute)) }
}
func bool(_ element: AXUIElement) throws -> Bool {
    guard let n = attr(element, kAXValueAttribute) as? NSNumber else { try fail("Unreadable switch state") }
    return n.intValue != 0
}
func namedSwitch(_ root: AXUIElement, labels: [String]) throws -> AXUIElement {
    let matches = switches(root).filter { e in
        let names = [str(e, kAXTitleAttribute), str(e, kAXDescriptionAttribute)]
        return names.contains { labels.contains($0) }
    }
    guard matches.count == 1 else { try fail("Missing or ambiguous named switch: " + labels.joined(separator: "/")) }
    return matches[0]
}
func flState() throws -> [String: Bool] {
    let root = try window("com.follow.clash")
    return ["tun": try bool(namedSwitch(root, labels: ["TUN"])),
            "proxy": try bool(namedSwitch(root, labels: ["시스템 프록시", "System proxy", "System Proxy"]))]
}
func flSet(_ key: String, _ desired: Bool) throws {
    let labels = key == "tun" ? ["TUN"] : ["시스템 프록시", "System proxy", "System Proxy"]
    let root = try window("com.follow.clash")
    let element = try namedSwitch(root, labels: labels)
    if try bool(element) != desired { try press(element) }
    for _ in 0..<20 {
        if try flState()[key] == desired { return }
        Thread.sleep(forTimeInterval: 0.2)
    }
    try fail("FlClash switch did not reach requested state")
}
func vpnSwitch(_ index: Int, _ count: Int) throws -> AXUIElement {
    let root = try window("com.apple.systempreferences")
    guard ["VPN"].contains(str(root, kAXTitleAttribute)) else { try fail("System Settings must remain on VPN") }
    guard !nodes(root).contains(where: { str($0, kAXRoleAttribute) == "AXSheet" }) else {
        try fail("Close the VPN details sheet before running")
    }
    let items = switches(root)
    guard items.count == count, index >= 0, index < count else { try fail("VPN list changed; recalibrate online") }
    return items[index]
}
// Verify the selected profile's two hostname fields without printing any field values.
func verifyVPN(_ index: Int, _ count: Int, _ server: String) throws {
    _ = try vpnSwitch(index, count)
    let root = try window("com.apple.systempreferences")
    let details = nodes(root).filter {
        ["세부사항 보기", "Show Details"].contains(str($0, kAXDescriptionAttribute)) ||
        ["세부사항 보기", "Show Details"].contains(str($0, kAXTitleAttribute))
    }
    guard details.count == count else { try fail("VPN details buttons changed; recalibrate online") }
    try press(details[index])
    defer {
        if let w = try? window("com.apple.systempreferences") {
            let sheets = nodes(w).filter { str($0, kAXRoleAttribute) == "AXSheet" }
            if let sheet = sheets.first,
               let cancel = nodes(sheet).first(where: { ["취소", "Cancel"].contains(str($0, kAXTitleAttribute)) }) {
                try? press(cancel)
            }
        }
    }
    for _ in 0..<20 {
        let w = try window("com.apple.systempreferences")
        if let sheet = nodes(w).first(where: { str($0, kAXRoleAttribute) == "AXSheet" }) {
            // Only compare non-secure text fields to the supplied public hostname.
            let fields = nodes(sheet).filter { str($0, kAXRoleAttribute) == "AXTextField" }
            let matching = fields.filter { str($0, kAXValueAttribute) == server }
            guard matching.count == 2 else { try fail("Server and remote ID do not both match the expected hostname") }
            return
        }
        Thread.sleep(forTimeInterval: 0.2)
    }
    try fail("VPN details did not open")
}
func output(_ value: Any) throws {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
    print(String(data: data, encoding: .utf8)!)
}
do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let action = args.first else { try fail("Expected fl-state, fl-set, vpn-verify, vpn-state, or vpn-set") }
    switch action {
    case "fl-state": try output(flState())
    case "fl-set":
        guard args.count == 3, ["tun", "proxy"].contains(args[1]), ["on", "off"].contains(args[2]) else { try fail("Invalid fl-set arguments") }
        try flSet(args[1], args[2] == "on"); try output(flState())
    case "vpn-verify", "vpn-state", "vpn-set":
        guard args.count >= 3, let index = Int(args[1]), let count = Int(args[2]) else { try fail("Expected zero-based VPN index and switch count") }
        if action == "vpn-verify" {
            guard args.count == 4 else { try fail("Expected server hostname") }
            try verifyVPN(index, count, args[3])
        }
        if action == "vpn-set" {
            guard args.count == 4, ["on", "off"].contains(args[3]) else { try fail("Expected on/off") }
            let e = try vpnSwitch(index, count)
            if try bool(e) != (args[3] == "on") { try press(e) }
        }
        try output(["on": try bool(vpnSwitch(index, count))])
    default: try fail("Unknown action")
    }
} catch {
    // Never include AX field values or application dumps in errors.
    fputs("\(error)\n", stderr); exit(1)
}
