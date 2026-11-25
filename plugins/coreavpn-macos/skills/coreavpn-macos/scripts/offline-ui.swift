// Build once while online: swiftc offline-ui.swift -o /absolute/path/offline-ui
// Local AX automation for an explicitly authorized offline test. Never reads passwords.
import AppKit
import ApplicationServices
import Foundation

var flMap: [String: Any]?
func shell(_ program: String, _ arguments: [String]) throws -> String {
    let p = Process(), output = Pipe()
    p.executableURL = URL(fileURLWithPath: program); p.arguments = arguments
    p.standardOutput = output; p.standardError = FileHandle.nullDevice
    try p.run()
    let data = output.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
    guard p.terminationStatus == 0 else { try fail("Local network state read failed") }
    return String(data: data, encoding: .utf8) ?? ""
}
func geometry(_ root: AXUIElement) throws -> [String: Double] {
    guard let p = attr(root, kAXPositionAttribute), let s = attr(root, kAXSizeAttribute),
          CFGetTypeID(p) == AXValueGetTypeID(), CFGetTypeID(s) == AXValueGetTypeID() else {
        try fail("Window geometry unavailable")
    }
    var point = CGPoint.zero, size = CGSize.zero
    guard AXValueGetValue(p as! AXValue, .cgPoint, &point),
          AXValueGetValue(s as! AXValue, .cgSize, &size) else { try fail("Window geometry unreadable") }
    return ["x": point.x, "y": point.y, "width": size.width, "height": size.height]
}
func fallbackState() throws -> [String: Bool] {
    let route = try shell("/sbin/route", ["-n", "get", "-inet", "168.126.63.1"])
    let tun: Bool
    if route.range(of: #"interface:\s*utun[0-9]+"#, options: .regularExpression) != nil &&
       route.range(of: #"gateway:\s*198\.18\.0\.1\b"#, options: .regularExpression) != nil {
        tun = true
    } else if route.range(of: #"interface:\s*en[0-9]+\b"#, options: .regularExpression) != nil {
        tun = false
    } else { try fail("Cannot infer FlClash TUN state from the verified route") }
    let proxy = try shell("/usr/sbin/scutil", ["--proxy"])
    let flags = ["HTTPEnable", "HTTPSEnable", "SOCKSEnable"].map { key in
        proxy.range(of: "\\b" + key + #"\s*:\s*1\b"#, options: .regularExpression) != nil
    }
    guard flags.allSatisfy({ $0 }) || flags.allSatisfy({ !$0 }) else { try fail("Mixed proxy settings cannot be represented by one switch") }
    guard proxy.range(of: #"ProxyAutoConfigEnable\s*:\s*1\b"#, options: .regularExpression) == nil else {
        try fail("An unrelated automatic proxy is enabled")
    }
    return ["tun": tun, "proxy": flags[0]]
}
func calibratedPosition(_ root: AXUIElement, _ key: String) throws -> CGPoint {
    guard let map = flMap, let width = map["width"] as? Double, let height = map["height"] as? Double,
          let point = map[key] as? [Double], point.count == 2 else { try fail("Missing live FlClash screen calibration") }
    let frame = try geometry(root)
    guard abs(frame["width"]! - width) <= 2, abs(frame["height"]! - height) <= 2,
          point[0] > 0, point[1] > 0, point[0] < width, point[1] < height else {
        try fail("FlClash window size changed; recalibrate online")
    }
    return CGPoint(x: frame["x"]! + point[0], y: frame["y"]! + point[1])
}
func fallbackClick(_ root: AXUIElement, _ key: String) throws {
    let position = try calibratedPosition(root, key)
    var pid: pid_t = 0
    if AXUIElementGetPid(root, &pid) == .success {
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetAttributeValue(app, kAXFrontmostAttribute as CFString, kCFBooleanTrue)
        AXUIElementPerformAction(root, kAXRaiseAction as CFString)
    }
    for _ in 0..<25 {
        if NSWorkspace.shared.frontmostApplication?.bundleIdentifier == "com.follow.clash" { break }
        Thread.sleep(forTimeInterval: 0.1)
    }
    guard NSWorkspace.shared.frontmostApplication?.bundleIdentifier == "com.follow.clash" else {
        try fail("FlClash did not become frontmost; no click sent")
    }
    for type in [CGEventType.mouseMoved, .leftMouseDown, .leftMouseUp] {
        guard let event = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: position, mouseButton: .left) else {
            try fail("Could not create local mouse event")
        }
        event.post(tap: .cghidEventTap)
        Thread.sleep(forTimeInterval: 0.06)
    }
}

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
func appWindows(_ ax: AXUIElement) -> [AXUIElement] {
    var result = attr(ax, kAXWindowsAttribute) as? [AXUIElement] ?? []
    for name in [kAXFocusedWindowAttribute, kAXMainWindowAttribute] {
        if let value = attr(ax, name), CFGetTypeID(value) == AXUIElementGetTypeID() {
            let element = value as! AXUIElement
            if !result.contains(where: { CFEqual($0, element) }) { result.append(element) }
        }
    }
    return result
}
func window(_ bundle: String) throws -> AXUIElement {
    guard AXIsProcessTrusted() else { try fail("Accessibility access missing; no settings changed") }
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
    guard !apps.isEmpty else {
        try fail("Required application is not running: " + bundle)
    }
    let expected = bundle == "com.follow.clash" ? "FlClash" : "VPN"
    // FlClashCore can share its parent app's bundle ID but has no dashboard.
    var matches: [AXUIElement] = []
    for app in apps {
        let ax = AXUIElementCreateApplication(app.processIdentifier)
        AXUIElementSetMessagingTimeout(ax, 2)
        let windows = appWindows(ax)
        let named = windows.filter { str($0, kAXTitleAttribute) == expected }
        if !named.isEmpty {
            app.activate(options: [.activateAllWindows])
            // Flutter may publish only its root until semantics are requested.
            AXUIElementSetAttributeValue(ax, "AXManualAccessibility" as CFString, kCFBooleanTrue)
            AXUIElementSetAttributeValue(ax, "AXEnhancedUserInterface" as CFString, kCFBooleanTrue)
            matches += named
        }
    }
    guard matches.count == 1 else { try fail("Expected one named application window: " + expected) }
    return matches[0]
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
    if flMap != nil { return try fallbackState() }
    return ["tun": try bool(namedSwitch(root, labels: ["TUN"])),
            "proxy": try bool(namedSwitch(root, labels: ["시스템 프록시", "System proxy", "System Proxy"]))]
}
func flSet(_ key: String, _ desired: Bool) throws {
    let labels = key == "tun" ? ["TUN"] : ["시스템 프록시", "System proxy", "System Proxy"]
    let root = try window("com.follow.clash")
    if flMap != nil {
        if try fallbackState()[key] != desired {
            // Activation is asynchronous; wait briefly before checking the click target.
            for _ in 0..<10 {
                if NSWorkspace.shared.frontmostApplication?.bundleIdentifier == "com.follow.clash" { break }
                Thread.sleep(forTimeInterval: 0.1)
            }
            try fallbackClick(root, key)
        }
    } else {
        let element = try namedSwitch(root, labels: labels)
        if try bool(element) != desired { try press(element) }
    }
    for _ in 0..<20 {
        if try flState()[key] == desired { return }
        Thread.sleep(forTimeInterval: 0.2)
    }
    try fail("FlClash switch did not reach requested state")
}
func flEngineButton(_ root: AXUIElement, starting: Bool) -> AXUIElement? {
    let labels = starting ? ["시작", "Start"] : ["중지", "Stop"]
    let matches = nodes(root).filter { element in
        str(element, kAXRoleAttribute) == "AXButton" &&
        [kAXTitleAttribute, kAXDescriptionAttribute, kAXHelpAttribute].contains {
            labels.contains(str(element, $0))
        }
    }
    return matches.count == 1 ? matches[0] : nil
}
func vpnDetailsSheet(_ root: AXUIElement) -> AXUIElement? {
    if let sheet = nodes(root).first(where: { str($0, kAXRoleAttribute) == "AXSheet" }) {
        return sheet
    }
    guard let app = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.systempreferences").first else {
        return nil
    }
    let ax = AXUIElementCreateApplication(app.processIdentifier)
    return appWindows(ax).first(where: { str($0, kAXRoleAttribute) == "AXSheet" })
}
func vpnSwitch(_ index: Int, _ count: Int) throws -> AXUIElement {
    let root = try window("com.apple.systempreferences")
    guard ["VPN"].contains(str(root, kAXTitleAttribute)) else { try fail("System Settings must remain on VPN") }
    guard vpnDetailsSheet(root) == nil else {
        try fail("Close the VPN details sheet before running")
    }
    let items = switches(root)
    guard items.count == count, index >= 0, index < count else { try fail("VPN list changed; recalibrate online") }
    return items[index]
}
func closeVPNDetails() throws {
    let root = try window("com.apple.systempreferences")
    guard let sheet = vpnDetailsSheet(root) else { return }
    guard let cancel = nodes(sheet).first(where: {
        [str($0, kAXTitleAttribute), str($0, kAXDescriptionAttribute)].contains(where: { ["취소", "Cancel"].contains($0) })
    }) else { try fail("VPN details Cancel button unavailable") }
    try press(cancel)
    for _ in 0..<20 {
        if try vpnDetailsSheet(window("com.apple.systempreferences")) == nil { return }
        Thread.sleep(forTimeInterval: 0.1)
    }
    try fail("VPN details did not close")
}
// Verify the selected profile's two hostname fields without printing any field values.
func verifyVPN(_ index: Int, _ count: Int, _ expected: String, byName: Bool = false) throws {
    _ = try vpnSwitch(index, count)
    let root = try window("com.apple.systempreferences")
    let details = nodes(root).filter {
        ["세부사항 보기", "Show Details"].contains(str($0, kAXDescriptionAttribute)) ||
        ["세부사항 보기", "Show Details"].contains(str($0, kAXTitleAttribute))
    }
    guard details.count == count else { try fail("VPN details buttons changed; recalibrate online") }
    try press(details[index])
    defer { try? closeVPNDetails() }
    for _ in 0..<20 {
        let w = try window("com.apple.systempreferences")
        if let sheet = vpnDetailsSheet(w) {
            // Only compare non-secure text fields to the supplied public hostname.
            let fields = nodes(sheet).filter { str($0, kAXRoleAttribute) == "AXTextField" }
            let matching = fields.filter { str($0, kAXValueAttribute) == expected }
            guard matching.count == (byName ? 1 : 2) else { try fail("VPN details do not match the expected profile") }
            try closeVPNDetails()
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
    var args = Array(CommandLine.arguments.dropFirst())
    if args.first == "--fl-map" {
        guard args.count >= 3 else { try fail("Expected calibration path and action") }
        let data = try Data(contentsOf: URL(fileURLWithPath: args[1]))
        flMap = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard flMap != nil else { try fail("Invalid FlClash calibration") }
        args.removeFirst(2)
    }
    guard let action = args.first else { try fail("Expected fl-state, fl-set, vpn-verify, vpn-state, or vpn-set") }
    switch action {
    case "vpn-close": try closeVPNDetails(); try output(["closed": true])
    case "fl-frame": try output(geometry(window("com.follow.clash")))
    case "fl-diagnose":
        try output(NSRunningApplication.runningApplications(withBundleIdentifier: "com.follow.clash").map { app -> [String: Any] in
            let ax = AXUIElementCreateApplication(app.processIdentifier)
            var value: CFTypeRef?
            let status = AXUIElementCopyAttributeValue(ax, kAXWindowsAttribute as CFString, &value)
            let windows = appWindows(ax)
            var names: CFArray?
            AXUIElementCopyAttributeNames(ax, &names)
            return ["pid": app.processIdentifier, "axStatus": status.rawValue,
                    "attributes": names as? [String] ?? [],
                    "titles": windows.map { str($0, kAXTitleAttribute) },
                    "roles": windows.map { str($0, kAXRoleAttribute) }]
        })
    case "fl-engine-check", "fl-engine-start", "fl-engine-stop":
        let root = try window("com.follow.clash")
        _ = try calibratedPosition(root, "engine")
        let button = flEngineButton(root, starting: action == "fl-engine-start")
        if action != "fl-engine-check" {
            if let button {
                try press(button)
            } else {
                try fallbackClick(root, "engine")
            }
        }
        try output(["ok": true, "named_stop_button": button != nil])
    case "fl-state": try output(flState())
    case "fl-set":
        guard args.count == 3, ["tun", "proxy"].contains(args[1]), ["on", "off"].contains(args[2]) else { try fail("Invalid fl-set arguments") }
        try flSet(args[1], args[2] == "on"); try output(flState())
    case "vpn-verify", "vpn-verify-name", "vpn-state", "vpn-set":
        guard args.count >= 3, let index = Int(args[1]), let count = Int(args[2]) else { try fail("Expected zero-based VPN index and switch count") }
        if action == "vpn-verify" || action == "vpn-verify-name" {
            guard args.count == 4 else { try fail("Expected server hostname") }
            try verifyVPN(index, count, args[3], byName: action == "vpn-verify-name")
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
