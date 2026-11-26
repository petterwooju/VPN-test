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
func window(_ bundle: String, activate: Bool = true) throws -> AXUIElement {
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
            if activate { app.activate(options: [.activateAllWindows]) }
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
            if let element = try? namedSwitch(root, labels: labels) {
                if try bool(element) != desired { try press(element) }
            } else {
                try fallbackClick(root, key)
            }
        }
    } else {
        let element = try namedSwitch(root, labels: labels)
        if try bool(element) != desired { try press(element) }
    }
    for _ in 0..<20 {
        // macOS applies the HTTP, HTTPS and SOCKS flags in separate updates.
        if let observed = try? flState(), observed[key] == desired { return }
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
func vpnSwitch(_ index: Int, _ count: Int, activate: Bool = true) throws -> AXUIElement {
    let root = try window("com.apple.systempreferences", activate: activate)
    guard ["VPN"].contains(str(root, kAXTitleAttribute)) else { try fail("System Settings must remain on VPN") }
    guard vpnDetailsSheet(root) == nil else {
        try fail("Close the VPN details sheet before running")
    }
    let items = switches(root)
    guard items.count == count, index >= 0, index < count else { try fail("VPN list changed; recalibrate online") }
    return items[index]
}
// A settings URL can return before the window and profile list are published.
func openVPNPane(expectedCount: Int) throws {
    guard AXIsProcessTrusted() else { try fail("Accessibility access missing") }
    let url = URL(string: "x-apple.systempreferences:com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension")!
    guard NSWorkspace.shared.open(url) else { try fail("Could not open VPN in System Settings") }
    let deadline = ProcessInfo.processInfo.systemUptime + 10
    while ProcessInfo.processInfo.systemUptime < deadline {
        if let root = try? window("com.apple.systempreferences") {
            guard vpnDetailsSheet(root) == nil else { try fail("Close the open VPN details sheet before starting") }
            if switches(root).count == expectedCount { return }
        }
        Thread.sleep(forTimeInterval: 0.25)
    }
    try fail("System Settings did not present a unique VPN window with the expected profile count")
}
func closeVPNDetails(_ expected: AXUIElement? = nil) throws {
    let root = try window("com.apple.systempreferences")
    guard let sheet = vpnDetailsSheet(root) else { return }
    if let expected, !CFEqual(sheet, expected) { try fail("VPN details sheet changed before dismissal") }
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
func openVPNDetails(_ index: Int, _ count: Int) throws -> AXUIElement {
    _ = try vpnSwitch(index, count)
    let root = try window("com.apple.systempreferences")
    let details = nodes(root).filter {
        ["세부사항 보기", "Show Details"].contains(str($0, kAXDescriptionAttribute)) ||
        ["세부사항 보기", "Show Details"].contains(str($0, kAXTitleAttribute))
    }
    guard details.count == count else { try fail("VPN details buttons changed; recalibrate online") }
    return try openVPNDetails(button: details[index], root: root)
}
func openVPNDetails(button: AXUIElement, root: AXUIElement) throws -> AXUIElement {
    guard vpnDetailsSheet(root) == nil else { try fail("Close the open VPN details sheet before starting") }
    try press(button)
    for _ in 0..<20 {
        if let sheet = vpnDetailsSheet(root) { return sheet }
        Thread.sleep(forTimeInterval: 0.2)
    }
    try fail("VPN details did not open")
}

// Keep the switch and its own Details button together. A cached index is only a
// search hint. AX objects from a fresh list, never a subsequent lookup by
// position, are used to press a switch or open its configuration.
struct VPNRow {
    let toggle: AXUIElement
    let details: AXUIElement
    var labels: Set<String>
}

func midY(_ element: AXUIElement) -> (center: Double, height: Double)? {
    guard let frame = try? geometry(element), let y = frame["y"], let height = frame["height"], height > 0 else { return nil }
    return (y + height / 2, height)
}

func namedVPNRows(_ root: AXUIElement) throws -> [VPNRow] {
    var toggles: [AXUIElement] = [], buttons: [AXUIElement] = []
    var rowLabels: [Set<String>] = [], rowButtons: [Set<Int>] = []
    var looseText: [(AXUIElement, Set<String>)] = []
    func visit(_ element: AXUIElement, depth: Int) -> (rows: [Int], details: [Int], labels: Set<String>) {
        var rows: [Int] = [], details: [Int] = [], labels: Set<String> = []
        let role = str(element, kAXRoleAttribute)
        if ["AXCheckBox", "AXSwitch"].contains(role) {
            rows.append(toggles.count)
            toggles.append(element)
            rowButtons.append([])
            // The switch's own title and its explicitly associated title element.
            rowLabels.append(Set([str(element, kAXTitleAttribute), str(element, kAXDescriptionAttribute)]))
            if let title = attr(element, kAXTitleUIElementAttribute), CFGetTypeID(title) == AXUIElementGetTypeID() {
                let label = title as! AXUIElement
                rowLabels[rows[0]].formUnion([str(label, kAXValueAttribute), str(label, kAXTitleAttribute)])
            }
        } else if role == "AXButton" && [kAXDescriptionAttribute, kAXTitleAttribute].contains(where: {
            ["세부사항 보기", "Show Details"].contains(str(element, $0))
        }) {
            details.append(buttons.count)
            buttons.append(element)
        } else if role == "AXStaticText" {
            labels = Set([str(element, kAXValueAttribute), str(element, kAXTitleAttribute)])
            labels.remove("")
            if !labels.isEmpty { looseText.append((element, labels)) }
        } else if ["AXGroup", "AXCell", "AXRow"].contains(role) {
            // SwiftUI can put the profile label on the row instead of a text child.
            labels = Set([str(element, kAXTitleAttribute), str(element, kAXDescriptionAttribute)])
            labels.remove("")
        }
        if depth < 25 {
            for child in attr(element, kAXChildrenAttribute) as? [AXUIElement] ?? [] {
                let content = visit(child, depth: depth + 1)
                rows += content.rows
                details += content.details
                labels.formUnion(content.labels)
            }
        }
        if rows.count == 1 {
            rowLabels[rows[0]].formUnion(labels)
            rowButtons[rows[0]].formUnion(details)
        }
        return (rows, details, labels)
    }
    _ = visit(root, depth: 0)
    guard !toggles.isEmpty, toggles.count == buttons.count else { try fail("VPN list does not expose one Details button per switch") }
    // Some Settings versions publish a flat list. Associate visible controls by
    // vertical overlap only when exactly one row fits. Actions still target AX objects.
    let centers = toggles.map(midY)
    func alignedRow(_ element: AXUIElement) -> Int? {
        guard let frame = midY(element) else { return nil }
        let hits = centers.indices.filter { index in
            guard let row = centers[index] else { return false }
            return abs(row.center - frame.center) < (row.height + frame.height) / 2
        }
        return hits.count == 1 ? hits[0] : nil
    }
    for (element, labels) in looseText {
        if let index = alignedRow(element) { rowLabels[index].formUnion(labels) }
    }
    let alignedButtons = buttons.map(alignedRow)
    var used: Set<Int> = []
    return try toggles.indices.map { index in
        if rowButtons[index].isEmpty {
            rowButtons[index] = Set(alignedButtons.indices.filter { alignedButtons[$0] == index })
        }
        guard rowButtons[index].count == 1, let buttonIndex = rowButtons[index].first,
              used.insert(buttonIndex).inserted else { try fail("Could not uniquely pair each VPN switch with its Details button") }
        return VPNRow(toggle: toggles[index], details: buttons[buttonIndex], labels: rowLabels[index])
    }
}

func currentVPNPane() throws -> AXUIElement {
    if let root = try? window("com.apple.systempreferences", activate: false) {
        guard vpnDetailsSheet(root) == nil else { try fail("Close the open VPN details sheet before starting") }
        if !switches(root).isEmpty { return root }
    }
    guard AXIsProcessTrusted() else { try fail("Accessibility access missing") }
    let url = URL(string: "x-apple.systempreferences:com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension")!
    guard NSWorkspace.shared.open(url) else { try fail("Could not open VPN in System Settings") }
    for _ in 0..<40 {
        if let root = try? window("com.apple.systempreferences", activate: false) {
            guard vpnDetailsSheet(root) == nil else { try fail("Close the open VPN details sheet before starting") }
            if !switches(root).isEmpty { return root }
        }
        Thread.sleep(forTimeInterval: 0.25)
    }
    try fail("VPN list unavailable in System Settings")
}

func vpnField(_ sheet: AXUIElement, labels: [String]) throws -> AXUIElement {
    let matches = nodes(sheet).filter { element in
        guard str(element, kAXRoleAttribute) == "AXTextField" else { return false }
        let keys = [kAXTitleAttribute, kAXDescriptionAttribute, kAXHelpAttribute, "AXLabel", "AXIdentifier"]
        if keys.contains(where: { labels.contains(str(element, $0)) }) { return true }
        guard let label = attr(element, kAXTitleUIElementAttribute),
              CFGetTypeID(label) == AXUIElementGetTypeID() else { return false }
        return [kAXValueAttribute, kAXTitleAttribute, kAXDescriptionAttribute].contains {
            labels.contains(str(label as! AXUIElement, $0))
        }
    }
    guard matches.count == 1 else { try fail("Could not identify the VPN field: " + labels[0]) }
    return matches[0]
}

func rowHasDisplayName(_ row: VPNRow, root: AXUIElement, name: String) throws -> Bool {
    let sheet = try openVPNDetails(button: row.details, root: root)
    do {
        let field = try vpnField(sheet, labels: ["표시 이름", "Display Name"])
        let match = str(field, kAXValueAttribute) == name
        try closeVPNDetails(sheet)
        return match
    } catch {
        try? closeVPNDetails(sheet)
        throw error
    }
}

struct NamedVPN {
    let root: AXUIElement
    let row: VPNRow
    let index: Int
    let count: Int
    let verifiedInSheet: Bool
    func status() throws -> [String: Any] { ["index": index, "count": count, "on": try bool(row.toggle)] }
}

// A row displaying only a generic status has no usable profile label. Treat
// repeated metadata as opaque too, except for explicit matches (duplicates).
func namedRowIndex(labels: [Set<String>], name: String, hint: Int, expectedCount: Int?,
                   inspect: (Int) throws -> Bool) throws -> (index: Int, inspected: Bool) {
    let generic: Set<String> = ["", "vpn", "ikev2", "on", "off", "switch", "connected", "disconnected",
        "not connected", "connecting", "disconnecting", "connect", "disconnect", "연결", "연결됨", "연결 안 됨",
        "연결되지 않음", "연결 해제됨", "연결 중", "연결 해제 중", "켬", "끔", "스위치"]
    var frequencies: [String: Int] = [:]
    for row in labels {
        for label in row where !generic.contains(label.lowercased()) { frequencies[label, default: 0] += 1 }
    }
    let explicit = labels.indices.filter { labels[$0].contains(name) }
    guard explicit.count <= 1 else { try fail("Duplicate VPN display name: " + name) }
    let opaque = labels.indices.filter { index in
        // A composed accessibility description is only a hint to inspect the
        // exact Display Name field. It never authorizes a switch press.
        labels[index].contains(where: { $0 != name && $0.contains(name) }) ||
        !labels[index].contains(where: { frequencies[$0] == 1 })
    }
    let sameList = labels.count == expectedCount && labels.indices.contains(hint)
    if sameList, explicit.first == hint { return (hint, false) }
    let verifyHint = sameList && explicit.isEmpty && opaque.contains(hint)
    if verifyHint {
        // Initial discovery checked all opaque rows. Confirm that very row still
        // has the same Display Name before reusing the hint.
        if try inspect(hint) { return (hint, true) }
    }
    var matched = explicit.first
    let order = (opaque.contains(hint) && !verifyHint ? [hint] : []) + opaque.filter { $0 != hint }
    for index in order where index != explicit.first {
        if try inspect(index) {
            guard matched == nil else { try fail("Duplicate VPN display name: " + name) }
            matched = index
        }
    }
    guard let matched else { try fail("Could not locate the named VPN profile: " + name) }
    return (matched, explicit.first != matched)
}

func locateVPN(name: String, hint: Int, expectedCount: Int? = nil) throws -> NamedVPN {
    guard !name.isEmpty else { try fail("Expected VPN display name") }
    let root = try currentVPNPane()
    let rows = try namedVPNRows(root)
    let result = try namedRowIndex(labels: rows.map(\.labels), name: name, hint: hint, expectedCount: expectedCount) {
        try rowHasDisplayName(rows[$0], root: root, name: name)
    }
    return NamedVPN(root: root, row: rows[result.index], index: result.index, count: rows.count,
                    verifiedInSheet: result.inspected)
}

func typeVPNField(_ element: AXUIElement, value: String) throws {
    var pid: pid_t = 0
    guard AXUIElementGetPid(element, &pid) == .success,
          AXUIElementSetAttributeValue(element, kAXFocusedAttribute as CFString, kCFBooleanTrue) == .success
    else { try fail("Could not focus the verified VPN endpoint field") }
    // Selection and replacement target this exact AX element, not global keyboard focus.
    var range = CFRange(location: 0, length: str(element, kAXValueAttribute).utf16.count)
    guard let selected = AXValueCreate(.cfRange, &range),
          AXUIElementSetAttributeValue(element, kAXSelectedTextRangeAttribute as CFString, selected) == .success,
          AXUIElementSetAttributeValue(element, kAXSelectedTextAttribute as CFString, value as CFString) == .success
    else { try fail("Could not replace text in the verified VPN endpoint field") }
    for _ in 0..<15 {
        if str(element, kAXValueAttribute) == value { return }
        Thread.sleep(forTimeInterval: 0.1)
    }
    try fail("VPN endpoint field did not accept typed text")
}
// Only return and modify the public fields of the exact named test profile.
func vpnEndpoints(_ index: Int, _ count: Int, name: String,
                  server: String? = nil, remoteID: String? = nil) throws -> [String: String] {
    let target = try locateVPN(name: name, hint: index, expectedCount: count)
    guard try !bool(target.row.toggle) else { try fail("Disconnect the VPN before editing its endpoints") }
    let sheet = try openVPNDetails(button: target.row.details, root: target.root)
    defer { try? closeVPNDetails(sheet) }
    let display = try vpnField(sheet, labels: ["표시 이름", "Display Name"])
    guard str(display, kAXValueAttribute) == name else { try fail("Unexpected VPN profile display name") }
    let address = try vpnField(sheet, labels: ["서버 주소", "Server Address"])
    let remote = try vpnField(sheet, labels: ["원격 ID", "Remote ID"])
    let current = ["server": str(address, kAXValueAttribute), "remote_id": str(remote, kAXValueAttribute)]
    let publicHost = #"^[a-z0-9-]+\.coreavpn\.(net|com|kr)$"#
    func accepted(address: String, remote: String) -> Bool {
        guard remote.range(of: publicHost, options: .regularExpression) != nil else { return false }
        if address.range(of: publicHost, options: .regularExpression) != nil { return true }
        guard name == "CoreaVPN_TEST", remote.hasSuffix(".coreavpn.net") else { return false }
        var ip = in_addr()
        guard inet_pton(AF_INET, address, &ip) == 1 else { return false }
        let n = UInt32(bigEndian: ip.s_addr), a = n >> 24, b = (n >> 16) & 255
        return a > 0 && a < 224 && a != 10 && a != 127 &&
            !(a == 169 && b == 254) && !(a == 172 && (16...31).contains(b)) &&
            !(a == 192 && b == 168) && !(a == 100 && (64...127).contains(b)) &&
            !(a == 198 && (18...19).contains(b)) &&
            ![0xc00000, 0xc00002, 0xc05863, 0xc63364, 0xcb0071].contains(n >> 8)
    }
    guard accepted(address: current["server"]!, remote: current["remote_id"]!) else {
        try fail("VPN endpoints must be public CoreaVPN hostnames")
    }
    guard let server, let remoteID else {
        try closeVPNDetails(sheet)
        return current
    }
    guard accepted(address: server, remote: remoteID) else {
        try fail("Refusing an unrecognized VPN hostname")
    }
    if current == ["server": server, "remote_id": remoteID] {
        try closeVPNDetails(sheet)
        return current
    }

    let buttons = nodes(sheet).filter { element in
        str(element, kAXRoleAttribute) == "AXButton" &&
        [kAXTitleAttribute, kAXDescriptionAttribute].contains { ["확인", "OK"].contains(str(element, $0)) }
    }
    guard buttons.count == 1 else { try fail("VPN settings OK button unavailable") }
    var pid: pid_t = 0
    if AXUIElementGetPid(sheet, &pid) == .success {
        AXUIElementSetAttributeValue(AXUIElementCreateApplication(pid), kAXFrontmostAttribute as CFString, kCFBooleanTrue)
        AXUIElementPerformAction(sheet, kAXRaiseAction as CFString)
    }
    for (element, value) in [(address, server), (remote, remoteID)] {
        if str(element, kAXValueAttribute) != value { try typeVPNField(element, value: value) }
    }
    _ = AXUIElementSetAttributeValue(display, kAXFocusedAttribute as CFString, kCFBooleanTrue)
    for _ in 0..<15 {
        if (attr(buttons[0], kAXEnabledAttribute) as? NSNumber)?.boolValue == true { break }
        Thread.sleep(forTimeInterval: 0.1)
    }
    guard (attr(buttons[0], kAXEnabledAttribute) as? NSNumber)?.boolValue == true else { try fail("VPN settings did not enable saving") }
    try press(buttons[0])
    for _ in 0..<20 {
        if try vpnDetailsSheet(window("com.apple.systempreferences")) == nil {
            return try vpnEndpoints(index, count, name: name)
        }
        Thread.sleep(forTimeInterval: 0.1)
    }
    try fail("VPN settings did not close after saving")
}

// Verify the selected profile's two hostname fields without printing any field values.
func inspectVPN(_ index: Int, _ count: Int, expected: String? = nil, byName: Bool = false) throws -> String? {
    let sheet = try openVPNDetails(index, count)
    defer { try? closeVPNDetails(sheet) }
    let fields = nodes(sheet).filter { str($0, kAXRoleAttribute) == "AXTextField" }
    if let expected {
        let matched: Bool
        if byName {
            matched = str(try vpnField(sheet, labels: ["표시 이름", "Display Name"]), kAXValueAttribute) == expected
        } else {
            matched = fields.filter { str($0, kAXValueAttribute) == expected }.count == 2
        }
        guard matched else { try fail("VPN details do not match the expected profile") }
        try closeVPNDetails(sheet)
        return expected
    }
    let publicHosts = fields.map { str($0, kAXValueAttribute) }.filter {
        $0.range(of: #"^[a-z0-9-]+\.coreavpn\.(net|com|kr)$"#,
                 options: .regularExpression) != nil
    }
    try closeVPNDetails(sheet)
    return publicHosts.count == 2 && publicHosts[0] == publicHosts[1] ? publicHosts[0] : nil
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
    case "quick-capabilities":
        guard AXIsProcessTrusted() else { try fail("Accessibility access missing; no settings changed") }
        try output(["numeric_endpoint": true, "release_button": true, "named_profiles": true])
    case "quick-passive-state":
        guard args.count == 3, let index = Int(args[1]), let count = Int(args[2]) else {
            try fail("Expected the selected test profile slot and count")
        }
        try output(["on": try bool(vpnSwitch(index, count, activate: false))])
    case "quick-press-release", "quick-release-ready":
        guard args.count == 1, AXIsProcessTrusted() else { try fail("Accessibility access required") }
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: "net.petterwooju.coreavpn.preview")
        guard apps.count == 1 else { try fail("Expected exactly one CoreaVPN preview app") }
        let ax = AXUIElementCreateApplication(apps[0].processIdentifier)
        AXUIElementSetMessagingTimeout(ax, 2)
        let buttons = appWindows(ax).flatMap { nodes($0) }.filter {
            str($0, kAXRoleAttribute) == "AXButton" &&
            str($0, kAXIdentifierAttribute) == "quick-release" &&
            (attr($0, kAXEnabledAttribute) as? NSNumber)?.boolValue == true
        }
        guard buttons.count == 1 else { try fail("Expected exactly one enabled quick-release button") }
        if action == "quick-press-release" { try press(buttons[0]) }
        try output(["ok": true, "pressed": action == "quick-press-release"])
    case "vpn-locate", "vpn-name-state", "vpn-name-set":
        let locate = action == "vpn-locate", setting = action == "vpn-name-set"
        guard args.count == (locate ? 3 : setting ? 5 : 4), let hint = Int(args[1]),
              locate || Int(args[2]) != nil else { try fail("Expected a VPN row hint and display name") }
        let name = args[locate ? 2 : 3]
        var target = try locateVPN(name: name, hint: hint, expectedCount: locate ? nil : Int(args[2]))
        if setting {
            guard ["on", "off"].contains(args[4]) else { try fail("Expected on/off") }
            if try bool(target.row.toggle) != (args[4] == "on") {
                guard try target.verifiedInSheet || rowHasDisplayName(target.row, root: target.root, name: name) else {
                    try fail("VPN profile changed before switching")
                }
                // AX objects become invalid if Settings rebuilds the list on sheet dismissal.
                // Use the original verified switch only while its row still belongs to this list.
                let current = try namedVPNRows(target.root)
                let labeled = current.indices.filter { current[$0].labels.contains(name) }
                guard labeled.count <= 1 else { try fail("Duplicate VPN display name: " + name) }
                if let index = labeled.first {
                    target = NamedVPN(root: target.root, row: current[index], index: index, count: current.count,
                                      verifiedInSheet: false)
                } else if !current.contains(where: { CFEqual($0.toggle, target.row.toggle) && CFEqual($0.details, target.row.details) }) {
                    try fail("VPN row changed before switching")
                }
                if try bool(target.row.toggle) != (args[4] == "on") { try press(target.row.toggle) }
            }
        }
        try output(target.status())
    case "vpn-close-clean":
        guard args.count == 2 else { try fail("Expected the selected VPN display name") }
        if let root = try? window("com.apple.systempreferences", activate: false), let sheet = vpnDetailsSheet(root) {
            let field = try vpnField(sheet, labels: ["표시 이름", "Display Name"])
            let buttons = nodes(sheet).filter { element in
                str(element, kAXRoleAttribute) == "AXButton" &&
                [kAXTitleAttribute, kAXDescriptionAttribute].contains { ["확인", "OK"].contains(str(element, $0)) }
            }
            guard str(field, kAXValueAttribute) == args[1], buttons.count == 1,
                  (attr(buttons[0], kAXEnabledAttribute) as? NSNumber)?.boolValue == false else {
                try fail("Close the open VPN details sheet to continue recovery")
            }
            try closeVPNDetails(sheet)
        }
        try output(["ready": true])
    case "vpn-open":
        guard args.count == 2, let count = Int(args[1]), count > 0 else { try fail("Expected VPN profile count") }
        try openVPNPane(expectedCount: count)
        try output(["ready": true])
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
    case "vpn-endpoints", "vpn-retarget":
        guard args.count == (action == "vpn-retarget" ? 6 : 4),
              let index = Int(args[1]), let count = Int(args[2]) else { try fail("Expected VPN slot and profile name") }
        let changing = action == "vpn-retarget"
        try output(vpnEndpoints(index, count, name: args[3],
                                server: changing ? args[4] : nil, remoteID: changing ? args[5] : nil))
    case "vpn-inventory", "vpn-verify", "vpn-verify-name", "vpn-state", "vpn-set":
        guard args.count >= 3, let index = Int(args[1]), let count = Int(args[2]) else { try fail("Expected zero-based VPN index and switch count") }
        if action == "vpn-inventory" {
            let server = try inspectVPN(index, count)
            try output(["server": server as Any? ?? NSNull(), "on": try bool(vpnSwitch(index, count))])
            break
        }
        if action == "vpn-verify" || action == "vpn-verify-name" {
            guard args.count == 4 else { try fail("Expected server hostname") }
            _ = try inspectVPN(index, count, expected: args[3], byName: action == "vpn-verify-name")
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
