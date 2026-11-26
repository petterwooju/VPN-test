#if os(macOS)
import AppKit
import Darwin
import Foundation
import SystemConfiguration

/// A read-only snapshot of connected peers reported by macOS. A socket's interface
/// identifies its immediate path, but cannot identify a transparent proxy's final exit.
enum MacSocketConnections {
    private struct VPNSession: Equatable {
        let serviceID: String
        let interface: String
        let index: UInt32
        let connectTime: Double

        // System Settings can expose profiles which SCNetworkService does not.
        // Without the named service and its own live session metadata, withhold attribution.
        static func current() -> Self? {
            guard let preferences = SCPreferencesCreate(nil, "CoreaVPN live connections" as CFString, nil),
                  let services = SCNetworkServiceCopyAll(preferences) as? [SCNetworkService] else { return nil }
            let matches = services.filter { SCNetworkServiceGetName($0) as String? == "CoreaVPN_TEST" }
            guard matches.count == 1, let serviceID = SCNetworkServiceGetServiceID(matches[0]),
                  let connection = SCNetworkConnectionCreateWithServiceID(nil, serviceID, nil, nil),
                  SCNetworkConnectionGetStatus(connection) == .connected,
                  let details = SCNetworkConnectionCopyExtendedStatus(connection) as? [String: Any],
                  let status = (details["VPN"] ?? details["IPSec"]) as? [String: Any],
                  let time = (status["ConnectTime"] as? NSNumber)?.doubleValue, time > 0,
                  let store = SCDynamicStoreCreate(nil, "CoreaVPN live connections" as CFString, nil, nil) else { return nil }
            let id = serviceID as String
            let setupKey = "Setup:/Network/Service/\(id)/Interface" as CFString
            guard let setup = SCDynamicStoreCopyValue(store, setupKey) as? [String: Any],
                  setup["SubType"] as? String == "IKEv2" else { return nil }
            let ipv4Key = "State:/Network/Service/\(id)/IPv4" as CFString
            guard let ip = SCDynamicStoreCopyValue(store, ipv4Key) as? [String: Any],
                  let interface = ip["InterfaceName"] as? String,
                  interface.hasPrefix("ipsec"), UInt32(interface.dropFirst(5)) != nil else { return nil }
            let index = if_nametoindex(interface)
            guard index != 0 else { return nil }
            return Self(serviceID: id, interface: interface, index: index, connectTime: time)
        }
    }

    private enum SampleError: LocalizedError {
        case unavailable, timedOut, tooLarge
        var errorDescription: String? {
            switch self {
            case .unavailable: return "macOS에서 현재 소켓 정보를 읽을 수 없습니다."
            case .timedOut: return "Mac 소켓 조회 시간이 초과됐습니다."
            case .tooLarge: return "Mac 소켓 조회 결과가 너무 큽니다."
            }
        }
    }

    static func snapshot() async throws -> LiveConnectionSnapshot {
        let task = Task.detached(priority: .utility) {
            try Task.checkCancellation()
            let before = VPNSession.current()
            let data = try readSample()
            try Task.checkCancellation()
            let stableTunnel = before.flatMap { $0 == VPNSession.current() ? $0.interface : nil }
            return try parse(String(decoding: data, as: UTF8.self), confirmedVPNInterface: stableTunnel)
        }
        return try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
    }

    private static func readSample() throws -> Data {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        process.arguments = ["-n", "-L", "1", "-J", "interface,state"]
        process.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        try process.run()
        defer { if process.isRunning { process.terminate() } }
        let deadline = ProcessInfo.processInfo.systemUptime + 4
        let fd = output.fileHandleForReading.fileDescriptor
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        var buffer = [UInt8](repeating: 0, count: 32_768)
        var data = Data()
        while true {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SampleError.timedOut }
            let ready = poll(&descriptor, 1, 100)
            if ready == 0 || (ready < 0 && errno == EINTR) { continue }
            guard ready > 0 else { throw SampleError.unavailable }
            let count = read(fd, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw SampleError.unavailable }
            if count == 0 { break }
            guard data.count + count <= 4 * 1024 * 1024 else { throw SampleError.tooLarge }
            data.append(contentsOf: buffer.prefix(count))
        }
        while process.isRunning {
            try Task.checkCancellation()
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw SampleError.timedOut }
            Thread.sleep(forTimeInterval: 0.015)
        }
        guard process.terminationStatus == 0 else { throw SampleError.unavailable }
        return data
    }

    static func parse(_ text: String, confirmedVPNInterface: String? = nil) throws -> LiveConnectionSnapshot {
        var lines = text.split(whereSeparator: \.isNewline).makeIterator()
        guard let header = lines.next() else { throw SampleError.unavailable }
        // nettop's process names can contain commas. Consume the two named data
        // columns from the right instead of treating commas inside names as fields.
        let columns = header.split(separator: ",", omittingEmptySubsequences: false)
        guard columns.count >= 3, columns[0].isEmpty,
              Set(columns[1...2]) == Set(["interface", "state"]) else { throw SampleError.unavailable }
        let interfaceFirst = columns[1] == "interface"
        var process: (pid: Int32, name: String)?
        var apps = [Int32: (String, String?)]()
        var rows = [MacLiveConnection]()
        var ids = Set<String>()
        for line in lines {
            var fields = line[...]
            if header.last == ",", fields.last == "," { fields.removeLast() }
            guard let last = fields.lastIndex(of: ",") else { continue }
            let tail = fields[fields.index(after: last)...]
            fields = fields[..<last]
            guard let middle = fields.lastIndex(of: ",") else { continue }
            let mid = fields[fields.index(after: middle)...]
            let interface = interfaceFirst ? mid : tail
            let state = interfaceFirst ? tail : mid
            let label = fields[..<middle].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let arrow = label.range(of: "<->") else {
                process = nil
                let name = label.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
                if let dot = name.lastIndex(of: "."), let pid = Int32(name[name.index(after: dot)...]) {
                    process = (pid, String(name[..<dot]).replacingOccurrences(of: "\"\"", with: "\""))
                }
                continue
            }
            guard let process, let blank = label.firstIndex(of: " ") else { continue }
            let proto = label[..<blank].lowercased()
            guard ["tcp4","tcp6","udp4","udp6"].contains(proto),
                  !proto.hasPrefix("tcp") || state.lowercased() == "established" else { continue }
            let peer = label[arrow.upperBound...]
            // IPv4 nettop endpoints use address:port, IPv6 endpoints use address.port.
            guard let separator = peer.lastIndex(of: proto.hasSuffix("6") ? "." : ":"),
                  let port = Int(peer[peer.index(after: separator)...]), (1...65535).contains(port) else { continue }
            let ip = String(peer[..<separator])
            guard !ip.isEmpty, ip != "*", ip != "0.0.0.0", ip != "::" else { continue }
            let id = "\(process.pid)|\(label)"
            guard ids.insert(id).inserted, rows.count < 512 else { continue }
            let app = apps[process.pid] ?? {
                let running = NSRunningApplication(processIdentifier: process.pid)
                return (running?.localizedName ?? process.name, running?.bundleIdentifier)
            }()
            apps[process.pid] = app
            let interfaceName = String(interface)
            let usesVPN = confirmedVPNInterface == interfaceName && !interfaceName.isEmpty
            rows.append(MacLiveConnection(id: id, app: app.0, bundleID: app.1, host: ip, ip: ip, port: port,
                                          transport: proto.hasPrefix("tcp") ? "TCP" : "UDP",
                                          rule: "", egress: usesVPN ? "coreaVPN" : "unknown", interface: interfaceName))
        }
        return LiveConnectionSnapshot(version: 1, total: ids.count, connections: rows)
    }
}
#endif
