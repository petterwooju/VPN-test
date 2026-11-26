#if os(macOS)
import AppKit
import Combine
import Darwin
import Foundation
import SystemConfiguration

@MainActor
final class MacDashboardMetrics: ObservableObject {
    struct TrafficPoint: Identifiable {
        let date: Date
        let downloadBytesPerSecond: Double
        let uploadBytesPerSecond: Double
        var id: Date { date }
    }

    @Published private(set) var traffic: [TrafficPoint] = []
    @Published private var status = DashboardReader.Status()
    var downloadBytesPerSecond: Double? { traffic.last?.downloadBytesPerSecond }
    var uploadBytesPerSecond: Double? { traffic.last?.uploadBytesPerSecond }
    var localIPv4: String? { status.localIPv4 }
    var memoryBytes: Int64? { status.memoryBytes }
    var proxyServices: [String]? { status.proxyServices }
    var routeInterface: String? { status.routeInterface }
    var flClashRunning: Bool { status.flClashRunning }

    /// Run from a view task keyed by the active physical interface. Its cancellation stops sampling.
    func observe(interface: String) async {
        guard !Task.isCancelled else { return }
        let reader = DashboardReader()
        var previous: DashboardReader.Counters?
        var tick = 0
        traffic = []
        status = DashboardReader.Status()
        while !Task.isCancelled {
            let snapshot = await reader.read(interface: interface, includeStatus: tick == 0)
            guard !Task.isCancelled else { return }
            if let details = snapshot.status { status = details }
            if let new = snapshot.counters, let old = previous, new.index == old.index,
               new.received >= old.received, new.sent >= old.sent,
               new.uptime > old.uptime, new.uptime - old.uptime < 5 {
                let elapsed = new.uptime - old.uptime
                if traffic.count == 60 { traffic.removeFirst() }
                traffic.append(TrafficPoint(date: snapshot.date,
                                            downloadBytesPerSecond: Double(new.received - old.received) / elapsed,
                                            uploadBytesPerSecond: Double(new.sent - old.sent) / elapsed))
            } else if !traffic.isEmpty {
                traffic = []
            }
            previous = snapshot.counters
            tick = (tick + 1) % 5
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
        }
    }
}

/// All queries read local OS state. The route lookup selects a source address without sending a packet.
private actor DashboardReader {
    struct Status {
        var localIPv4: String?
        var memoryBytes: Int64?
        var proxyServices: [String]?
        var routeInterface: String?
        var flClashRunning = !NSRunningApplication.runningApplications(withBundleIdentifier: "com.follow.clash").isEmpty
    }

    struct Counters {
        let index: UInt32
        let received: UInt64
        let sent: UInt64
        let uptime: Double
    }

    func read(interface: String, includeStatus: Bool) -> (date: Date, counters: Counters?, status: Status?) {
        let counts = Self.counters(interface: interface)
        let date = Date()
        let status = includeStatus ? Status(localIPv4: Self.ipv4(interface: interface),
                                            memoryBytes: Self.residentMemory(),
                                            proxyServices: Self.enabledProxies(),
                                            routeInterface: try? TunnelProbe.routeInterface()) : nil
        return (date, counts, status)
    }

    /// NET_RT_IFLIST2 exposes 64-bit counters. getifaddrs' if_data byte fields wrap at 4 GiB.
    private static func counters(interface: String) -> Counters? {
        let index = if_nametoindex(interface)
        guard index != 0 else { return nil }
        var mib = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, Int32(index)]
        var size = 0
        guard sysctl(&mib, 6, nil, &size, nil, 0) == 0,
              size >= MemoryLayout<if_msghdr2>.size else { return nil }
        var buffer = Data(count: size)
        return buffer.withUnsafeMutableBytes { bytes -> Counters? in
            guard sysctl(&mib, 6, bytes.baseAddress, &size, nil, 0) == 0,
                  size >= MemoryLayout<if_msghdr2>.size else { return nil }
            // A single-interface IFLIST response starts with its interface header, then its addresses.
            let header = bytes.loadUnaligned(as: if_msghdr2.self)
            guard header.ifm_type == RTM_IFINFO2, header.ifm_index == index else { return nil }
            return Counters(index: index, received: header.ifm_data.ifi_ibytes, sent: header.ifm_data.ifi_obytes,
                            uptime: ProcessInfo.processInfo.systemUptime)
        }
    }

    private static func ipv4(interface: String) -> String? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard !interface.isEmpty, getifaddrs(&first) == 0, let first else { return nil }
        defer { freeifaddrs(first) }
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let item = pointer.pointee
            guard String(cString: item.ifa_name) == interface,
                  let address = item.ifa_addr, Int32(address.pointee.sa_family) == AF_INET else { continue }
            var host = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0,
                           NI_NUMERICHOST) == 0 { return String(cString: host) }
        }
        return nil
    }

    private static func enabledProxies() -> [String]? {
        guard let settings = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return nil }
        let modes = [("HTTPEnable", "HTTP"), ("HTTPSEnable", "HTTPS"), ("SOCKSEnable", "SOCKS"),
                     ("ProxyAutoConfigEnable", "PAC"), ("ProxyAutoDiscoveryEnable", "WPAD")]
        return modes.compactMap { key, label in
            (settings[key] as? NSNumber)?.boolValue == true ? label : nil
        }
    }

    private static func residentMemory() -> Int64? {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout.size(ofValue: info) / MemoryLayout<integer_t>.size)
        let status = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return status == KERN_SUCCESS ? Int64(info.resident_size) : nil
    }
}
#endif
