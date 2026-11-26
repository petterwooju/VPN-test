import Foundation
import Network
import Darwin

struct PhysicalLink: Equatable {
    var interface = ""
    var transport = ""
    var prefix = ""
    var available = false

    static func detect(_ path: NWPath) -> Self {
        let candidates: [(NWInterface.InterfaceType, String)] = [(.wiredEthernet, "ethernet"), (.wifi, "wifi"), (.cellular, "cellular")]
        let interfaces = path.availableInterfaces
        // A VPN can become the primary NWPath interface. Choose the active,
        // addressed physical interface for endpoint lookup and history.
        let matches = candidates.sorted { lhs, rhs in
            path.usesInterfaceType(lhs.0) && !path.usesInterfaceType(rhs.0)
        }
        for (kind, name) in matches {
            for item in interfaces where item.type == kind {
                if let prefix = prefixForInterface(item.name) {
                    return Self(interface: item.name, transport: name, prefix: prefix, available: path.status == .satisfied)
                }
            }
        }
        return Self()
    }

    private static func prefixForInterface(_ name: String) -> String? {
        var first: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&first) == 0, let first else { return nil }
        defer { freeifaddrs(first) }
        var v6: String?
        for pointer in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let info = pointer.pointee
            guard String(cString: info.ifa_name) == name,
                  let addr = info.ifa_addr, let mask = info.ifa_netmask,
                  (info.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }
            if Int32(addr.pointee.sa_family) == AF_INET {
                let a = UnsafeRawPointer(addr).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr.s_addr
                let m = UnsafeRawPointer(mask).assumingMemoryBound(to: sockaddr_in.self).pointee.sin_addr.s_addr
                let subnet = UInt32(bigEndian: a & m)
                return [24, 16, 8, 0].map { String((subnet >> $0) & 255) }.joined(separator: ".") + "/\(m.nonzeroBitCount)"
            }
            if Int32(addr.pointee.sa_family) == AF_INET6 {
                var a = UnsafeRawPointer(addr).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                var m = UnsafeRawPointer(mask).assumingMemoryBound(to: sockaddr_in6.self).pointee.sin6_addr
                let bytes = withUnsafeBytes(of: &a, Array.init)
                guard bytes.first != 0xfe else { continue }
                let masks = withUnsafeBytes(of: &m, Array.init)
                v6 = zip(bytes, masks).map { String(format: "%02x", $0 & $1) }.joined()
            }
        }
        return v6
    }
}

@MainActor
final class UplinkMonitor: ObservableObject {
    @Published private(set) var link = PhysicalLink()
    private let monitor = NWPathMonitor()
    private let physicalMonitors = [NWInterface.InterfaceType.wiredEthernet, .wifi, .cellular].map {
        NWPathMonitor(requiredInterfaceType: $0)
    }
    private let queue = DispatchQueue(label: "CoreaVPN.Uplink")
    private var lastDefault = PhysicalLink()
    private var constrained: [Int: PhysicalLink] = [:]

    init() {
        monitor.pathUpdateHandler = { [weak self] path in
            let result = PhysicalLink.detect(path)
            Task { @MainActor in self?.lastDefault = result; self?.update() }
        }
        monitor.start(queue: queue)
        for (index, monitor) in physicalMonitors.enumerated() {
            monitor.pathUpdateHandler = { [weak self] path in
                let result = PhysicalLink.detect(path)
                Task { @MainActor in self?.constrained[index] = result; self?.update() }
            }
            monitor.start(queue: queue)
        }
    }
    private func update() {
        let physical = constrained.keys.sorted().compactMap { constrained[$0] }.filter(\.available)
        // The physical route may still be up when the default path reports
        // only the newly established VPN's virtual interface.
        let current = lastDefault.available ? lastDefault : (
            physical.first(where: { $0.interface == link.interface }) ?? physical.first ?? PhysicalLink())
        if current != link { link = current }
    }
    deinit { monitor.cancel(); physicalMonitors.forEach { $0.cancel() } }
}
