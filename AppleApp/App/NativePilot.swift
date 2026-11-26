#if os(macOS)
import Foundation
import Security

@MainActor enum NativePilot {
    static func run(_ action: String, arguments: [String]) async throws -> [String: Any] {
        guard let code = SecTaskCreateFromSelf(nil),
              let permissions = SecTaskCopyValueForEntitlement(code, "com.apple.developer.networking.vpn.api" as CFString, nil) as? [String],
              permissions.contains("allow-vpn") else {
            throw ClientIssue.message("Personal VPN 권한으로 서명한 설치본이 필요합니다.")
        }
        let vpn = NativeVPN()
        if action == "--pilot-disconnect" {
            try await vpn.disconnect()
            return ["ok": true]
        }
        let baseline = try await vpn.snapshot()
        guard baseline.host != nil, !baseline.connected, !baseline.onDemand,
              try vpn.configuredCredentialUsername() != nil else {
            throw ClientIssue.message("먼저 앱에서 계정과 VPN 구성을 저장하고 CoreaVPN을 해제해 주세요.")
        }
        if action == "--pilot-ready", arguments.isEmpty { return ["ok": true] }
        guard action == "--pilot-puma", arguments.count == 1, let interface = arguments.first,
              if_nametoindex(interface) != 0, try TunnelProbe.routeInterface() == interface else {
            throw ClientIssue.message("Puma 검사의 물리 회선을 확인하지 못했습니다.")
        }
        try vpn.checkExclusiveRoute()
        let host = "puma.coreavpn.net"
        let resolver = VPNResolver()
        let address = try await resolver.resolve(host, network: interface, interface: interface)
        let sample: [Double]
        do {
            try await vpn.connect(host: host, address: address, onDemand: false)
            sample = try await vpn.measure(host: host)
        } catch {
            let original = error
            try await vpn.restore(baseline)
            throw original
        }
        try await vpn.restore(baseline)
        return ["ok": true, "server": host, "address": address, "sent": 20, "received": sample.count,
                "mean_ms": sample.isEmpty ? NSNull() as Any : sample.reduce(0,+) / Double(sample.count),
                "loss_pct": Double(20 - sample.count) * 5]
    }
}
#endif
