#if os(macOS)
import Foundation

struct LiveConnectionSnapshot: Codable {
    let version: Int
    let total: Int
    let connections: [MacLiveConnection]
}

struct MacLiveConnection: Codable, Identifiable {
    let id: String
    let app: String
    var bundleID: String? = nil
    let host: String
    var ip: String? = nil
    let port: Int
    let transport: String
    let rule: String
    var ruleID: UUID? = nil
    let egress: String
    var group: String? = nil
    var node: String? = nil
    var server: String? = nil
    let interface: String
    var startedAt: Double? = nil

    var destination: String {
        guard port > 0 else { return host }
        return host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
    var outbound: String {
        switch egress {
        case "coreaVPN": return "CoreaVPN"
        case "direct": return "Direct"
        case "clashDirect": return "Direct · FlClash"
        case "proxy": return "기존 프록시"
        case "blocked": return "차단"
        default: return "미확인"
        }
    }
    var routeDetail: String {
        var details = [String]()
        for part in [group, node, server, interface] {
            if let part, !part.isEmpty, !details.contains(part) { details.append(part) }
        }
        return details.joined(separator: " → ")
    }
    func matches(_ query: String) -> Bool {
        query.isEmpty || [app, bundleID ?? "", destination, ip ?? "", transport, rule, outbound, routeDetail]
            .contains { $0.localizedCaseInsensitiveContains(query) }
    }
}
#endif
