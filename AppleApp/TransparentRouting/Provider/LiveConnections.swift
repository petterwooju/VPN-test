import Foundation

/// A display-only record of the channel that opened successfully. Never serialize FlowExit:
/// its dialing specification includes the proxy's credentials.
struct ProviderLiveConnection: Encodable {
    let id: UUID
    let startedAt: Double
    let app: String
    let bundleID: String?
    let host: String
    let ip: String?
    let port: Int
    let transport: String
    let rule: String
    let ruleID: UUID
    let egress: String
    let group: String?
    let node: String?
    let server: String?
    let interface: String

    init(app: String, bundleID: String?, query: RouteQuery, rule: RoutingRule,
         exit: FlowExit, server: String?) {
        id = UUID()
        startedAt = Date().timeIntervalSince1970
        self.app = Self.label(app)
        self.bundleID = bundleID.map(Self.label)
        host = Self.label(query.domain.isEmpty ? query.ip : query.domain)
        ip = query.ip.isEmpty ? nil : Self.label(query.ip)
        port = query.port ?? 0
        transport = query.transport
        self.rule = Self.label(([rule.displayText] + rule.qualifiers).joined(separator: ", "))
        self.ruleID = rule.id
        if case let .group(name) = rule.policy { group = Self.label(name) } else { group = nil }
        node = exit.node.map(Self.label)
        self.server = exit.isVPN ? server.map(Self.label) : nil
        egress = exit.isVPN ? "coreaVPN" : (exit.node == nil ? "direct" : "proxy")
        interface = exit.binding.name
    }

    private static func label(_ text: String) -> String {
        let bytes = text.utf8.prefix(513)
        guard bytes.count > 512 else { return text }
        return String(decoding: bytes.prefix(509), as: UTF8.self) + "…"
    }
}

struct ProviderConnectionSnapshot: Encodable {
    static let request = Data("CoreaVPN.live-connections.v1".utf8)
    static let limit = 128
    let version = 1
    let total: Int
    let connections: [ProviderLiveConnection]
}
