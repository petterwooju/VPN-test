#if os(macOS)
import Foundation

/// An explicitly configured controller on this Mac. The dashboard only reads live metadata.
enum MacMihomoConnections {
    private enum MonitorError: LocalizedError {
        case invalidPort, invalidToken, denied, unreachable, invalidResponse, tooLarge
        var errorDescription: String? {
            switch self {
            case .invalidPort: return "로컬 컨트롤러의 HTTP 포트를 확인하세요."
            case .invalidToken: return "컨트롤러 토큰의 형식을 확인하세요."
            case .denied: return "컨트롤러에서 인증을 거부했습니다. 토큰을 확인하세요."
            case .unreachable: return "이 Mac의 컨트롤러에 연결할 수 없습니다. HTTP 컨트롤러 주소와 포트를 확인하세요."
            case .invalidResponse: return "로컬 컨트롤러에서 유효한 mihomo 연결 목록을 받지 못했습니다."
            case .tooLarge: return "컨트롤러 응답이 표시 가능한 크기를 초과했습니다."
            }
        }
    }

    private final class NoRedirects: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }

    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.urlCredentialStorage = nil
        config.httpShouldSetCookies = false
        config.connectionProxyDictionary = ["HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0,
                                           "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0,
                                           "ExceptionsList": ["127.0.0.1"]]
        config.timeoutIntervalForRequest = 2
        config.timeoutIntervalForResource = 3
        return URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
    }()

    static func snapshot(port: UInt16, token: String) async throws -> LiveConnectionSnapshot {
        guard port > 0 else { throw MonitorError.invalidPort }
        guard token.utf8.count <= 4096, !token.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw MonitorError.invalidToken
        }
        let payload = try await get("connections", port: port, token: token)
        let response = try parsePayload(payload)
        var types: [String: String] = [:]
        if response.contains(where: { $0.chains?.first.map { reservedTypes[$0] == nil } ?? false }) {
            // Chain entries are adapter names. A custom name alone cannot establish its type.
            if let catalog = try? await get("proxies", port: port, token: token),
               let decoded = try? JSONDecoder().decode(Catalog.self, from: catalog) {
                types = decoded.proxies.mapValues(\.type)
            }
        }
        try Task.checkCancellation()
        return makeSnapshot(response, types: types)
    }

    private static func get(_ path: String, port: UInt16, token: String) async throws -> Data {
        try Task.checkCancellation()
        let url = URL(string: "http://127.0.0.1:\(port)/\(path)")!
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if !token.isEmpty { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        let limit = 2 * 1024 * 1024
        do {
            let (bytes, response) = try await session.bytes(for: request)
            defer { bytes.task.cancel() }
            guard let http = response as? HTTPURLResponse else { throw MonitorError.invalidResponse }
            if [401, 403].contains(http.statusCode) { throw MonitorError.denied }
            guard http.statusCode == 200 else { throw MonitorError.invalidResponse }
            guard http.expectedContentLength <= Int64(limit) else { throw MonitorError.tooLarge }
            var data = Data()
            if http.expectedContentLength > 0 { data.reserveCapacity(Int(http.expectedContentLength)) }
            for try await byte in bytes {
                guard data.count < limit else { throw MonitorError.tooLarge }
                data.append(byte)
            }
            return data
        } catch let error as MonitorError { throw error }
        catch {
            try Task.checkCancellation()
            throw MonitorError.unreachable
        }
    }

    private struct Catalog: Decodable {
        struct Entry: Decodable { var type: String }
        var proxies: [String: Entry]
    }

    private struct Tracker: Decodable {
        let id: String
        let metadata: Metadata
        var start: String?
        var chains: [String]?
        var rule: String?
        var rulePayload: String?
    }

    private struct Metadata: Decodable {
        let network: String?
        let process: String?
        let processPath: String?
        let host: String?
        let sniffHost: String?
        let destinationIP: String?
        let destinationPort: Port?
        struct Port: Decodable {
            var value: UInt16
            init(from decoder: Decoder) throws {
                let box = try decoder.singleValueContainer()
                if let number = try? box.decode(UInt16.self) { value = number; return }
                let string = try box.decode(String.self)
                guard let value = UInt16(string) else {
                    throw DecodingError.dataCorruptedError(in: box, debugDescription: "포트 형식")
                }
                self.value = value
            }
        }
    }

    private struct Payload: Decodable {
        let connections: [Tracker]
        private enum Keys: String, CodingKey { case connections }
        init(from decoder: Decoder) throws {
            let values = try decoder.container(keyedBy: Keys.self)
            guard values.contains(.connections) else { throw MonitorError.invalidResponse }
            connections = try values.decodeIfPresent([Tracker].self, forKey: .connections) ?? []
        }
    }

    private static func parsePayload(_ data: Data) throws -> [Tracker] {
        do { return try JSONDecoder().decode(Payload.self, from: data).connections }
        catch { throw MonitorError.invalidResponse }
    }

    private static let reservedTypes = ["DIRECT": "Direct", "REJECT": "Reject", "REJECT-DROP": "RejectDrop",
                                        "PASS": "Pass", "COMPATIBLE": "Compatible", "GLOBAL": "Selector"]
    private static let proxyTypes: Set<String> = ["Shadowsocks", "ShadowsocksR", "Snell", "Socks5", "Http",
        "Vmess", "Vless", "Trojan", "Hysteria", "Hysteria2", "WireGuard", "Tuic", "Ssh", "Mieru", "AnyTLS",
        "Sudoku", "Masque", "TrustTunnel", "ShadowQuic", "OpenVPN", "Tailscale", "ZeroTier", "EasyTier", "GostRelay"]

    private static func text(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return String(value.prefix(512))
    }

    private static func makeSnapshot(_ trackers: [Tracker], types: [String: String]) -> LiveConnectionSnapshot {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let seconds = ISO8601DateFormatter()
        var seen = Set<String>()
        var rows = [MacLiveConnection]()
        for item in trackers {
            guard !item.id.isEmpty, seen.insert(item.id).inserted else { continue }
            let meta = item.metadata
            // mihomo Chain.Last() returns index 0 (the terminal adapter). Groups wrap it from inner to outer.
            let chain = item.chains ?? []
            let leaf = chain.first
            let type = leaf.flatMap { types[$0] ?? reservedTypes[$0] }
            let egress: String
            switch type {
            case "Direct": egress = "clashDirect"
            case "Reject", "RejectDrop": egress = "blocked"
            case let value? where proxyTypes.contains(value): egress = "proxy"
            default: egress = "unknown"
            }
            let process = meta.processPath?.split(separator: "/")
            let bundle = process?.first(where: { $0.hasSuffix(".app") }).map { String($0.dropLast(4)) }
            let app = text(bundle) ?? text(meta.process) ?? text(process?.last.map(String.init)) ?? "앱 미확인"
            let rule = [text(item.rule), text(item.rulePayload)].compactMap { $0 }.joined(separator: " · ")
            let parsedDate = item.start.flatMap { fractional.date(from: $0) ?? seconds.date(from: $0) }
            let group = chain.count > 1 ? text(chain.dropFirst().reversed().joined(separator: " → ")) : nil
            rows.append(MacLiveConnection(id: item.id, app: app, bundleID: nil,
                host: text(meta.host) ?? text(meta.sniffHost) ?? text(meta.destinationIP) ?? "목적지 미확인",
                ip: text(meta.destinationIP), port: meta.destinationPort.map { Int($0.value) } ?? 0, transport: meta.network?.uppercased() ?? "—",
                rule: rule.isEmpty ? "규칙 미보고" : rule, egress: egress, group: group, node: text(leaf),
                server: nil, interface: "", startedAt: parsedDate?.timeIntervalSince1970))
        }
        rows.sort { lhs, rhs in
            let left = lhs.startedAt ?? 0, right = rhs.startedAt ?? 0
            return left == right ? lhs.id < rhs.id : left > right
        }
        return LiveConnectionSnapshot(version: 1, total: rows.count, connections: Array(rows.prefix(128)))
    }
}
#endif
