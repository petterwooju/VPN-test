import Foundation
import Network
import Security

struct ProxyLeafError: LocalizedError {
    var message: String
    var errorDescription: String? { message }
    init(_ message: String) { self.message = message }
}

struct ImportedProxyLeaf {
    let name: String
    let kind: String
    fileprivate let original: [String: Any]

    func configuration(verifiedName: String = "", trustedPin: String = "") throws -> [String: Any] {
        guard ["ss", "anytls"].contains(kind) else { throw ProxyLeafError("Shadowsocks와 AnyTLS 노드를 선택할 수 있습니다.") }
        let base: Set<String> = ["name", "type", "server", "port", "password", "udp", "udp-over-tcp"]
        let fields: Set<String> = kind == "ss" ? ["cipher", "plugin", "plugin-opts", "udp-over-tcp-version"] :
            ["sni", "alpn", "skip-cert-verify", "fingerprint", "idle-session-check-interval", "idle-session-timeout", "min-idle-session"]
        guard Set(original.keys).isSubset(of: base.union(fields)) else { throw ProxyLeafError("보존할 수 없는 추가 노드 옵션이 있습니다.") }
        var conf = original
        func required(_ key: String) throws -> String {
            guard let v = conf[key] as? String, !v.isEmpty, v.utf8.count < 8192 else { throw ProxyLeafError("노드의 필수 문자열 설정을 확인하십시오.") }
            return v
        }
        func number(_ key: String, _ range: ClosedRange<Int>) throws {
            guard let v = conf[key] else { return }
            let n = (v as? String).flatMap(Int.init) ?? (v as? NSNumber)?.intValue
            guard let n, range.contains(n) else { throw ProxyLeafError("노드의 숫자 옵션 범위를 확인하십시오.") }
            conf[key] = n
        }
        func flag(_ key: String) throws {
            guard let v = conf[key] else { return }
            switch String(describing: v).lowercased() {
            case "true", "1": conf[key] = true
            case "false", "0": conf[key] = false
            default: throw ProxyLeafError("노드의 켜짐·꺼짐 옵션을 확인하십시오.")
            }
        }
        let server = try required("server")
        guard Self.validHost(server), conf["port"] != nil else { throw ProxyLeafError("노드 서버 주소 또는 포트를 확인하십시오.") }
        _ = try required("password")
        try number("port", 1...65535); try flag("udp"); try flag("udp-over-tcp")
        if kind == "ss" {
            guard ["chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"].contains(try required("cipher")) else {
                throw ProxyLeafError("시험용 코어가 지원하지 않는 Shadowsocks 암호화 방식입니다.")
            }
            if let plugin = conf["plugin"] {
                guard plugin as? String == "obfs", let options = conf["plugin-opts"] as? [String: Any],
                      Set(options.keys) == Set(["mode", "host"]), let mode = options["mode"] as? String, ["tls", "http"].contains(mode),
                      let host = options["host"] as? String, Self.validObfsHost(host) else {
                    throw ProxyLeafError("지원되는 obfs 모드·호스트 설정이 필요합니다.")
                }
            } else if conf["plugin-opts"] != nil { throw ProxyLeafError("obfs 플러그인 유형이 없습니다.") }
            try number("udp-over-tcp-version", 1...2)
            if conf["udp"] as? Bool == true, conf["udp-over-tcp"] as? Bool != true {
                throw ProxyLeafError("이 시험용 Shadowsocks 노드의 UDP에는 UDP-over-TCP가 필요합니다.")
            }
        } else {
            try flag("skip-cert-verify")
            let originalSkip = conf["skip-cert-verify"] as? Bool ?? false
            let inputPin = trustedPin.trimmingCharacters(in: .whitespacesAndNewlines)
            let explicitName = verifiedName.trimmingCharacters(in: .whitespacesAndNewlines)
            let pin = (inputPin.isEmpty ? conf["fingerprint"] as? String ?? "" : inputPin)
                .replacingOccurrences(of: ":", with: "").lowercased()
            if !pin.isEmpty {
                guard pin.utf8.count == 64, pin.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
                    throw ProxyLeafError("신뢰할 수 있는 공급자의 SHA-256 인증서 지문 64자리를 입력하십시오.")
                }
                conf["fingerprint"] = pin
            }
            if originalSkip && pin.isEmpty && explicitName.isEmpty {
                throw ProxyLeafError("원본 노드는 인증서 검증을 생략합니다. 신뢰할 수 있는 인증서 이름 또는 공급자가 제공한 SHA-256 지문을 지정하십시오.")
            }
            let sni = explicitName.isEmpty ? (conf["sni"] as? String ?? server) : explicitName
            guard Self.validHost(sni) else { throw ProxyLeafError("인증서의 서버 이름을 확인하십시오.") }
            conf["sni"] = sni
            conf["skip-cert-verify"] = false
            if let alpn = conf["alpn"] {
                guard let values = alpn as? [String], values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 255 }) else {
                    throw ProxyLeafError("ALPN 목록을 읽을 수 없습니다.")
                }
            }
            for key in ["idle-session-check-interval", "idle-session-timeout"] {
                try number(key, 0...86400)
            }
            try number("min-idle-session", 0...64)
        }
        return conf
    }

    private static func validHost(_ v: String) -> Bool {
        if IPv4Address(v) != nil || IPv6Address(v) != nil { return true }
        let labels = v.split(separator: ".", omittingEmptySubsequences: false)
        return v.utf8.count <= 253 && labels.allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 63 && part.first != "-" && part.last != "-" &&
                part.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
    private static func validObfsHost(_ host: String) -> Bool {
        if validHost(host) { return true }
        let parts = host.split(separator: ":", omittingEmptySubsequences: false)
        // This is the plugin's wire header, not the proxy socket's TCP port.
        return host.utf8.count <= 253 && parts.count == 2 && validHost(String(parts[0])) &&
            !parts[1].isEmpty && parts[1].utf8.allSatisfy { (48...57).contains($0) }
    }
}

struct ProxyLeafCatalog {
    let groups: [RoutingGroup]
    private let leaves: [String: ImportedProxyLeaf]

    init(text: String) throws {
        guard text.utf8.count <= 12 * 1024 * 1024 else { throw ProxyLeafError("설정 파일이 너무 큽니다.") }
        let routing = try ClashRuleImport.parse(text)
        groups = routing.groups
        typealias YAML = ClashRuleImport
        var nodes = [String: ImportedProxyLeaf](), current: [String: Any] = [:]
        var inSection = false, found = false, itemIndent: Int?, child: String?
        func commit() throws {
            guard !current.isEmpty else { return }
            guard let name = current["name"] as? String, let kind = current["type"] as? String,
                  !name.isEmpty, !kind.isEmpty, nodes[name] == nil, name.utf8.count <= 512 else {
                throw ProxyLeafError("노드 이름·유형이 누락되었거나 중복됩니다.")
            }
            nodes[name] = ImportedProxyLeaf(name: name, kind: kind, original: current)
            current = [:]; child = nil
        }
        func map(_ item: String) throws -> [String: Any] {
            var result = [String: Any]()
            for field in try YAML.splitFlow(String(item.dropFirst().dropLast())) {
                guard let (k, v) = YAML.keyValue(field), result[k] == nil else { throw ProxyLeafError("노드 맵 형식을 읽을 수 없습니다.") }
                result[k] = try value(v)
            }
            return result
        }
        func value(_ raw: String) throws -> Any {
            if raw.hasPrefix("{"), raw.hasSuffix("}") { return try map(raw) }
            if raw.hasPrefix("[") { return try YAML.stringArray(raw) }
            return try YAML.scalar(raw)
        }
        func field(_ line: String) throws {
            guard let (k, v) = YAML.keyValue(line), current[k] == nil else { throw ProxyLeafError("노드 설정 필드가 중복되었거나 잘못되었습니다.") }
            child = v.isEmpty ? k : nil
            if v.isEmpty { current[k] = k == "alpn" ? [] as [String] as Any : [:] as [String: Any] as Any }
            else { current[k] = try value(v) }
        }
        for raw in text.components(separatedBy: .newlines) {
            let line = YAML.stripComment(raw)
            if line.isEmpty { continue }
            let indent = raw.prefix { $0 == " " }.count
            let list = line == "-" || line.hasPrefix("- ")
            if indent == 0 && !list {
                if inSection { try commit() }
                inSection = YAML.keyValue(line)?.0 == "proxies"
                if inSection {
                    guard !found, let (_, rhs) = YAML.keyValue(line), rhs.isEmpty || rhs == "[]" else {
                        throw ProxyLeafError("최상위 proxies 목록 형식을 지원하지 않습니다.")
                    }
                    found = true
                }
                continue
            }
            guard inSection else { continue }
            if itemIndent == nil { itemIndent = indent }
            guard let base = itemIndent else { continue }
            if list, indent == base {
                try commit()
                let item = line.dropFirst().trimmingCharacters(in: .whitespaces)
                if item.hasPrefix("{"), item.hasSuffix("}") { current = try map(item) }
                else if !item.isEmpty { try field(item) }
            } else if list, let k = child, indent >= base + 2 {
                guard var items = current[k] as? [String] else { throw ProxyLeafError("중첩 노드 목록을 읽을 수 없습니다.") }
                items.append(try YAML.scalar(String(line.dropFirst()))); current[k] = items
            } else if indent == base + 2 { try field(line) }
            else if indent == base + 4, let k = child, var m = current[k] as? [String: Any],
                    let (key, v) = YAML.keyValue(line), m[key] == nil {
                m[key] = try value(v); current[k] = m
            } else { throw ProxyLeafError("지원되지 않는 YAML 중첩 필드가 있습니다.") }
        }
        try commit()
        guard found else { throw ProxyLeafError("인증 정보가 포함된 원본 FlClash 설정을 선택하십시오.") }
        leaves = nodes
    }

    var allLeaves: [ImportedProxyLeaf] { leaves.values.sorted { $0.name < $1.name } }

    func members(of group: String) -> [ImportedProxyLeaf] {
        let byName = Dictionary(uniqueKeysWithValues: groups.map { ($0.name, $0) })
        var seen = Set<String>(), nodes: [ImportedProxyLeaf] = []
        func visit(_ name: String) {
            guard seen.insert(name).inserted else { return }
            if let leaf = leaves[name] { nodes.append(leaf); return }
            for member in byName[name]?.members ?? [] { visit(member) }
        }
        visit(group); return nodes
    }
}

struct ExperimentalProxyStore {
    static let service = "net.petterwooju.coreavpn.lab.proxy-leaf.v1"

    private func query(_ group: String? = nil) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Self.service]
        if let group { q[kSecAttrAccount as String] = group }
        #if os(macOS)
        q[kSecUseDataProtectionKeychain as String] = true
        #endif
        return q
    }
    func save(group: String, leaf: ImportedProxyLeaf, verifiedName: String = "", trustedPin: String = "") throws {
        let config = try leaf.configuration(verifiedName: verifiedName, trustedPin: trustedPin)
        let value: [String: Any] = ["version": 1, "group": group, "node": leaf.name, "configuration": config]
        let data = try JSONSerialization.data(withJSONObject: value)
        let attrs: [String: Any] = [kSecValueData as String: data, kSecAttrLabel as String: leaf.name,
                                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let q = query(group)
        var status = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound { status = SecItemAdd(q.merging(attrs) { _, new in new } as CFDictionary, nil) }
        guard status == errSecSuccess else { throw ProxyLeafError("프록시 키체인 저장 실패 (\(status)).") }
    }
    func reference(for group: String) throws -> Data {
        var q = query(group)
        q[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let code = SecItemCopyMatching(q as CFDictionary, &result)
        guard code == errSecSuccess, let ref = result as? Data else { throw ProxyLeafError("선택한 그룹의 노드를 먼저 키체인에 저장하십시오.") }
        return ref
    }
    func selections() throws -> [String: String] {
        var q = query()
        q[kSecReturnAttributes as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitAll
        var r: CFTypeRef?
        let code = SecItemCopyMatching(q as CFDictionary, &r)
        if code == errSecItemNotFound { return [:] }
        guard code == errSecSuccess, let items = r as? [[String: Any]] else { throw ProxyLeafError("그룹 목록을 열 수 없습니다 (\(code)).") }
        return items.reduce(into: [:]) { out, item in
            if let group = item[kSecAttrAccount as String] as? String, let node = item[kSecAttrLabel as String] as? String { out[group] = node }
        }
    }
}
