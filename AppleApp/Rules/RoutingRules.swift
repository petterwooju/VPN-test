import Darwin
import Foundation

enum RoutingPolicy: Codable, Hashable {
    case direct, coreaVPN, reject
    case group(String)

    init(imported name: String) {
        switch name {
        case "DIRECT": self = .direct
        case "REJECT": self = .reject
        default: self = .group(name)
        }
    }

    var title: String {
        switch self {
        case .direct: return "Direct"
        case .coreaVPN: return "자동 선택된 CoreaVPN"
        case .reject: return "REJECT"
        case let .group(name): return "기존 프록시 · \(name)"
        }
    }
}

struct RoutingGroup: Codable, Hashable {
    var name: String
    var type: String
    var members: [String] = []
    var providers: [String] = []
    var url: String?
    var interval: Int?
    var tolerance: Int?
    var strategy: String?
    var unsupportedOptions: [String]?
}

struct RouteQuery {
    var domain = ""
    var ip = ""
    var processPath = ""
    var processName = ""
    var country = ""
    var geoMatch: ((String) -> Comparison)?
    var port: Int?
    var transport = ""

    var hasInput: Bool {
        ![domain, ip, processName, processPath, country, transport].allSatisfy(\.isEmpty) || port != nil
    }
}

struct RoutePreview {
    var match: RoutingRule?
    var undecided: [RoutingRule] = []
}

enum RuleProblem: LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self { case let .message(text): return text }
    }
}

enum Comparison { case yes, no, unknown }

struct RoutingRule: Identifiable, Hashable, Codable {
    let id: UUID
    var kind: String
    var value: String
    var policy: RoutingPolicy
    var qualifiers: [String]
    var original: String?

    static let editableKinds = ["DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6"]
    static let previewKinds = Set(editableKinds + ["DOMAIN-KEYWORD", "GEOIP", "PROCESS-PATH", "PROCESS-NAME", "DST-PORT", "NETWORK", "MATCH", "AND", "OR", "NOT"])

    init(kind: String, value: String, policy: RoutingPolicy, qualifiers: [String] = [], original: String? = nil, id: UUID = UUID()) {
        self.id = id
        self.kind = kind
        self.value = value
        self.policy = policy
        self.qualifiers = qualifiers
        self.original = original
    }

    static func imported(_ text: String) throws -> Self {
        let parts = commaFields(text)
        guard let kind = parts.first, !kind.isEmpty else { throw RuleProblem.message("비어 있는 규칙입니다.") }
        let key = kind.uppercased()
        let target = key == "MATCH" ? 1 : 2
        // A different dialect may encode the policy elsewhere. Retain the entire
        // unrecognized line, but never treat a guessed target as an actionable match.
        guard parts.indices.contains(target), !parts[target].isEmpty else {
            return Self(kind: key, value: text, policy: .group("미확인"), original: text)
        }
        return Self(kind: key, value: key == "MATCH" ? "" : parts[1],
                    policy: RoutingPolicy(imported: parts[target]), qualifiers: Array(parts.dropFirst(target + 1)), original: text)
    }

    var displayText: String { kind == "MATCH" ? "MATCH" : "\(kind)  \(value)" }

    /// IP predicates are the only preview conditions that can change their truth
    /// value between numeric addresses when no app, hostname or flow is supplied.
    var addressConditions: [String] {
        Self.addressConditions(kind, value, depth: 0)
    }

    private static func addressConditions(_ kind: String, _ value: String, depth: Int) -> [String] {
        if ["IP-CIDR", "IP-CIDR6"].contains(kind) { return [value] }
        guard depth < 12, ["AND", "OR", "NOT"].contains(kind), let list = unwrap(value) else { return [] }
        return commaFields(list).flatMap { term -> [String] in
            guard let child = unwrap(term) else { return [] }
            let pair = commaFields(child)
            guard pair.count == 2 else { return [] }
            return addressConditions(pair[0].uppercased(), pair[1], depth: depth + 1)
        }
    }

    func issue(groups: Set<String>, supportsProcess: Bool) -> String? {
        if let problem = Self.conditionIssue(kind, value, supportsProcess, depth: 0) { return problem }
        if !qualifiers.allSatisfy({ $0.lowercased() == "no-resolve" && ["GEOIP", "IP-CIDR", "IP-CIDR6"].contains(kind) }) {
            return "지원되지 않는 규칙 옵션"
        }
        if case .group(let name) = policy, !groups.contains(name) { return "정의되지 않은 정책 대상 · \(name)" }
        return nil
    }

    private static func conditionIssue(_ kind: String, _ value: String, _ process: Bool, depth: Int) -> String? {
        guard depth < 12 else { return "규칙 중첩 한도 초과" }
        guard previewKinds.contains(kind) else { return "지원되지 않는 조건 · \(kind)" }
        if !process && ["PROCESS-NAME", "PROCESS-PATH"].contains(kind) { return "iPhone 앱 식별 미지원" }
        if ["AND", "OR", "NOT"].contains(kind) {
            guard let list = unwrap(value) else { return "복합 조건 형식 확인 필요" }
            let terms = commaFields(list)
            guard kind != "NOT" || terms.count == 1 else { return "NOT 조건 형식 확인 필요" }
            for term in terms {
                guard let child = unwrap(term) else { return "복합 조건 형식 확인 필요" }
                let fields = commaFields(child)
                guard fields.count == 2 else { return "복합 조건 형식 확인 필요" }
                if let problem = conditionIssue(fields[0].uppercased(), fields[1], process, depth: depth + 1) { return problem }
            }
        }
        return nil
    }

    func validateEdit() throws {
        if ["IP-CIDR", "IP-CIDR6"].contains(kind) {
            guard let block = RoutingCIDR(value), block.family == (kind == "IP-CIDR" ? AF_INET : AF_INET6) else {
                throw RuleProblem.message("주소 뒤에 대역 길이를 포함해 주세요. 예: 192.0.2.0/24 또는 2001:db8::/32")
            }
        } else if ["DOMAIN", "DOMAIN-SUFFIX"].contains(kind) {
            let domain = Self.normalizeDomain(value)
            guard !domain.isEmpty, domain.utf8.count <= 253, !domain.contains(".."),
                  domain.split(separator: ".").allSatisfy({ label in
                      (1...63).contains(label.utf8.count) && label.first != "-" && label.last != "-" &&
                      label.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
                  }), !value.hasPrefix(".") else {
                throw RuleProblem.message("도메인 이름을 입력해 주세요. 접미사 규칙도 별표 없이 입력합니다.")
            }
        }
    }

    func compare(_ query: RouteQuery, supportsProcess: Bool) -> Comparison {
        guard qualifiers.allSatisfy({ $0.lowercased() == "no-resolve" && ["GEOIP", "IP-CIDR", "IP-CIDR6"].contains(kind) }) else { return .unknown }
        return Self.evaluate(kind, value, query, supportsProcess, depth: 0)
    }

    static func normalizeDomain(_ name: String) -> String {
        name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    private static func evaluate(_ kind: String, _ value: String, _ q: RouteQuery, _ process: Bool, depth: Int) -> Comparison {
        guard depth < 12 else { return .unknown }
        switch kind {
        case "MATCH": return .yes
        case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
            let domain = normalizeDomain(q.domain)
            let entry = normalizeDomain(value)
            guard !domain.isEmpty, !entry.isEmpty else { return .unknown }
            if kind == "DOMAIN-KEYWORD" { return domain.contains(entry) ? .yes : .no }
            return domain == entry || (kind == "DOMAIN-SUFFIX" && domain.hasSuffix("." + entry)) ? .yes : .no
        case "IP-CIDR", "IP-CIDR6":
            guard let block = RoutingCIDR(value), let result = block.contains(q.ip) else { return .unknown }
            return result ? .yes : .no
        case "GEOIP":
            if let classify = q.geoMatch { return classify(value.uppercased()) }
            guard !q.country.isEmpty else { return .unknown }
            return q.country.caseInsensitiveCompare(value) == .orderedSame ? .yes : .no
        case "NETWORK":
            guard !q.transport.isEmpty else { return .unknown }
            return q.transport.caseInsensitiveCompare(value) == .orderedSame ? .yes : .no
        case "DST-PORT":
            guard let port = q.port else { return .unknown }
            let pieces = value.split(separator: "/", omittingEmptySubsequences: false)
            var found = false
            for piece in pieces {
                let bounds = piece.split(separator: "-", omittingEmptySubsequences: false)
                guard (1...2).contains(bounds.count), let low = Int(bounds[0]), let high = Int(bounds[bounds.count - 1]),
                      low >= 0, high <= 65535, low <= high else { return .unknown }
                found = found || (low...high).contains(port)
            }
            return found ? .yes : .no
        case "PROCESS-PATH", "PROCESS-NAME":
            guard process else { return .unknown }
            let candidate = kind == "PROCESS-PATH" ? q.processPath :
                (!q.processName.isEmpty ? q.processName : (q.processPath as NSString).lastPathComponent)
            guard !candidate.isEmpty else { return .unknown }
            return candidate.caseInsensitiveCompare(value) == .orderedSame ? .yes : .no
        case "AND", "OR", "NOT":
            guard let outer = unwrap(value) else { return .unknown }
            let terms = commaFields(outer)
            guard !terms.isEmpty else { return .unknown }
            let results: [Comparison] = terms.map { term in
                guard let inner = unwrap(term) else { return .unknown }
                let fields = commaFields(inner)
                guard fields.count == 2 else { return .unknown }
                return evaluate(fields[0].uppercased(), fields[1], q, process, depth: depth + 1)
            }
            if kind == "NOT" {
                guard results.count == 1 else { return .unknown }
                switch results[0] { case .yes: return .no; case .no: return .yes; case .unknown: return .unknown }
            }
            if kind == "AND" {
                if results.contains(.no) { return .no }
                return results.contains(.unknown) ? .unknown : .yes
            }
            if results.contains(.yes) { return .yes }
            return results.contains(.unknown) ? .unknown : .no
        default: return .unknown
        }
    }

    private static func unwrap(_ string: String) -> String? {
        guard string.first == "(", string.last == ")" else { return nil }
        return String(string.dropFirst().dropLast())
    }
}

private func commaFields(_ text: String) -> [String] {
    var out: [String] = [], field = "", depth = 0
    for ch in text {
        if ch == "," && depth == 0 {
            out.append(field.trimmingCharacters(in: .whitespaces))
            field = ""
        } else {
            if ch == "(" { depth += 1 }
            if ch == ")" { depth -= 1 }
            field.append(ch)
        }
    }
    out.append(field.trimmingCharacters(in: .whitespaces))
    return out
}

struct RoutingCIDR {
    let family: Int32
    let network: [UInt8]
    let bits: Int

    init?(_ value: String) {
        let pair = value.split(separator: "/", omittingEmptySubsequences: false)
        guard pair.count == 2, let (family, bytes) = Self.address(String(pair[0])),
              let bits = Int(pair[1]), (0...bytes.count * 8).contains(bits) else { return nil }
        self.family = family
        self.network = bytes
        self.bits = bits
    }

    private static func address(_ text: String) -> (Int32, [UInt8])? {
        var buf = [UInt8](repeating: 0, count: 16)
        for family in [AF_INET, AF_INET6] {
            if inet_pton(family, text, &buf) == 1 { return (family, Array(buf.prefix(family == AF_INET ? 4 : 16))) }
        }
        return nil
    }

    func contains(_ text: String) -> Bool? {
        guard let (other, bytes) = Self.address(text) else { return nil }
        guard family == other else { return false }
        let whole = bits / 8, extra = bits % 8
        guard network.prefix(whole) == bytes.prefix(whole) else { return false }
        return extra == 0 || network[whole] >> (8 - extra) == bytes[whole] >> (8 - extra)
    }
}

struct RoutingDocument: Codable {
    var format = 1
    var groups: [RoutingGroup] = []
    var rules: [RoutingRule] = []
    var nodeTypes: [String: String]?

    var knownTargets: Set<String> {
        Set(groups.map(\.name)).union(nodeTypes?.keys.map { $0 } ?? [])
    }

    static func decode(_ data: Data) throws -> Self {
        let doc = try JSONDecoder().decode(Self.self, from: data)
        guard doc.format == 1, Set(doc.rules.map(\.id)).count == doc.rules.count,
              Set(doc.groups.map(\.name)).count == doc.groups.count else {
            throw RuleProblem.message("지원하지 않는 규칙 파일 형식이거나 중복 항목이 있습니다.")
        }
        return doc
    }

    func preview(_ query: RouteQuery, supportsProcess: Bool = RoutingDocument.supportsProcess) -> RoutePreview {
        var preview = RoutePreview()
        for rule in rules {
            switch rule.compare(query, supportsProcess: supportsProcess) {
            case .yes: preview.match = rule; return preview
            case .no: continue
            case .unknown: preview.undecided.append(rule)
            }
        }
        return preview
    }

    static var supportsProcess: Bool {
        #if os(macOS)
        true
        #else
        false
        #endif
    }
}
