import Foundation

/// Reads the rule and group sections of a Clash configuration. Never stores node
/// credentials, provider URLs, scripts, DNS configuration or the source file.
enum ClashRuleImport {
    static func parse(_ text: String) throws -> RoutingDocument {
        var section = ""
        var sawRules = false, sawGroups = false
        var rules: [RoutingRule] = [], groups: [RoutingGroup] = []
        var entry: RoutingGroup?
        var groupIndent: Int?, listIndent: Int?
        var listKey: String?
        var rulesIndent: Int?
        var nodeTypes: [String: String] = [:]
        var nodeName = "", nodeType = ""
        var nodeIndent: Int?

        func flushNode() {
            if !nodeName.isEmpty && !nodeType.isEmpty { nodeTypes[nodeName] = nodeType }
            nodeName = ""
            nodeType = ""
        }

        func nodeField(_ text: String) throws {
            guard let (key, value) = keyValue(text) else { return }
            if key == "name" { nodeName = try scalar(stripComment(value)) }
            if key == "type" { nodeType = try scalar(stripComment(value)) }
        }

        func flushGroup() throws {
            guard let next = entry else { return }
            guard !next.name.isEmpty else { throw RuleProblem.message("프록시 그룹 이름을 읽을 수 없습니다.") }
            groups.append(next)
            entry = nil
            listKey = nil
        }

        for (lineIndex, source) in text.split(whereSeparator: \.isNewline).enumerated() {
            let raw = String(source)
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let indent = raw.prefix { $0 == " " }.count
            if indent == 0 && !line.hasPrefix("- ") && line != "-" {
                if section == "proxy-groups" { try flushGroup() }
                if section == "proxies" { flushNode() }
                section = ""
                let parts = keyValue(line)
                if parts?.0 == "proxies" {
                    section = "proxies"
                    continue
                }
                guard let (key, rhs) = parts, key == "rules" || key == "proxy-groups" else { continue }
                if key == "rules" && sawRules || key == "proxy-groups" && sawGroups {
                    throw RuleProblem.message("설정에 \(key) 섹션이 중복됩니다.")
                }
                if key == "rules" { sawRules = true } else { sawGroups = true }
                let value = stripComment(rhs)
                section = key
                if value.isEmpty || value == "[]" { continue }
                if key == "rules", value.first == "[", value.last == "]" {
                    rules += try stringArray(value).map { try RoutingRule.imported($0) }
                    continue
                }
                throw RuleProblem.message("\(key)에는 YAML 목록 형식이 필요합니다.")
            }
            if section == "proxies" {
                if nodeIndent == nil { nodeIndent = indent }
                if line.hasPrefix("- "), indent == nodeIndent {
                    flushNode()
                    let start = String(line.dropFirst(2)).trimmed
                    if start.hasPrefix("{"), start.hasSuffix("}") {
                        for field in try splitFlow(String(start.dropFirst().dropLast())) { try nodeField(field) }
                    } else { try nodeField(start) }
                } else if let base = nodeIndent, indent == base + 2 { try nodeField(line) }
                continue
            }
            guard ["rules", "proxy-groups"].contains(section) else { continue }
            let item = stripComment(line)
            if item.isEmpty { continue }
            let isListItem = item == "-" || item.hasPrefix("- ")
            if section == "rules" {
                guard isListItem, rulesIndent == nil || rulesIndent == indent else {
                    throw RuleProblem.message("규칙의 여러 줄 YAML 또는 중첩 형식을 읽을 수 없습니다 (\(lineIndex + 1)번째 줄).")
                }
                rulesIndent = indent
                let rawRule = try scalar(String(item.dropFirst()).trimmed)
                rules.append(try RoutingRule.imported(rawRule))
                continue
            }

            if groupIndent == nil { groupIndent = indent }
            if isListItem, indent == groupIndent {
                try flushGroup()
                entry = RoutingGroup(name: "", type: "")
                let spec = String(item.dropFirst()).trimmed
                if spec.isEmpty { continue }
                if spec.first == "{" && spec.last == "}" {
                    for pair in try splitFlow(String(spec.dropFirst().dropLast())) {
                        guard let (key, value) = keyValue(pair) else { throw RuleProblem.message("프록시 그룹 형식을 읽을 수 없습니다.") }
                        try setGroupField(key, value, &entry, listKey: &listKey)
                    }
                } else {
                    guard let (key, value) = keyValue(spec) else { throw RuleProblem.message("프록시 그룹 형식을 읽을 수 없습니다.") }
                    try setGroupField(key, value, &entry, listKey: &listKey)
                }
                listIndent = nil
            } else if isListItem {
                if let field = listKey, let base = listIndent, indent >= base {
                    let member = try scalar(String(item.dropFirst()).trimmed)
                    if field == "proxies" { entry?.members.append(member) } else { entry?.providers.append(member) }
                }
            } else if let base = groupIndent, indent == base + 2, let (key, value) = keyValue(item) {
                try setGroupField(key, value, &entry, listKey: &listKey)
                listIndent = indent
            }
        }
        try flushGroup()
        flushNode()
        guard sawRules else { throw RuleProblem.message("선택한 파일에 최상위 rules 섹션이 없습니다.") }
        guard Set(groups.map(\.name)).count == groups.count else { throw RuleProblem.message("같은 이름의 프록시 그룹이 두 번 정의되어 있습니다.") }
        return RoutingDocument(groups: groups, rules: rules, nodeTypes: nodeTypes)
    }

    private static func setGroupField(_ key: String, _ value: String, _ group: inout RoutingGroup?, listKey: inout String?) throws {
        listKey = nil
        switch key {
        case "name": group?.name = try scalar(value)
        case "type": group?.type = try scalar(value)
        case "url":
            let text = try scalar(value)
            guard let url = URLComponents(string: text), ["https", "http"].contains(url.scheme?.lowercased()),
                  url.host?.isEmpty == false, url.user == nil, url.password == nil,
                  url.query == nil, url.fragment == nil else {
                let existing = group?.unsupportedOptions ?? []
                group?.unsupportedOptions = existing + ["url"]
                return
            }
            group?.url = text
        case "strategy": group?.strategy = try scalar(value)
        case "interval", "tolerance":
            let source = try scalar(value)
            guard let number = Int(source), number >= 0 else { throw RuleProblem.message("프록시 그룹 시간 설정을 읽을 수 없습니다.") }
            if key == "interval" { group?.interval = number } else { group?.tolerance = number }
        case "proxies", "use":
            if value.isEmpty { listKey = key }
            else if key == "proxies" { group?.members = try stringArray(value) }
            else { group?.providers = try stringArray(value) }
        case "icon", "hidden": break
        default:
            let existing = group?.unsupportedOptions ?? []
            group?.unsupportedOptions = existing + [key]
        }
    }

    static func keyValue(_ text: String) -> (String, String)? {
        guard let colon = text.firstIndex(of: ":") else { return nil }
        return (String(text[..<colon]).trimmed, String(text[text.index(after: colon)...]).trimmed)
    }

    static func scalar(_ string: String) throws -> String {
        let value = string.trimmed
        if value.first == "\"" {
            guard let result = try? JSONDecoder().decode(String.self, from: Data(value.utf8)) else {
                throw RuleProblem.message("큰따옴표 문자열의 이스케이프를 읽을 수 없습니다.")
            }
            return result
        }
        if value.first == "'" {
            guard value.count >= 2, value.last == "'" else { throw RuleProblem.message("작은따옴표가 닫히지 않았습니다.") }
            return String(value.dropFirst().dropLast()).replacingOccurrences(of: "''", with: "'")
        }
        if value.isEmpty || ["&", "*", "|", ">", "!"].contains(value.first.map(String.init) ?? "") {
            throw RuleProblem.message("YAML 별칭, 태그 또는 여러 줄 값은 지원하지 않습니다.")
        }
        return value
    }

    static func stringArray(_ value: String) throws -> [String] {
        guard value.first == "[", value.last == "]" else { throw RuleProblem.message("YAML 목록을 읽을 수 없습니다.") }
        let inner = String(value.dropFirst().dropLast()).trimmed
        return inner.isEmpty ? [] : try splitFlow(inner).map(scalar)
    }

    static func splitFlow(_ text: String) throws -> [String] {
        var values: [String] = [], token = "", depth = 0
        var quote: Character?, escaped = false
        for c in text {
            if escaped { token.append(c); escaped = false; continue }
            if let active = quote {
                if c == "\\" && active == "\"" { escaped = true }
                if c == active { quote = nil }
            } else if c == "'" || c == "\"" { quote = c }
            else if c == "[" || c == "{" { depth += 1 }
            else if c == "]" || c == "}" { depth -= 1 }
            else if c == "," && depth == 0 {
                values.append(token.trimmed)
                token = ""
                continue
            }
            token.append(c)
        }
        guard quote == nil && depth == 0 && !escaped else { throw RuleProblem.message("YAML 목록이 닫히지 않았습니다.") }
        values.append(token.trimmed)
        return values
    }

    static func stripComment(_ text: String) -> String {
        var result = "", quote: Character?, escaped = false, previousSpace = true
        for ch in text {
            if escaped { escaped = false }
            else if let active = quote {
                if ch == "\\" && active == "\"" { escaped = true }
                else if ch == active { quote = nil }
            } else if ch == "'" || ch == "\"" { quote = ch }
            else if ch == "#" && previousSpace { break }
            result.append(ch)
            previousSpace = ch.isWhitespace
        }
        return result.trimmed
    }
}

private extension String {
    var trimmed: String { trimmingCharacters(in: .whitespaces) }
}
