import Darwin
import Foundation

/// Extracts the countries referenced by the document from a V2Ray GeoIPList.
/// The subset can be stored with the rules and reused without the original file.
struct RoutingGeoDatabase {
    private struct Region {
        var prefixes = [Int: Set<Data>]()
        var reversed = false
    }
    private var regions = [String: Region]()
    private static let invalid = RuleProblem.message("GEOIP.dat 네트워크 데이터를 읽을 수 없습니다.")

    private struct Reader {
        let bytes: Data
        var cursor: Data.Index
        init(_ bytes: Data) { self.bytes = bytes; cursor = bytes.startIndex }
        mutating func number() throws -> Int {
            var result = 0
            for shift in stride(from: 0, through: 56, by: 7) {
                guard cursor < bytes.endIndex else { throw RoutingGeoDatabase.invalid }
                let byte = bytes[cursor]
                cursor += 1
                result |= Int(byte & 127) << shift
                if byte < 128 { return result }
            }
            throw RoutingGeoDatabase.invalid
        }
        mutating func field() throws -> (Int, Data, Int)? {
            guard cursor < bytes.endIndex else { return nil }
            let tag = try number()
            guard tag >= 8 else { throw RoutingGeoDatabase.invalid }
            if tag & 7 == 0 { return (tag >> 3, Data(), try number()) }
            guard tag & 7 == 2 else { throw RoutingGeoDatabase.invalid }
            let size = try number()
            guard size >= 0, size <= bytes.endIndex - cursor else { throw RoutingGeoDatabase.invalid }
            let value = bytes[cursor..<cursor + size]
            cursor += size
            return (tag >> 3, value, 0)
        }
    }

    static func subset(from source: Data, for document: RoutingDocument) throws -> Data {
        guard source.count <= 128 * 1024 * 1024 else { throw invalid }
        let expression = try NSRegularExpression(pattern: #"GEOIP,([a-z0-9_-]+)"#, options: [.caseInsensitive])
        var codes = Set<String>()
        for rule in document.rules {
            let text = "\(rule.kind),\(rule.value)"
            let value = text as NSString
            for match in expression.matches(in: text, range: NSRange(location: 0, length: value.length)) {
                codes.insert(value.substring(with: match.range(at: 1)).uppercased())
            }
        }
        var result = Data(), reader = Reader(source)
        while reader.cursor < source.endIndex {
            let start = reader.cursor
            guard let (id, entry, _) = try reader.field(), id == 1 else { throw invalid }
            var fields = Reader(entry)
            while let (key, data, _) = try fields.field() {
                if key == 1 {
                    if let name = String(data: data, encoding: .utf8), codes.contains(name.uppercased()) {
                        result.append(source[start..<reader.cursor])
                    }
                    break
                }
            }
        }
        return result
    }

    init(_ source: Data) throws {
        guard source.count <= 20 * 1024 * 1024 else { throw Self.invalid }
        var reader = Reader(source)
        while let (id, entry, _) = try reader.field() {
            guard id == 1 else { throw Self.invalid }
            var name = "", region = Region(), fields = Reader(entry)
            while let (key, data, number) = try fields.field() {
                switch key {
                case 1: name = String(data: data, encoding: .utf8)?.uppercased() ?? ""
                case 2:
                    var parts = Reader(data), ip = Data(), bits = 0
                    while let (k, address, n) = try parts.field() {
                        if k == 1 { ip = Data(address) }
                        if k == 2 { bits = n }
                    }
                    guard [4, 16].contains(ip.count), (0...ip.count * 8).contains(bits) else { throw Self.invalid }
                    region.prefixes[bits, default: []].insert(Self.mask(ip, bits))
                case 3: region.reversed = number != 0
                default: continue
                }
            }
            guard !name.isEmpty, regions[name] == nil else { throw Self.invalid }
            regions[name] = region
        }
    }

    private static func mask(_ ip: Data, _ bits: Int) -> Data {
        var key = Data([UInt8(ip.count)])
        key.append(ip.prefix(bits / 8))
        if bits % 8 != 0 { key.append(ip[bits / 8] & (0xff << (8 - bits % 8))) }
        return key
    }

    func classifier(address: String) -> (String) -> Comparison {
        var bytes = [UInt8](repeating: 0, count: 16)
        let ip: Data?
        if inet_pton(AF_INET, address, &bytes) == 1 { ip = Data(bytes.prefix(4)) }
        else if inet_pton(AF_INET6, address, &bytes) == 1 { ip = Data(bytes) }
        else { ip = nil }
        return { code in
            guard let ip, let region = regions[code] else { return .unknown }
            let match = region.prefixes.contains { bits, entries in
                bits <= ip.count * 8 && entries.contains(Self.mask(ip, bits))
            }
            return match != region.reversed ? .yes : .no
        }
    }
}
