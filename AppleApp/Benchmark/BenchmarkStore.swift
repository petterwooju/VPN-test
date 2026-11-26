import Combine
import CryptoKit
import Foundation

@MainActor
final class BenchmarkStore: ObservableObject {
    private struct Document: Codable {
        var version = 1
        var runs: [BenchmarkRun]
    }

    private let fileURL: URL
    static let baselineID = UUID(uuidString: "84278AED-AAB6-46CF-B301-202611250001")!
    @Published private(set) var runs: [BenchmarkRun]

    init(fileURL: URL) throws {
        self.fileURL = fileURL
        if FileManager.default.fileExists(atPath: fileURL.path) {
            let document = try JSONDecoder().decode(Document.self, from: Data(contentsOf: fileURL))
            guard document.version == 1 else { throw BenchmarkError.corruptStore }
            // A killed foreground scan can resume, but no longer owns a live operation.
            runs = document.runs.map { original in
                var run = original
                if run.phase == .scanning {
                    run.phase = .paused
                    run.recoveryNeeded = true
                    run.activeHost = nil
                }
                return run
            }
        } else {
            runs = []
        }
    }

    func save(_ run: BenchmarkRun) throws {
        var updated = runs
        if let index = updated.firstIndex(where: { $0.id == run.id }) {
            updated[index] = run
        } else {
            updated.append(run)
        }
        let data = try JSONEncoder().encode(Document(runs: updated))
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try data.write(to: fileURL, options: .atomic)
        runs = updated
    }

    func rankings(for network: BenchmarkNetwork) -> [ServerRank] {
        BenchmarkRun.rank(runs.filter { $0.network == network }.flatMap(\.rows))
    }

    func httpsRankings(for network: BenchmarkNetwork) -> [HTTPSServerRank] {
        BenchmarkRun.rankHTTPS(runs.filter { $0.network == network }.flatMap(\.rows))
    }

    // Supply .beijingReference unless the user has explicitly identified the original Mac/en6.
    // Rebinding from the reference to that installation is permitted once, never duplicates rows.
    func importBeijingBaseline(csv: String, into network: BenchmarkNetwork = .beijingReference) throws {
        guard network.interface == "en6", network.transport.lowercased() == "ethernet",
              !network.label.isEmpty, !network.deviceID.isEmpty else { throw BenchmarkError.invalidBaseline }
        if let old = runs.first(where: { $0.id == Self.baselineID }) {
            if old.network == network || network == .beijingReference { return }
            guard old.network == .beijingReference else { throw BenchmarkError.invalidBaseline }
        }
        let rows = csv.trimmingCharacters(in: CharacterSet(charactersIn: "\u{FEFF}"))
            .components(separatedBy: .newlines).filter { !$0.isEmpty }
        guard rows.first == "server,dns_ipv4,measured_at,tunnel,sent,received,loss_pct,average_ms,minimum_ms,maximum_ms" else {
            throw BenchmarkError.invalidBaseline
        }
        // The bundled source is the original 10-column benchmark, which contains no quoted fields.
        let date = ISO8601DateFormatter()
        let attempts: [BenchmarkAttempt] = try rows.dropFirst().map { line in
            let fields = line.components(separatedBy: ",")
            guard fields.count == 10, let time = date.date(from: fields[2]), !fields[3].isEmpty,
                  let sent = Int(fields[4]), let received = Int(fields[5]),
                  let mean = Double(fields[7]), let minimum = Double(fields[8]), let maximum = Double(fields[9])
            else { throw BenchmarkError.invalidBaseline }
            let sample = try PingSample(sent: sent, received: received, meanMS: mean, minimumMS: minimum, maximumMS: maximum)
            guard Double(fields[6]) == sample.lossPercent else { throw BenchmarkError.invalidBaseline }
            return BenchmarkAttempt(host: fields[0], time: time, outcome: .measured, sample: sample)
        }
        let hosts = attempts.map(\.host)
        guard hosts.count == CoreaServer.catalog.count, Set(hosts) == Set(CoreaServer.catalog.map(\.host)),
              let start = attempts.map(\.time).min(),
              let end = date.date(from: "2026-11-25T17:35:04+08:00")
        else { throw BenchmarkError.invalidBaseline }
        var baseline = BenchmarkRun(id: Self.baselineID, network: network, mode: .all, started: start,
                                    order: hosts, baseline: ScanBaseline(host: nil, connected: false, onDemand: false))
        baseline.rows = attempts
        baseline.phase = .completed
        baseline.finished = end
        baseline.message = "2026-11-25 베이징 사무실 유선망 측정 기록"
        try save(baseline)
    }

    func csv(network: BenchmarkNetwork? = nil) -> String {
        let date = ISO8601DateFormatter()
        var lines = ["run,device,network,transport,interface,physical_network,mode,phase,server,measured_at,protocol,target,outcome,sent,received,loss_pct,mean_ms,min_ms,max_ms,detail,measurement,https_peer_ipv4,https_sent,https_received,https_failure_pct,https_idle_ms,download_mbps,upload_mbps,download_loaded_ms,upload_loaded_ms,download_bytes,upload_bytes,icmp_target,https_target,ping_error,https_error,download_rank_first,selected_server,download_seconds,upload_seconds,selection_error"]
        for run in runs where network == nil || run.network == network {
            let fastest = run.httpsRanks.first?.host ?? ""
            for attempt in run.rows {
                let sample = attempt.sample
                let https = attempt.httpsSample
                let paired = run.paired == true || (https != nil && sample != nil)
                let target = paired ? "" : (https != nil ? HTTPSBenchmarkSample.target : (sample != nil ? PingSample.target : ""))
                var fields: [String] = [
                    run.id.uuidString, run.network.deviceID, run.network.label, run.network.transport, run.network.interface,
                    run.network.fingerprint ?? "",
                    run.mode.rawValue, run.phase.rawValue, attempt.host, date.string(from: attempt.time), "IKEv2", target,
                    attempt.outcome.rawValue
                ]
                fields.append(sample.map { String($0.sent) } ?? "")
                fields.append(sample.map { String($0.received) } ?? "")
                for value in [sample?.lossPercent, sample?.meanMS, sample?.minimumMS, sample?.maximumMS] {
                    fields.append(value.map { String($0) } ?? "")
                }
                fields.append(attempt.detail ?? "")
                fields.append(paired ? "ICMP+HTTPS" : (https != nil ? "HTTPS" : (sample != nil ? "ICMP" : "")))
                fields.append(https?.peerIPv4 ?? "")
                fields.append(https.map { String($0.sent) } ?? "")
                fields.append(https.map { String($0.received) } ?? "")
                for value in [https?.failurePercent, https?.averageMS, https?.downloadMbps, https?.uploadMbps,
                              https?.downloadLoadedMS, https?.uploadLoadedMS] {
                    fields.append(value.map { String($0) } ?? "")
                }
                fields.append(https?.downloadBytes.map { String($0) } ?? "")
                fields.append(https?.uploadBytes.map { String($0) } ?? "")
                fields += [paired || sample != nil ? PingSample.target : "", paired || https != nil ? HTTPSBenchmarkSample.target : "",
                           attempt.pingError ?? "", attempt.httpsError ?? "", fastest, run.selectedHost ?? ""]
                fields += [https?.downloadSeconds.map { String($0) } ?? "", https?.uploadSeconds.map { String($0) } ?? "",
                           attempt.selectionError ?? ""]
                lines.append(fields.map(Self.escapeCSV).joined(separator: ","))
            }
        }
        return "\u{FEFF}" + lines.joined(separator: "\r\n") + "\r\n"
    }

    private static func escapeCSV(_ value: String) -> String {
        let safe = value.first.map { "=+-@\t\r".contains($0) } == true ? "'" + value : value
        return "\"" + safe.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }
}

enum LocalMeasurement: String, Codable, CaseIterable {
    case https
    case icmp

    static let preferenceKey = "coreaVPNLocalMeasurement"

    var title: String {
        switch self {
        case .https: return "FAST 방식 (HTTPS)"
        case .icmp: return "ICMP ping (\(PingSample.target))"
        }
    }

    var arguments: [String] { ["--measurement", rawValue] }

    func decode(_ data: Data, host: String) throws -> LocalProbeResult {
        switch self {
        case .https: return try LocalProbeResult.decodeHTTPS(data, host: host)
        case .icmp: return try LocalPumaMeasurement.decodePing(data, host: host)
        }
    }

    var resultsFilename: String {
        switch self {
        case .https: return "https-results.jsonl"
        case .icmp: return "ping-results.jsonl"
        }
    }
}

/// Measurements collected by a local VPN runner.
struct LocalProbeResult: Equatable {
    var sample: PingSample?
    var httpsSample: HTTPSBenchmarkSample?
    let started: Date
    let ended: Date
    let tunnel: String

    var received: Int { httpsSample?.received ?? sample?.received ?? 0 }
    var qualifies: Bool { httpsSample?.qualifies ?? sample?.qualifies ?? false }

    private struct HTTPSEvidence: Decodable {
        let measurement: String
        let valid: Bool
        let server: String, target: String, tunnel: String, started: String, ended: String
        let peer_ipv4: String
        var speed: HTTPSBenchmarkSample
    }

    static func decodeHTTPS(_ data: Data, host: String) throws -> Self {
        var result = try JSONDecoder().decode(HTTPSEvidence.self, from: data)
        result.speed.discardUnconfirmedUpload()
        let date = ISO8601DateFormatter()
        guard result.measurement == "https", result.valid, result.server == host,
              result.target == HTTPSBenchmarkSample.target, result.speed.valid,
              result.tunnel.range(of: #"^ipsec[0-9]+$"#, options: .regularExpression) != nil,
              VPNEndpoints.isPublicIPv4(result.peer_ipv4),
              let start = date.date(from: result.started), let end = date.date(from: result.ended),
              start <= end else { throw LocalPumaImportError.invalid }
        result.speed.peerIPv4 = result.peer_ipv4
        return Self(httpsSample: result.speed, started: start, ended: end, tunnel: result.tunnel)
    }
}

struct LocalPumaMeasurement {
    let sourceID: String
    let probe: LocalProbeResult
    let interface: String
    var started: Date { probe.started }
    var ended: Date { probe.ended }
    var sample: PingSample? { probe.sample }
    var httpsSample: HTTPSBenchmarkSample? { probe.httpsSample }
    var tunnel: String { probe.tunnel }
    var received: Int { probe.received }
    static let host = "puma.coreavpn.net"

    fileprivate var runID: UUID {
        // Deterministic across repeated imports, log moves and app restarts.
        let digest = SHA256.hash(data: Data(("CoreaVPN/legacy/" + sourceID.lowercased()).utf8))
        return digest.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
    }

    private struct Plan: Decodable {
        let device: String
        let measurement: LocalMeasurement?
    }
    private struct Recovery: Decodable { let ok: Bool; let errors: [String] }
    private struct Event: Decodable {
        let stage: String
        let ok: Bool?
        let seconds: Int?
    }
    private struct Result: Decodable {
        let server: String, target: String, tunnel: String, started: String, ended: String
        let valid: Bool
        let ping: Statistics
    }
    private struct Statistics: Decodable {
        let sent: Int, received: Int, loss_pct: Double
        let minimum_ms: Double?, average_ms: Double?, maximum_ms: Double?
    }

    private static func validateDirectory(_ directory: URL) throws {
        let sourceID = directory.lastPathComponent
        let name = #"^(?:[0-9]{8}-[0-9]{6}|[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})-puma-pilot$"#
        let flags = try directory.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard flags.isDirectory == true, flags.isSymbolicLink != true,
              sourceID.range(of: name, options: .regularExpression) != nil else { throw LocalPumaImportError.invalid }

    }

    private static func read(_ name: String, from directory: URL, limit: Int = 32_768) throws -> Data {
        let url = directory.appendingPathComponent(name)
        let flags = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard flags.isRegularFile == true, flags.isSymbolicLink != true else { throw LocalPumaImportError.invalid }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: limit + 1) ?? Data()
        guard data.count <= limit else { throw LocalPumaImportError.invalid }
        return data
    }

    static func load(from directory: URL) throws -> Self {
        try validateDirectory(directory)
        let decoder = JSONDecoder()
        let plan = try decoder.decode(Plan.self, from: read("plan.json", from: directory))
        let probe = try readProbe(from: directory, measurement: plan.measurement)
        let recovery = try decoder.decode(Recovery.self, from: read("recovered.json", from: directory))
        guard recovery.ok, recovery.errors.isEmpty else { throw LocalPumaImportError.incomplete }
        let lines = try read("events.jsonl", from: directory, limit: 256_000).split(separator: 10).map { Data($0) }
        let events = try lines.map { try decoder.decode(Event.self, from: $0) }
        if events.last(where: { $0.stage == "worker-finished" })?.ok == true {
            _ = try read("finished", from: directory, limit: 0)
        } else {
            // A watchdog can finish recovery after the originating worker has exited.
            let method: LocalMeasurement = probe.httpsSample == nil ? .icmp : .https
            let complete = method == .icmp ? "ping-complete" : "https-complete"
            guard let measured = events.lastIndex(where: { $0.stage == complete }),
                  let failed = events.lastIndex(where: { $0.stage == "recovery-complete" && $0.ok == false }),
                  let stable = events.lastIndex(where: { $0.stage == "system-proxy-stable" && ($0.seconds ?? 0) >= 30 }),
                  let verified = events.lastIndex(where: { $0.stage == "verify-stable-flclash-proxy" }),
                  let final = events.lastIndex(where: { $0.stage == "recovery-complete" }),
                  measured < failed, failed < stable, stable < verified, verified < final,
                  events[verified].ok == true, events[final].ok == true,
                  !events.contains(where: { $0.stage == "measurement-stopped" }),
                  let event = try JSONSerialization.jsonObject(with: lines[measured]) as? [String: Any],
                  let evidence = event["result"] as? [String: Any],
                  try method.decode(JSONSerialization.data(withJSONObject: evidence), host: host) == probe else {
                throw LocalPumaImportError.incomplete
            }
        }
        guard !plan.device.isEmpty else { throw LocalPumaImportError.invalid }
        return Self(sourceID: directory.lastPathComponent, probe: probe, interface: plan.device)
    }

    static func readProbe(from directory: URL) throws -> LocalProbeResult {
        try validateDirectory(directory)
        let plan = try JSONDecoder().decode(Plan.self, from: read("plan.json", from: directory))
        return try readProbe(from: directory, measurement: plan.measurement)
    }

    private static func readProbe(from directory: URL, measurement: LocalMeasurement?) throws -> LocalProbeResult {
        // Runs from older app versions had one result file and no method in the plan.
        let speedFile = directory.appendingPathComponent(LocalMeasurement.https.resultsFilename)
        let method = measurement ?? (FileManager.default.fileExists(atPath: speedFile.path) ? .https : .icmp)
        let lines = try read(method.resultsFilename, from: directory).split(separator: 10)
        guard lines.count == 1, let line = lines.first else { throw LocalPumaImportError.invalid }
        return try method.decode(Data(line), host: host)
    }

    static func decodePing(_ data: Data, host: String) throws -> LocalProbeResult {
        let result = try JSONDecoder().decode(Result.self, from: data)
        let date = ISO8601DateFormatter()
        guard result.valid, result.server == host, result.target == PingSample.target,
              result.tunnel.range(of: #"^ipsec[0-9]+$"#, options: .regularExpression) != nil,
              let start = date.date(from: result.started), let end = date.date(from: result.ended),
              start <= end else { throw LocalPumaImportError.invalid }
        let ping = result.ping
        let sample = try PingSample(sent: ping.sent, received: ping.received, meanMS: ping.average_ms,
                                    minimumMS: ping.minimum_ms, maximumMS: ping.maximum_ms)
        guard sample.lossPercent == ping.loss_pct,
              ping.received == 0 || (ping.minimum_ms != nil && ping.maximum_ms != nil) else { throw LocalPumaImportError.invalid }
        return LocalProbeResult(sample: sample, started: start, ended: end, tunnel: result.tunnel)
    }
}

private enum LocalPumaImportError: LocalizedError {
    case invalid, incomplete, network, conflict
    var errorDescription: String? {
        switch self {
        case .invalid: return "Puma 터널의 20회 측정 기록을 확인할 수 없습니다."
        case .incomplete: return "검사 완료와 FlClash 복구를 확인한 뒤 다시 가져오세요."
        case .network: return "이 측정을 실행한 Mac의 같은 유선 또는 Wi-Fi 회선을 선택해 주세요."
        case .conflict: return "이미 가져온 검사와 회선 또는 측정값이 다릅니다."
        }
    }
}

extension BenchmarkStore {
    /// Old logs lack physical network fingerprints. Confirm the Mac and network in the UI.
    @discardableResult
    func importLocalPuma(from directory: URL, into network: BenchmarkNetwork) throws -> Bool {
        let measurement = try LocalPumaMeasurement.load(from: directory)
        guard network.interface == measurement.interface,
              network.interface.range(of: #"^en[0-9]+$"#, options: .regularExpression) != nil,
              ["ethernet", "wifi"].contains(network.transport),
              network.deviceID != BenchmarkNetwork.beijingReference.deviceID,
              !network.deviceID.isEmpty, !network.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw LocalPumaImportError.network
        }
        let host = LocalPumaMeasurement.host
        let source = "로컬 Puma 검사 · " + measurement.sourceID
        if var old = runs.first(where: { $0.id == measurement.runID || ($0.mode == .puma && $0.started == measurement.started) }) {
            guard old.network == network, old.started == measurement.started, old.finished == measurement.ended,
                  old.rows.count == 1, let row = old.rows.first, row.host == host, row.sample == measurement.sample,
                  row.httpsSample?.restoringTimes(from: measurement.httpsSample) == measurement.httpsSample,
                  row.detail == measurement.tunnel else { throw LocalPumaImportError.conflict }
            guard row.httpsSample != measurement.httpsSample else { return false }
            old.rows[0].httpsSample = measurement.httpsSample
            try save(old)
            return true
        }
        var run = BenchmarkRun(id: measurement.runID, network: network, mode: .puma, started: measurement.started,
                               order: [host], baseline: ScanBaseline(host: nil, connected: false, onDemand: false))
        run.phase = .completed
        run.finished = measurement.ended
        run.message = source
        run.rows = [BenchmarkAttempt(host: host, time: measurement.started,
                                     outcome: measurement.received == 0 ? .noReply : .measured,
                                     sample: measurement.sample, detail: measurement.tunnel, httpsSample: measurement.httpsSample)]
        try save(run)
        return true
    }
}
