import Foundation

// The provider groups govern simultaneous logins. See https://coreavpn.net/docs/servers.htm .
struct CoreaServer: Identifiable, Hashable {
    let host: String
    let group: String
    let iPhoneSupported: Bool
    var id: String { host }
    var requiresExtendedAccount: Bool { group == "D" || group == "E" }

    static let catalog: [CoreaServer] = {
        let table: [(String, String, String, Bool)] = [
            ("lynx", "net", "A", true), ("puma", "net", "B", true),
            ("saturn", "net", "C", true), ("ibex", "net", "B", true),
            ("lion", "net", "B", false), ("titan", "net", "C", true),
            ("hornet", "net", "A", true), ("venus", "net", "C", false),
            ("wolf", "net", "B", false), ("oryx", "net", "C", false),
            ("gannet", "net", "B", false), ("leo", "net", "C", false),
            ("falcon", "net", "B", false), ("hawk", "net", "B", false),
            ("cougar", "net", "C", false), ("moon", "net", "C", false),
            ("eagle", "net", "A", true), ("lynx", "com", "D", true),
            ("puma", "com", "D", true), ("gannet", "com", "D", false),
            ("moon", "com", "D", false), ("lynx", "kr", "E", true),
            ("venus", "kr", "E", true)
        ]
        return table.map { name, suffix, group, supported in
            CoreaServer(host: "\(name).coreavpn.\(suffix)", group: group, iPhoneSupported: supported)
        }
    }()
}

struct BenchmarkNetwork: Hashable, Codable {
    let deviceID: String
    let label: String
    let interface: String
    let transport: String
    var fingerprint: String? = nil

    // A different Mac with en6 must never inherit the local reference by inference.
    static let beijingReference = BenchmarkNetwork(deviceID: "reference-mac-20261125",
                                                    label: "Beijing office", interface: "en6", transport: "ethernet")
}

enum ScanMode: String, Codable {
    case quick, fastQuick, all, puma

    func candidates(configured: [CoreaServer]) -> [CoreaServer] {
        #if os(macOS)
        if self == .all { return CoreaServer.catalog }
        #endif
        return configured
    }
}
enum ScanPhase: String, Codable { case scanning, paused, retained, completed, cancelled, failed }
enum AttemptOutcome: String, Codable { case measured, noReply, failed, skipped, partial, stopped, notRun }

enum BenchmarkError: LocalizedError {
    case invalidSample, invalidBaseline, wrongNetwork, invalidResume, busy, noCandidates, duplicate, corruptStore
    var errorDescription: String? {
        switch self {
        case .invalidSample: return "유효한 터널 ping 표본이 아닙니다."
        case .invalidBaseline: return "베이징 사무실 기준선 파일 또는 회선 지정이 올바르지 않습니다."
        case .wrongNetwork: return "회선이 바뀌어 측정을 일시 정지했습니다."
        case .invalidResume: return "같은 회선과 검사 설정에서만 이어갈 수 있습니다."
        case .busy: return "진행 중인 VPN 작업이 있습니다."
        case .noCandidates: return "이 기기와 계정에서 검사할 서버가 없습니다."
        case .duplicate: return "중복된 서버가 포함되어 있습니다."
        case .corruptStore: return "측정 기록의 형식을 읽을 수 없습니다."
        }
    }
}

struct PingSample: Codable, Equatable {
    static let probeCount = 20
    static let target = "168.126.63.1"
    let sent: Int
    let received: Int
    let meanMS: Double?
    let minimumMS: Double?
    let maximumMS: Double?

    init(sent: Int, received: Int, meanMS: Double?, minimumMS: Double? = nil, maximumMS: Double? = nil) throws {
        guard sent == Self.probeCount, (0...sent).contains(received),
              [minimumMS, meanMS, maximumMS].compactMap({ $0 }).allSatisfy({ $0.isFinite && $0 >= 0 }),
              (received == 0) == (meanMS == nil),
              received > 0 || (minimumMS == nil && maximumMS == nil),
              minimumMS.map({ $0 <= (meanMS ?? 0) }) ?? true,
              maximumMS.map({ $0 >= (meanMS ?? 0) }) ?? true
        else { throw BenchmarkError.invalidSample }
        self.sent = sent
        self.received = received
        self.meanMS = meanMS
        self.minimumMS = minimumMS
        self.maximumMS = maximumMS
    }

    var lossPercent: Double { 100 * Double(sent - received) / Double(sent) }
    var qualifies: Bool {
        sent == Self.probeCount && (0...sent).contains(received) &&
            lossPercent <= 10 && (0...100).contains(meanMS ?? .infinity)
    }
}

struct HTTPSBenchmarkSample: Codable, Equatable {
    static let target = "speed.cloudflare.com"
    static let quickMinimumMbps = 50
    static var quickConnectionTitle: String { "FAST 다운로드 \(quickMinimumMbps)Mbps 이상 서버 연결" }
    static let probeCount = 20
    let sent: Int
    let received: Int
    let averageMS: Double?
    var downloadMbps: Double?
    var uploadMbps: Double?
    let downloadLoadedMS: Double?
    let uploadLoadedMS: Double?
    var downloadBytes: Int?
    var uploadBytes: Int?
    var downloadSeconds: Double? = nil
    var uploadSeconds: Double? = nil
    var peerIPv4: String? = nil

    enum CodingKeys: String, CodingKey {
        case sent, received
        case averageMS = "average_ms"
        case downloadMbps = "download_mbps"
        case uploadMbps = "upload_mbps"
        case downloadLoadedMS = "download_loaded_ms"
        case uploadLoadedMS = "upload_loaded_ms"
        case downloadBytes = "download_bytes"
        case uploadBytes = "upload_bytes"
        case downloadSeconds = "download_seconds"
        case uploadSeconds = "upload_seconds"
        case peerIPv4 = "peer_ipv4"
    }

    var valid: Bool {
        (0...Self.probeCount).contains(sent) && (0...sent).contains(received) &&
        (received == 0) == (averageMS == nil) &&
        [averageMS, downloadLoadedMS, uploadLoadedMS].compactMap { $0 }.allSatisfy { $0.isFinite && $0 >= 0 } &&
        [downloadMbps, uploadMbps].compactMap { $0 }.allSatisfy { $0.isFinite && $0 > 0 } &&
        [downloadBytes, uploadBytes].compactMap { $0 }.allSatisfy { $0 >= 0 } &&
        (downloadSeconds == nil || Self.matches(downloadMbps, bytes: downloadBytes, seconds: downloadSeconds)) &&
        (uploadSeconds == nil || Self.matches(uploadMbps, bytes: uploadBytes, seconds: uploadSeconds))
    }

    var failurePercent: Double? { sent > 0 ? 100 * Double(sent - received) / Double(sent) : nil }
    private static func matches(_ rate: Double?, bytes: Int?, seconds: Double?) -> Bool {
        guard let seconds, seconds.isFinite, seconds > 0,
              let bytes, bytes > 0, let rate, rate.isFinite, rate > 0 else { return false }
        let measured = Double(bytes) * 8 / (1_000_000 * seconds)
        return measured.isFinite && abs(measured - rate) <= 1e-9 * max(measured, rate)
    }
    var qualifies: Bool {
        (downloadMbps ?? 0) >= Double(Self.quickMinimumMbps) && Self.matches(downloadMbps, bytes: downloadBytes, seconds: downloadSeconds)
    }

    mutating func discardUnconfirmedUpload() {
        if uploadSeconds != nil && !Self.matches(uploadMbps, bytes: uploadBytes, seconds: uploadSeconds) {
            uploadSeconds = nil
            uploadBytes = nil
            uploadMbps = nil
        }
    }

    // Earlier store versions discarded elapsed times even when present in the source report.
    func restoringTimes(from source: Self?) -> Self {
        var updated = self
        updated.downloadSeconds = downloadSeconds ?? source?.downloadSeconds
        updated.uploadSeconds = uploadSeconds ?? source?.uploadSeconds
        return updated
    }
}

struct ScanBaseline: Codable, Equatable {
    var host: String?
    var connected: Bool
    var onDemand: Bool
    // Only non-secret connection settings; never persist password/PSK here.
    var endpoint: String? = nil
    var authentication: String? = nil
    var enabled: Bool = true
}

struct BenchmarkAttempt: Codable, Identifiable, Equatable {
    var id: String { host }
    let host: String
    let time: Date
    var outcome: AttemptOutcome
    var sample: PingSample?
    var detail: String?
    var httpsSample: HTTPSBenchmarkSample?
    var pingError: String?
    var httpsError: String?
    var selectionError: String?
    var retentionInvalidated: Bool?
    var qualifies: Bool { retentionInvalidated != true && (httpsSample?.qualifies ?? sample?.qualifies ?? false) }
}

struct ServerRank: Identifiable {
    var id: String { host }
    let host: String
    var sent = 0
    var received = 0
    var runCount = 0
    var weightedRTT = 0.0
    var meanMS: Double? { received > 0 ? weightedRTT / Double(received) : nil }
    var lossPercent: Double { sent > 0 ? 100 * Double(sent - received) / Double(sent) : 100 }
}

struct HTTPSServerRank: Identifiable {
    var id: String { host }
    let host: String
    var runCount = 0
    fileprivate var download = 0.0
    fileprivate var upload = 0.0
    fileprivate var uploadCount = 0
    fileprivate var sent = 0
    fileprivate var received = 0
    fileprivate var weightedLatency = 0.0

    var downloadMbps: Double { download / Double(runCount) }
    var uploadMbps: Double? { uploadCount > 0 ? upload / Double(uploadCount) : nil }
    var failurePercent: Double? { sent > 0 ? 100 * Double(sent - received) / Double(sent) : nil }
    var idleLatencyMS: Double? { received > 0 ? weightedLatency / Double(received) : nil }
}

struct BenchmarkRun: Codable, Identifiable {
    let id: UUID
    let network: BenchmarkNetwork
    let mode: ScanMode
    let started: Date
    let order: [String]
    let baseline: ScanBaseline
    var rows: [BenchmarkAttempt] = []
    var phase: ScanPhase = .scanning
    var activeHost: String? = nil
    var selectedHost: String? = nil
    var message: String? = nil
    var finished: Date? = nil
    var recoveryNeeded: Bool? = nil
    var paired: Bool? = nil
    var selectionBaseline: ScanBaseline? = nil

    var ranks: [ServerRank] { Self.rank(rows) }
    var httpsRanks: [HTTPSServerRank] { Self.rankHTTPS(rows) }
    var canResume: Bool { phase == .paused || phase == .scanning }
    static func rank(_ attempts: [BenchmarkAttempt]) -> [ServerRank] {
        var totals: [String: ServerRank] = [:]
        for attempt in attempts {
            guard let sample = attempt.sample else { continue }
            var total = totals[attempt.host] ?? ServerRank(host: attempt.host)
            total.sent += sample.sent
            total.received += sample.received
            total.runCount += 1
            total.weightedRTT += (sample.meanMS ?? 0) * Double(sample.received)
            totals[attempt.host] = total
        }
        return totals.values.sorted {
            if $0.lossPercent != $1.lossPercent { return $0.lossPercent < $1.lossPercent }
            if $0.meanMS != $1.meanMS { return ($0.meanMS ?? .infinity) < ($1.meanMS ?? .infinity) }
            return $0.host < $1.host
        }
    }

    static func rankHTTPS(_ attempts: [BenchmarkAttempt]) -> [HTTPSServerRank] {
        var totals: [String: HTTPSServerRank] = [:]
        for attempt in attempts {
            guard let sample = attempt.httpsSample, sample.valid,
                  let down = sample.downloadMbps, (sample.downloadBytes ?? 0) > 0 else { continue }
            var total = totals[attempt.host] ?? HTTPSServerRank(host: attempt.host)
            total.runCount += 1
            total.download += down
            if let up = sample.uploadMbps, (sample.uploadBytes ?? 0) > 0 {
                total.upload += up
                total.uploadCount += 1
            }
            total.sent += sample.sent
            total.received += sample.received
            total.weightedLatency += (sample.averageMS ?? 0) * Double(sample.received)
            totals[attempt.host] = total
        }
        return totals.values.sorted {
            if $0.downloadMbps != $1.downloadMbps { return $0.downloadMbps > $1.downloadMbps }
            if $0.failurePercent != $1.failurePercent { return ($0.failurePercent ?? .infinity) < ($1.failurePercent ?? .infinity) }
            if $0.idleLatencyMS != $1.idleLatencyMS { return ($0.idleLatencyMS ?? .infinity) < ($1.idleLatencyMS ?? .infinity) }
            return $0.host < $1.host
        }
    }
}
