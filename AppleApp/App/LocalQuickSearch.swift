#if os(macOS)
import AppKit
import CryptoKit
import Foundation

/// The detached supervisor owns the profile, watchdog and global lock. This
/// object issues requests and observes files so the app can quit and reconnect.
@MainActor
final class LocalQuickSearch: ObservableObject {
    private enum Operation: String, Codable { case quick, all, select }

    private struct Request: Codable {
        let id: UUID
        let hosts: [String]
        let network: BenchmarkNetwork
        let started: Date
        let measurement: LocalMeasurement?
        var operation: Operation? = nil
        var comparisonID: UUID? = nil
        var imported: Bool? = nil
        var kind: Operation { operation ?? .quick }
    }
    private struct State: Decodable {
        let phase: String
        let host: String?
        let reason: String?
        let recovered: Bool?
    }
    private struct Event: Decodable {
        let stage: String
        let server: String?
        let step: String?
        let time: String?
        let tunnel: String?
        let error: String?
        let ok: Bool?
        var evidence: Data? = nil

        static func parse(_ data: Data) -> Self? {
            guard var event = try? JSONDecoder().decode(Self.self, from: data) else { return nil }
            if ["ping-complete", "https-complete", "https-idle-complete", "https-download-complete"].contains(event.stage),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let raw = json["result"] as? [String: Any] {
                event.evidence = try? JSONSerialization.data(withJSONObject: raw)
            }
            return event
        }
    }
    private struct Plan: Decodable { let device: String; let operation: Operation? }
    private struct Connection: Decodable {
        let measurement: String, target: String, server: String, tunnel: String
        let valid: Bool, interface_index: Int

        func matches(_ host: String) -> Bool {
            measurement == "connection" && target == PingSample.target && server == host && valid &&
                interface_index > 0 && tunnel.range(of: #"^ipsec[0-9]+$"#, options: .regularExpression) != nil
        }
    }
    private struct Recovery: Decodable { let ok: Bool; let errors: [String] }
    private struct Server: Decodable { let server: String }

    @Published private(set) var running = false
    @Published private(set) var retainedHost: String?
    @Published private(set) var activeHost: String?
    @Published private(set) var status = ""
    @Published private(set) var latestDirectory: URL?
    @Published private(set) var results: [BenchmarkAttempt] = []
    @Published private(set) var recoveryVerified = false
    @Published private(set) var canRelease = false
    @Published private(set) var phase = ""
    @Published private(set) var lastMeasurement: LocalMeasurement?
    @Published private(set) var comparisonRows: [BenchmarkAttempt] = []
    @Published private(set) var comparisonReady = false
    @Published private(set) var selectionFailure: String?
    private let comparisonKey = "localFullComparisonRequest.v1"
    private var comparison: Request?
    var comparisonNetwork: BenchmarkNetwork? { comparison?.network }
    var comparisonID: UUID? { comparison?.id }
    var showingQuick: Bool { request?.kind == .quick }
    var failedSelectionHost: String? { selectionFailure != nil ? request?.hosts.first : nil }

    private let fm = FileManager.default
    private let defaults: UserDefaults
    private let requestKey = "localQuickSearchRequest.v1"
    private var request: Request?
    private var retryNeeded = false
    private var stoppedDuringSearch = false
    private var monitor: Task<Void, Never>?
    private let workspace: URL?
    private let pilotLockHeld: () -> Bool

    var releaseButtonTitle: String {
        if retryNeeded { return "FlClash 복구 재시도" }
        if running {
            switch phase {
            case "", "preparing", "searching":
                return canRelease ? "검사 중지" : "검사 중지 중…"
            case "recovering": return "FlClash 복구 중…"
            case "retained" where !canRelease: return "연결 해제 중…"
            default: break
            }
        }
        return "CoreaVPN 해제 · FlClash 복구"
    }

    private var runner: URL? {
        workspace?.appendingPathComponent("VPN-test/plugins/coreavpn-macos/skills/coreavpn-macos/scripts/quick-search.py")
    }

    private func configuredFile(_ key: String, _ name: String) -> URL? {
        guard let file = workspace?.appendingPathComponent("build/" + name, isDirectory: false),
              Bundle.main.object(forInfoDictionaryKey: key) as? String == file.path else { return nil }
        return file
    }

    private var uiHelper: URL? { configuredFile("CoreaVPNQuickUI", "offline-ui-quick") }
    private var calibration: URL? { configuredFile("CoreaVPNQuickMap", "fl-map.json") }

    var available: Bool {
        guard let runner, let ui = uiHelper, let map = calibration else { return false }
        let resolver = ui.deletingLastPathComponent().appendingPathComponent("quick-resolve")
        return fm.isReadableFile(atPath: runner.path) && fm.isReadableFile(atPath: map.path) &&
            fm.isExecutableFile(atPath: ui.path) && fm.isExecutableFile(atPath: resolver.path)
    }

    init(workspace: URL? = LocalTerminal.workspace, defaults: UserDefaults = .standard,
         pilotLockHeld: @escaping () -> Bool = LocalTerminal.anotherPilotIsRunning) {
        self.pilotLockHeld = pilotLockHeld
        self.workspace = workspace
        self.defaults = defaults
        if let data = defaults.data(forKey: requestKey) {
            request = try? JSONDecoder().decode(Request.self, from: data)
        }
        if let data = defaults.data(forKey: comparisonKey) {
            comparison = try? JSONDecoder().decode(Request.self, from: data)
        }
        if comparison == nil && request?.kind == .all { comparison = request }
        if let file = publishedComparison, let data = LocalTerminal.read(file, limit: 16_384),
           let archived = try? JSONDecoder().decode(Request.self, from: data),
           archived.imported == true && archived.kind == .all && archived.started > (comparison?.started ?? .distantPast) {
            comparison = archived
        }
        refresh()
    }

    private func directory(for request: Request) -> URL? {
        workspace?.appendingPathComponent("runs", isDirectory: true)
            .appendingPathComponent(request.id.uuidString + (request.imported == true ? "-imported-comparison" : "-quick-search"), isDirectory: true)
    }

    private var publishedComparison: URL? {
        workspace?.appendingPathComponent("runs/imported-comparison.json")
    }

    /// Archive a completed CLI comparison under the same decoder and recovery gate as app-launched scans.
    /// This stores only read-only report data. Executable files, watchdog state and release markers are excluded.
    func importComparison(from source: URL, into network: BenchmarkNetwork, store: BenchmarkStore) throws -> Bool {
        guard let publication = publishedComparison, !pilotLockHeld() else { throw BenchmarkError.corruptStore }
        func bytes(_ name: String, _ limit: Int) throws -> Data {
            guard let data = LocalTerminal.read(source.appendingPathComponent(name), limit: limit) else {
                throw BenchmarkError.corruptStore
            }
            return data
        }
        let reports = try ["events.jsonl": bytes("events.jsonl", 524_288), "plan.json": bytes("plan.json", 131_072),
                           "quick-state.json": bytes("quick-state.json", 32_768), "recovered.json": bytes("recovered.json", 16_384),
                           "quick-hosts.json": bytes("quick-hosts.json", 16_384)]
        let hosts = try JSONDecoder().decode([String].self, from: reports["quick-hosts.json"]!)
        let events = reports["events.jsonl"]!.split(separator: 10).compactMap { Event.parse(Data($0)) }
        let date = ISO8601DateFormatter()
        date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard !hosts.isEmpty, Set(hosts).count == hosts.count, Set(hosts).isSubset(of: Set(CoreaServer.catalog.map(\.host))),
              let start = events.first?.time.flatMap(date.date), let end = events.last?.time.flatMap(date.date), start <= end,
              events.last(where: { $0.stage == "recovery-complete" })?.ok == true,
              let e = events.first(where: { $0.stage == "server-start" }), e.server != nil else { throw BenchmarkError.corruptStore }
        let digest = SHA256.hash(data: reports["events.jsonl"]!)
        let originalID = source.lastPathComponent.hasSuffix("-quick-search") ?
            UUID(uuidString: String(source.lastPathComponent.dropLast("-quick-search".count))) : nil
        let id = originalID ?? digest.withUnsafeBytes { UUID(uuid: $0.loadUnaligned(as: uuid_t.self)) }
        let receipt = Request(id: id, hosts: hosts, network: network, started: start, measurement: nil, operation: .all, imported: true)
        guard let dest = directory(for: receipt) else { throw BenchmarkError.corruptStore }
        let state = try JSONDecoder().decode(State.self, from: reports["quick-state.json"]!)
        let plan = try JSONDecoder().decode(Plan.self, from: reports["plan.json"]!)
        let recovery = try JSONDecoder().decode(Recovery.self, from: reports["recovered.json"]!)
        guard Self.ready(receipt, state, plan, recovery, events) else { throw BenchmarkError.wrongNetwork }
        var record = BenchmarkRun(id: id, network: network, mode: .all, started: start, order: hosts,
                                  baseline: ScanBaseline(host: nil, connected: false, onDemand: false))
        record.paired = true
        record.phase = .completed
        record.finished = end
        record.message = "로컬 전체 검사 · " + source.lastPathComponent
        record.rows = pairedRows(request: receipt, events: events, stopped: false)
        let existing = store.runs.first { $0.id == id }
        var updatedExisting: BenchmarkRun?
        if var existing {
            var restoredTimes = false
            for index in existing.rows.indices {
                let saved = existing.rows[index]
                guard let current = record.rows.first(where: { $0.host == saved.host }) else { throw BenchmarkError.corruptStore }
                let enriched = saved.httpsSample?.restoringTimes(from: current.httpsSample)
                if enriched != saved.httpsSample {
                    existing.rows[index].httpsSample = enriched
                    restoredTimes = true
                }
            }
            guard existing.network == network && existing.mode == .all && existing.paired == true &&
                existing.rows.filter({ hosts.contains($0.host) }).map(\.sample) == record.rows.filter({ hosts.contains($0.host) }).map(\.sample) &&
                existing.rows.filter({ hosts.contains($0.host) }).map(\.httpsSample) == record.rows.filter({ hosts.contains($0.host) }).map(\.httpsSample)
                else { throw BenchmarkError.corruptStore }
            // Rebuild derived status text from the same verified raw events for older imports.
            for i in existing.rows.indices where hosts.contains(existing.rows[i].host) {
                guard let updated = record.rows.first(where: { $0.host == existing.rows[i].host }) else { continue }
                if existing.rows[i].httpsError != updated.httpsError || existing.rows[i].outcome != updated.outcome {
                    existing.rows[i].httpsError = updated.httpsError
                    existing.rows[i].outcome = updated.outcome
                    restoredTimes = true
                }
            }
            if restoredTimes { updatedExisting = existing }
        }
        try fm.createDirectory(at: dest.deletingLastPathComponent(), withIntermediateDirectories: true)
        if fm.fileExists(atPath: dest.path) {
            for (name, data) in reports where LocalTerminal.read(dest.appendingPathComponent(name), limit: data.count) != data {
                throw BenchmarkError.corruptStore
            }
        } else {
            let stage = dest.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
            try fm.createDirectory(at: stage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            defer { try? fm.removeItem(at: stage) }
            for (name, data) in reports { try data.write(to: stage.appendingPathComponent(name), options: .atomic) }
            try fm.moveItem(at: stage, to: dest)
        }
        if let updatedExisting { try store.save(updatedExisting) }
        else if existing == nil { try store.save(record) }
        if receipt.started >= (comparison?.started ?? .distantPast) {
            try JSONEncoder().encode(receipt).write(to: publication, options: .atomic)
            comparison = receipt
            refresh()
            if try updateImportedScope(in: store) { return true }
        }
        return existing == nil || updatedExisting != nil
    }

    @discardableResult
    func updateImportedScope(in store: BenchmarkStore) throws -> Bool {
        guard let comparison, comparison.imported == true, comparisonReady,
              var record = store.runs.first(where: { $0.id == comparison.id && $0.network == comparison.network }) else { return false }
        var changed = false
        for index in record.rows.indices where !comparison.hosts.contains(record.rows[index].host) && record.rows[index].outcome == .skipped {
            record.rows[index].outcome = .notRun
            record.rows[index].detail = "이번 검사 범위 밖"
            changed = true
        }
        if changed { try store.save(record) }
        return changed
    }

    private func receipt(for request: Request) -> URL {
        fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CoreaVPN/LocalQuickSearch/" + request.id.uuidString, isDirectory: true)
    }

    @discardableResult
    func start(hosts: [String], network: BenchmarkNetwork, measurement: LocalMeasurement) -> Bool {
        begin(.quick, hosts: hosts, network: network, measurement: measurement)
    }

    @discardableResult
    func startAll(hosts: [String], network: BenchmarkNetwork) -> Bool {
        begin(.all, hosts: hosts, network: network)
    }

    @discardableResult
    func select(host: String, network: BenchmarkNetwork, store: BenchmarkStore) throws -> Bool {
        refresh()
        guard comparisonReady, let comparison, comparison.network == network,
              comparison.hosts.contains(host), comparisonRows.contains(where: {
                  $0.host == host && ![.skipped, .notRun, .stopped].contains($0.outcome)
              }),
              !running, !retryNeeded else { return false }
        // Save the recovered report before replacing its active launcher request.
        if request?.kind == .all { _ = try importCompleted(into: store) }
        guard store.runs.contains(where: { $0.id == comparison.id && $0.phase == .completed }) else { return false }
        return begin(.select, hosts: [host], network: network, comparisonID: comparison.id)
    }

    private func begin(_ operation: Operation, hosts: [String], network: BenchmarkNetwork,
                       measurement: LocalMeasurement? = nil, comparisonID: UUID? = nil) -> Bool {
        refresh()
        guard !running, !retryNeeded, !pilotLockHeld() else {
            status = "먼저 진행 중인 검사 또는 복구를 마쳐 주세요."
            return false
        }
        guard available, let runner, let ui = uiHelper, let map = calibration else {
            status = "이 Mac의 검사 도구와 FlClash 좌표 설정을 확인해 주세요."
            return false
        }
        let known = Set(CoreaServer.catalog.map(\.host))
        guard !hosts.isEmpty, Set(hosts).count == hosts.count, hosts.allSatisfy(known.contains),
              ["ethernet", "wifi"].contains(network.transport), !network.interface.isEmpty else {
            status = "사용할 수 있는 서버와 현재 물리 회선을 확인해 주세요."
            return false
        }
        let leo = "leo.coreavpn.net"
        let ordered = operation == .quick && hosts.contains(leo) ? [leo] + hosts.filter { $0 != leo } : hosts
        let next = Request(id: UUID(), hosts: ordered, network: network, started: Date(),
                           measurement: measurement, operation: operation, comparisonID: comparisonID)
        guard let run = directory(for: next) else { return false }
        do {
            let data = try JSONEncoder().encode(next)
            var arguments = ["-B", runner.path, "--ui", ui.path, "--fl-map", map.path, "--log-dir", run.path,
                             "--expected-device", network.interface, "--operation", operation.rawValue]
            arguments += expectedPrefix(network)
            if let measurement { arguments += measurement.arguments }
            arguments.append("--hosts")
            arguments += ordered
            arguments.append("--run")
            try launch(next, arguments: arguments)
            request = next
            defaults.set(data, forKey: requestKey)
            if operation == .all {
                comparison = next
                defaults.set(data, forKey: comparisonKey)
            }
            refresh()
            return true
        } catch { status = error.localizedDescription; return false }
    }

    private func expectedPrefix(_ network: BenchmarkNetwork) -> [String] {
        guard let cidr = network.fingerprint, !cidr.contains(":"), cidr.contains("/") else { return [] }
        return ["--expected-prefix", cidr]
    }

    private func launch(_ request: Request, arguments: [String]) throws {
        let base = receipt(for: request)
        try fm.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let id = UUID().uuidString
        let attempt = base.appendingPathComponent(id, isDirectory: true)
        let argv = (["/usr/bin/python3"] + arguments).map(LocalTerminal.quoted).joined(separator: " ")
        let command = """
        \(argv) 2>&1 | /usr/bin/tee launcher.log
        exit "${PIPESTATUS[0]}"
        """
        try Data(id.utf8).write(to: base.appendingPathComponent("attempt"), options: .atomic)
        // Terminal is the existing authorized owner of the profile UI helper.
        // Every retry receives its own receipt, including separate pid and exit markers.
        try LocalTerminal.launch(folder: attempt, name: "CoreaVPN-Quick.command", command: command) { [weak self] error in
            Task { @MainActor in
                guard let self, self.request?.id == request.id else { return }
                self.refresh()
                if error != nil { self.status = "Terminal에서 검색 도구를 열지 못했습니다." }
            }
        }
    }

    private func currentAttempt(_ request: Request) -> URL? {
        let base = receipt(for: request)
        guard let data = LocalTerminal.read(base.appendingPathComponent("attempt"), limit: 64),
              let id = UUID(uuidString: String(decoding: data, as: UTF8.self)) else { return nil }
        return base.appendingPathComponent(id.uuidString, isDirectory: true)
    }

    private func launcherAlive(_ request: Request, attempt: URL?) -> Bool {
        // Existing runs from the initial direct-launch version have a receipt-level pid.
        let marker = attempt?.appendingPathComponent("shell-pid") ?? receipt(for: request).appendingPathComponent("pid")
        if let attempt, fm.fileExists(atPath: attempt.appendingPathComponent("exit-code").path) { return false }
        if let data = LocalTerminal.read(marker, limit: 32),
           let pid = Int32(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) {
            return pid > 1 && kill(pid, 0) == 0
        }
        guard let attempt, let created = try? attempt.resourceValues(forKeys: [.creationDateKey]).creationDate else { return false }
        return Date().timeIntervalSince(created) < 60
    }

    func release() {
        guard let request, let run = directory(for: request), let runner else { return }
        do {
            if retryNeeded {
                guard !launcherAlive(request, attempt: currentAttempt(request)), !pilotLockHeld() else { return }
                try launch(request, arguments: ["-B", runner.path, "--recover", "--log-dir", run.path])
                refresh()
                status = "저장된 원래 프로필과 FlClash 설정을 다시 복구하고 있습니다."
            } else {
                guard canRelease else { return }
                // The sibling marker covers the interval before Python creates the run directory.
                let marker = releaseMarker(for: run)
                if !fm.fileExists(atPath: marker.path) {
                    let intent = phase == "retained" ? "" : "stop-search"
                    try Data(intent.utf8).write(to: marker, options: .withoutOverwriting)
                }
                refresh()
            }
            poll()
        } catch { status = error.localizedDescription }
    }

    private func releaseMarker(for run: URL) -> URL {
        run.deletingLastPathComponent().appendingPathComponent(run.lastPathComponent + ".release")
    }

    func refresh() {
        guard let request, let run = directory(for: request) else {
            refreshComparison(currentRun: nil, currentState: nil, currentEvents: [])
            return
        }
        latestDirectory = run
        let decoder = JSONDecoder()
        let state = LocalTerminal.read(run.appendingPathComponent("quick-state.json"), limit: 32768)
            .flatMap { try? decoder.decode(State.self, from: $0) }
        let events = lines("events.jsonl", in: run).compactMap(Event.parse)
        results = request.kind == .quick ? attempts(in: run, request: request, events: events) : []
        refreshComparison(currentRun: run, currentState: state, currentEvents: events)
        selectionFailure = nil
        if request.kind == .select, ["failed", "no-match"].contains(state?.phase ?? "") {
            selectionFailure = events.last(where: { $0.stage == "server-failed" && $0.server == request.hosts.first })?.error ??
                state?.reason ?? "선택한 서버에 연결할 수 없습니다."
        }
        lastMeasurement = request.measurement ?? (results.contains { $0.httpsSample != nil } ? .https :
                                                   results.contains { $0.sample != nil } ? .icmp : nil)
        let recovery = LocalTerminal.read(run.appendingPathComponent("recovered.json"), limit: 16384)
            .flatMap { try? decoder.decode(Recovery.self, from: $0) }
        let phase = state?.phase ?? ""
        self.phase = phase
        recoveryVerified = state?.recovered == true && recovery?.ok == true && recovery?.errors.isEmpty == true
        let lockHeld = pilotLockHeld()
        let attempt = currentAttempt(request)
        let alive = launcherAlive(request, attempt: attempt)
        let terminal = ["released", "no-match", "completed", "failed"].contains(phase)
        let touched = fm.fileExists(atPath: run.appendingPathComponent("engine-stop-sent").path)
        let protected = lockHeld && !terminal && (!phase.isEmpty || alive)
        running = protected || alive
        retryNeeded = !running && touched && !recoveryVerified
        let marker = releaseMarker(for: run)
        let requested = fm.fileExists(atPath: marker.path) || fm.fileExists(atPath: run.appendingPathComponent("release").path)
        stoppedDuringSearch = requested && LocalTerminal.read(marker, limit: 32) == Data("stop-search".utf8)
        canRelease = retryNeeded || (running && phase != "recovering" && !terminal && !requested)
        let selected = request.kind == .select ? selectedConnection(in: run, request: request, host: state?.host) :
            verifiedQuickWinner(request: request, directory: run)

        retainedHost = phase == "retained" && protected && !stoppedDuringSearch && selected == state?.host ? selected : nil
        activeHost = phase == "searching" ? (state?.host ?? events.last { $0.stage == "server-start" }?.server) : retainedHost
        switch phase {
        case _ where requested && running && !terminal && phase != "recovering":
            status = stoppedDuringSearch ? "검사 중지를 요청했습니다." : "연결 해제를 요청했습니다."
        case "retained" where protected: status = retainedHost.map { "\($0) 연결 유지 중" } ?? "유지된 터널의 측정 기록을 확인하고 있습니다."
        case "searching" where running && request.kind == .select:
            status = "\(request.hosts.first ?? "")에 연결하고 있습니다."
        case "searching" where running && request.kind == .all:
            let completedHosts = Set(events.filter { $0.stage == "server-finished" || $0.stage == "server-failed" }.compactMap(\.server))
            let step = events.last(where: { $0.server == activeHost && $0.stage == "probe-start" })?.step
            status = "전체 검사 \(completedHosts.count)/\(request.hosts.count) · \(activeHost ?? "준비") · " +
                (step == "https" ? "FAST" : step == "icmp" ? "ping" : "연결")
        case "searching" where running:
            status = activeHost.map { "\($0) 연결 · \(lastMeasurement?.title ?? "속도") 측정 중" }
                ?? "후보 서버를 검사하고 있습니다."
        case "recovering" where running: status = "VPN을 해제하고 FlClash를 복구하고 있습니다."
        case "released" where !touched && state?.recovered == true: status = "네트워크 전환 전에 검사를 취소했습니다."
        case "released" where recoveryVerified && stoppedDuringSearch: status = "검사를 중지하고 FlClash를 복구했습니다."
        case "released": status = recoveryVerified ? "VPN 해제와 FlClash 복구를 확인했습니다." : "종료 기록과 FlClash 복구 상태를 확인해 주세요."
        case "completed":
            status = comparisonReady ? "전체 검사를 마치고 FlClash를 복구했습니다. 표에서 연결할 서버를 선택하세요." : "전체 검사 복구 결과를 확인하고 있습니다."
        case "no-match": status = recoveryVerified ? "조건을 통과한 서버가 없어 FlClash를 복구했습니다." : "적격 서버 없음 · 복구 결과를 확인해 주세요."
        case "failed": status = (state?.reason ?? "검사가 중단됐습니다.") + (recoveryVerified ? " · FlClash 복구 확인" : "")
        default: status = running ? "CoreaVPN_TEST와 FlClash의 현재 상태를 확인하고 있습니다." : "검사가 중단됐습니다. 실행 기록을 확인해 주세요."
        }
        if phase.isEmpty, !running, let attempt,
           let console = LocalTerminal.read(attempt.appendingPathComponent("launcher.log"), limit: 16_384),
           let diagnostic = String(decoding: console, as: UTF8.self).split(whereSeparator: \.isNewline).last {
            status = "검색 실행 중단 · " + diagnostic.prefix(512)
        }
        if retryNeeded { status += " · FlClash 복구 재시도 필요" }
        if running { poll() }
    }

    private func lines(_ name: String, in directory: URL) -> [Data] {
        guard let data = LocalTerminal.read(directory.appendingPathComponent(name), limit: 512 * 1024) else { return [] }
        return data.split(separator: 10).map { Data($0) }
    }

    private func selectedConnection(in run: URL, request: Request, host: String?) -> String? {
        guard request.kind == .select, request.hosts.count == 1, let host, request.hosts.first == host,
              let bytes = LocalTerminal.read(run.appendingPathComponent("winner.json"), limit: 32_768),
              let winner = try? JSONDecoder().decode(Connection.self, from: bytes), winner.matches(host) else { return nil }
        return host
    }

    private func refreshComparison(currentRun: URL?, currentState: State?, currentEvents: [Event]) {
        guard let comparison, comparison.kind == .all, let dir = directory(for: comparison) else { return }
        let state: State?
        let events: [Event]
        if dir == currentRun {
            state = currentState
            events = currentEvents
        } else {
            state = LocalTerminal.read(dir.appendingPathComponent("quick-state.json"), limit: 32_768)
                .flatMap { try? JSONDecoder().decode(State.self, from: $0) }
            events = lines("events.jsonl", in: dir).compactMap(Event.parse)
        }
        let recovered = LocalTerminal.read(dir.appendingPathComponent("recovered.json"), limit: 16_384)
            .flatMap { try? JSONDecoder().decode(Recovery.self, from: $0) }
        let plan = LocalTerminal.read(dir.appendingPathComponent("plan.json"), limit: 128 * 1024)
            .flatMap { try? JSONDecoder().decode(Plan.self, from: $0) }
        comparisonReady = Self.ready(comparison, state, plan, recovered, events)
        comparisonRows = pairedRows(request: comparison, events: events, stopped: state?.phase == "released")
    }

    private static func ready(_ comparison: Request, _ state: State?, _ plan: Plan?, _ recovered: Recovery?, _ events: [Event]) -> Bool {
        state?.phase == "completed" && state?.recovered == true && recovered?.ok == true &&
            recovered?.errors.isEmpty == true && plan?.operation == .all && plan?.device == comparison.network.interface &&
            events.last(where: { $0.stage == "verify-stable-flclash-proxy" })?.ok == true
    }

    /// A unique run directory, one connection per server, and verified completion events
    /// bind the two samples. Raw probe output can precede the worker's final route check.
    private func pairedRows(request: Request, events: [Event], stopped: Bool) -> [BenchmarkAttempt] {
        var rows = [String: BenchmarkAttempt]()
        var tunnels = [String: String]()
        var finished = Set<String>()
        for server in CoreaServer.catalog {
            let eligible = request.hosts.contains(server.host)
            let scoped = request.imported == true
            rows[server.host] = BenchmarkAttempt(host: server.host, time: request.started,
                                                 outcome: eligible || scoped ? .notRun : .skipped,
                                                 detail: eligible ? nil : scoped ? "이번 검사 범위 밖" : "계정 또는 선택한 그룹에서 제외")
        }
        for event in events {
            guard let host = event.server, request.hosts.contains(host), var row = rows[host] else { continue }
            switch event.stage {
            case "server-start":
                // If a runner ever retries a connection, never pair with its predecessor.
                row = BenchmarkAttempt(host: host, time: request.started, outcome: .notRun, detail: "연결 중")
                tunnels.removeValue(forKey: host)
                finished.remove(host)
            case "server-connected":
                tunnels[host] = event.tunnel
                row.detail = "IKEv2 연결 확인"
            case "probe-start":
                row.detail = event.step == "icmp" ? "ping 측정 중" : "FAST 측정 중"
            case "ping-complete", "https-idle-complete", "https-download-complete", "https-complete":
                let method: LocalMeasurement = event.stage == "ping-complete" ? .icmp : .https
                guard let bytes = event.evidence, let result = try? method.decode(bytes, host: host),
                      result.tunnel == tunnels[host] else { continue }
                let first = row.sample == nil && row.httpsSample == nil
                if first {
                    // Use probe start instead of app launch for the per-server history row.
                    row = BenchmarkAttempt(host: host, time: result.started, outcome: row.outcome,
                                           detail: row.detail, pingError: row.pingError, httpsError: row.httpsError)
                }
                if method == .icmp { row.sample = result.sample }
                else {
                    row.httpsSample = result.httpsSample
                    if event.stage == "https-complete", let sample = result.httpsSample {
                        row.httpsError = Self.httpsIssue(sample, report: bytes)
                    } else if event.stage == "https-download-complete", result.httpsSample?.downloadMbps == nil {
                        row.httpsError = Self.directionIssue("download", report: bytes)
                    }
                }
                row.outcome = pairedOutcome(row)
            case "probe-failed":
                let reason = event.error ?? "측정 실패"
                if event.step == "icmp" { row.pingError = reason }
                else if event.step == "https" { row.httpsError = reason }
                row.outcome = pairedOutcome(row)
            case "server-failed":
                row.detail = [event.step, event.error].compactMap { $0 }.joined(separator: " · ")
                row.outcome = row.sample != nil || row.httpsSample != nil ? .partial : .failed
                finished.insert(host)
            case "server-finished":
                if row.outcome != .failed || !finished.contains(host) {
                    row.outcome = pairedOutcome(row)
                    row.detail = tunnels[host]
                }
                finished.insert(host)
            default:
                continue
            }
            rows[host] = row
        }
        if stopped {
            for host in request.hosts where !finished.contains(host) {
                guard var row = rows[host], row.detail != nil else { continue }
                row.outcome = row.sample != nil || row.httpsSample != nil ? .partial : .stopped
                if row.sample == nil && row.pingError == nil { row.pingError = "중지" }
                if row.httpsSample?.uploadMbps == nil && row.httpsError == nil { row.httpsError = "중지" }
                row.detail = "검사 중지"
                rows[host] = row
            }
        }
        return CoreaServer.catalog.compactMap { rows[$0.host] }
    }

    private static func directionIssue(_ direction: String, report: Data) -> String {
        let raw = try? JSONSerialization.jsonObject(with: report) as? [String: Any]
        let detail = (raw?["errors"] as? [String: String])?[direction]
        let label = direction == "download" ? "다운로드" : "업로드"
        switch detail {
        case nil, "No confirmed HTTPS transfer":
            return label + " 전송량 미확인"
        case "HTTPS " + direction + ": No warmed TLS connection":
            return label + " 측정용 TLS 연결 준비 실패"
        case "HTTPS download: No response payload bytes received":
            return "다운로드 응답 데이터 미수신"
        case "HTTPS upload: No upload block acknowledged by the server":
            return "업로드 데이터 수신 확인 실패"
        default:
            return label + " · " + (detail ?? "")
        }
    }

    private static func httpsIssue(_ sample: HTTPSBenchmarkSample, report: Data) -> String? {
        var reasons = [String]()
        if sample.averageMS == nil {
            reasons.append(sample.sent == 0 ? "평상시 지연 HTTP 요청 미송신" : "평상시 지연 응답 없음")
        }
        if sample.downloadMbps == nil { reasons.append(directionIssue("download", report: report)) }
        else if sample.downloadLoadedMS == nil { reasons.append("다운로드 중 지연 미측정") }
        if sample.uploadMbps == nil { reasons.append(directionIssue("upload", report: report)) }
        else if sample.uploadLoadedMS == nil { reasons.append("업로드 중 지연 미측정") }
        return reasons.isEmpty ? nil : reasons.joined(separator: " · ")
    }

    private func pairedOutcome(_ row: BenchmarkAttempt) -> AttemptOutcome {
        if let ping = row.sample, let speed = row.httpsSample, ping.received > 0,
           speed.downloadMbps != nil, speed.uploadMbps != nil,
           row.pingError == nil && row.httpsError == nil { return .measured }
        if row.sample != nil || row.httpsSample != nil { return .partial }
        return .failed
    }

    private func attempts(in directory: URL, request: Request, events: [Event]) -> [BenchmarkAttempt] {
        var rows: [String: BenchmarkAttempt] = [:]
        let methods = request.measurement.map { [$0] } ?? [.icmp, .https]
        let hosts = request.hosts
        for method in methods {
            for data in lines(method.resultsFilename, in: directory) {
                guard let host = try? JSONDecoder().decode(Server.self, from: data).server, hosts.contains(host),
                      let result = try? method.decode(data, host: host) else { continue }
                let issue = result.httpsSample.flatMap { Self.httpsIssue($0, report: data) }
                let outcome: AttemptOutcome
                if let speed = result.httpsSample, speed.downloadMbps != nil || speed.uploadMbps != nil || speed.received > 0 {
                    outcome = issue == nil ? .measured : .partial
                } else { outcome = result.received == 0 ? .noReply : .measured }
                rows[host] = BenchmarkAttempt(host: host, time: result.started, outcome: outcome, sample: result.sample,
                                              detail: result.tunnel, httpsSample: result.httpsSample, httpsError: issue)
            }
        }
        let date = ISO8601DateFormatter()
        date.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        for event in events where event.stage == "server-failed" {
            guard let host = event.server, hosts.contains(host), rows[host] == nil,
                  let time = event.time.flatMap(date.date) else { continue }
            rows[host] = BenchmarkAttempt(host: host, time: time, outcome: .failed, detail: event.step)
        }
        return hosts.compactMap { rows[$0] }
    }

    @discardableResult
    func importCompleted(into store: BenchmarkStore) throws -> Bool {
        guard let request, let run = latestDirectory,
              !request.network.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let data = LocalTerminal.read(run.appendingPathComponent("plan.json"), limit: 128 * 1024),
              let plan = try? JSONDecoder().decode(Plan.self, from: data),
              plan.device == request.network.interface, plan.operation == request.kind || (plan.operation == nil && request.kind == .quick) else { return false }
        if request.kind == .select {
            guard !stoppedDuringSearch, let id = request.comparisonID, id == comparison?.id,
                  let host = request.hosts.first,
                  var record = store.runs.first(where: { $0.id == id && $0.phase == .completed && $0.network == request.network }),
                  record.order.contains(host), let row = record.rows.firstIndex(where: { $0.host == host }) else { return false }
            if let error = selectionFailure {
                guard recoveryVerified, record.rows[row].selectionError != error else { return false }
                record.rows[row].selectionError = error
            } else {
                guard selectedConnection(in: run, request: request, host: host) == host,
                      retainedHost == host || recoveryVerified,
                      record.selectedHost != host || record.rows[row].selectionError != nil else { return false }
                record.selectedHost = host
                record.rows[row].selectionError = nil
            }
            try store.save(record)
            return true
        }
        if request.kind == .all {
            guard request.id == comparison?.id, recoveryVerified, !comparisonRows.isEmpty, phase != "completed" || comparisonReady,
                  ["completed", "released", "failed"].contains(phase) else { return false }
            var record = BenchmarkRun(id: request.id, network: request.network, mode: .all, started: request.started,
                                      order: request.hosts, baseline: ScanBaseline(host: nil, connected: false, onDemand: false))
            record.paired = true
            record.rows = comparisonRows
            record.phase = phase == "completed" ? .completed : phase == "released" ? .cancelled : .failed
            record.finished = try run.appendingPathComponent("quick-state.json")
                .resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            record.message = status
            if let existing = store.runs.first(where: { $0.id == request.id }) {
                guard existing.network == record.network, existing.mode == .all, existing.order == record.order else {
                    throw BenchmarkError.corruptStore
                }
                for index in record.rows.indices {
                    record.rows[index].selectionError = existing.rows.first(where: { $0.host == record.rows[index].host })?.selectionError
                }
                if existing.phase == record.phase && existing.rows == record.rows { return false }
                record.selectedHost = existing.selectedHost
            }
            try store.save(record)
            return true
        }
        guard !results.isEmpty else { return false }
        let existing = store.runs.first { $0.id == request.id }
        let isHeld = phase == "retained" && retainedHost != nil
        let lostConnection = phase == "failed" && existing?.phase == .retained
        guard isHeld || recoveryVerified || lostConnection else { return false }
        let mode: ScanMode = request.operation != nil && request.measurement == .https ? .fastQuick : .quick
        var record = BenchmarkRun(id: request.id, network: request.network, mode: mode,
                                  started: request.started, order: request.hosts,
                                  baseline: ScanBaseline(host: nil, connected: false, onDemand: false))
        record.rows = results
        if !stoppedDuringSearch { record.selectedHost = verifiedQuickWinner(request: request, directory: run) }
        if isHeld {
            // Retention requires both the live supervisor and its verified tunnel sample.
            guard record.selectedHost == retainedHost, existing?.finished == nil else { return false }
            record.phase = .retained
            record.message = results.contains(where: { $0.httpsSample != nil })
                ? "FAST 다운로드 속도를 확인해 연결을 유지합니다."
                : "ping 20회에서 손실률 10% 이하, 평균 지연 100ms 이하를 확인해 연결을 유지합니다."
        } else {
            record.finished = try run.appendingPathComponent("quick-state.json")
                .resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
            if phase == "released" && stoppedDuringSearch { record.phase = .cancelled }
            else { record.phase = phase == "failed" ? .failed : .completed }
            record.message = status
        }
        if let existing {
            let upgraded = existing.rows.map { stored -> BenchmarkAttempt in
                var row = stored
                let source = record.rows.first(where: { $0.host == stored.host })
                row.httpsSample = stored.httpsSample?.restoringTimes(from: source?.httpsSample)
                if row.httpsSample != nil, row.httpsSample == source?.httpsSample, let source {
                    row.outcome = source.outcome
                    row.httpsError = source.httpsError
                }
                return row
            }
            guard existing.network == record.network, existing.mode == record.mode, existing.started == record.started,
                  existing.order == record.order, upgraded == record.rows,
                  existing.selectedHost == record.selectedHost else { throw BenchmarkError.corruptStore }
            if existing.rows == record.rows && existing.phase == record.phase && existing.finished == record.finished && existing.message == record.message {
                return false
            }
        }
        try store.save(record)
        return true
    }

    private func verifiedQuickWinner(request: Request, directory: URL) -> String? {
        guard request.kind == .quick,
              let data = LocalTerminal.read(directory.appendingPathComponent("winner.json"), limit: 32_768),
              let host = try? JSONDecoder().decode(Server.self, from: data).server, request.hosts.contains(host),
              let verified = winnerEvidence(data, host: host, measurement: request.measurement),
              results.contains(where: { $0.host == host && $0.sample == verified.sample &&
                  $0.httpsSample == verified.httpsSample && $0.detail == verified.tunnel }) else { return nil }
        if request.operation == nil, let speed = verified.httpsSample {
            // Historical HTTPS quick requests used idle RTT and both transfer directions.
            guard speed.received >= 18, (speed.averageMS ?? .infinity) <= 100,
                  (speed.downloadBytes ?? 0) > 0, (speed.uploadBytes ?? 0) > 0 else { return nil }
            return phase != "retained" || speed.qualifies ? host : nil
        }
        return verified.qualifies ? host : nil
    }

    private func winnerEvidence(_ data: Data, host: String, measurement: LocalMeasurement?) -> LocalProbeResult? {
        if let measurement { return try? measurement.decode(data, host: host) }
        return (try? LocalMeasurement.https.decode(data, host: host)) ??
               (try? LocalMeasurement.icmp.decode(data, host: host))
    }

    private func poll() {
        guard monitor == nil else { return }
        monitor = Task { [weak self] in
            while self?.running == true {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard !Task.isCancelled else { break }
                self?.refresh()
            }
            self?.monitor = nil
        }
    }
    deinit { monitor?.cancel() }
}
#endif
