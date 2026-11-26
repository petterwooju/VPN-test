import Foundation

@MainActor
private final class TrialDriver: BenchmarkDriver {
    var state = ScanBaseline(host: "lynx.coreavpn.net", connected: true, onDemand: true)
    var visits: [String] = []
    var chosen: [String] = []
    var failHosts: Set<String> = []
    var results: [String: PingSample] = [:]
    var delay: UInt64 = 0
    var speeds: [String: HTTPSBenchmarkSample] = [:]
    var failAfterSpeedCheckpoint = false
    var snapshots = 0
    var onRestore: (() -> Void)?

    func snapshot() async throws -> ScanBaseline {
        snapshots += 1
        return state
    }
    func select(host: String) async throws {
        chosen.append(host)
        if failHosts.contains(host) { throw BenchmarkError.invalidSample }
        state = ScanBaseline(host: host, connected: true, onDemand: true)
    }
    func restore(_ baseline: ScanBaseline) async throws {
        try Task.checkCancellation()
        onRestore?()
        state = baseline
    }
    func disconnect() async throws { state.connected = false; state.onDemand = false }
    func begin(host: String) async throws {
        visits.append(host)
        state = ScanBaseline(host: host, connected: true, onDemand: false)
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        if failHosts.contains(host) { throw BenchmarkError.invalidSample }
    }
    func speed(host: String, checkpoint: @escaping (HTTPSBenchmarkSample) throws -> Void) async throws -> HTTPSBenchmarkSample {
        guard let sample = speeds[host] else { throw BenchmarkError.invalidSample }
        try checkpoint(sample)
        if failAfterSpeedCheckpoint { throw BenchmarkError.invalidSample }
        return sample
    }
    func ping(host: String) async throws -> PingSample {
        guard let sample = results[host] else { throw BenchmarkError.invalidSample }
        return sample
    }
}

@main
struct BenchmarkChecks {
    @MainActor
    private static func localPumaImport(in root: URL) throws {
        let records = root.appendingPathComponent("local-puma.json")
        let store = try BenchmarkStore(fileURL: records)
        let directory = root.appendingPathComponent("20261125-164354-puma-pilot")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        func write(_ name: String, _ text: String) throws {
            try Data(text.utf8).write(to: directory.appendingPathComponent(name))
        }
        let network = BenchmarkNetwork(deviceID: "this-mac", label: "Office", interface: "en6", transport: "ethernet", fingerprint: "office")
        let other = BenchmarkNetwork(deviceID: "this-mac", label: "Home", interface: "en6", transport: "ethernet", fingerprint: "home")
        let wifi = BenchmarkNetwork(deviceID: "this-mac", label: "Wi-Fi", interface: "en0", transport: "wifi")
        let result = #"{"started":"2026-11-25T16:44:25+08:00","ended":"2026-11-25T16:44:46+08:00","server":"puma.coreavpn.net","target":"168.126.63.1","tunnel":"ipsec0","valid":true,"ping":{"sent":20,"received":18,"loss_pct":10,"average_ms":55.91,"minimum_ms":53.889,"maximum_ms":59.102}}"#
        try write("finished", "")
        try write("recovered.json", #"{"ok":true,"errors":[]}"#)
        try write("events.jsonl", #"{"stage":"worker-finished","ok":true}"#)
        try write("plan.json", #"{"device":"en6"}"#)
        try write("ping-results.jsonl", result)
        func expectRejection(_ selected: BenchmarkNetwork) {
            do {
                _ = try store.importLocalPuma(from: directory, into: selected)
                preconditionFailure("Invalid import was accepted")
            } catch { }
        }
        expectRejection(wifi)
        expectRejection(.beijingReference)
        let inserted = try store.importLocalPuma(from: directory, into: network)
        let reopened = try BenchmarkStore(fileURL: records)
        let repeated = try reopened.importLocalPuma(from: directory, into: network)
        precondition(inserted && !repeated && reopened.runs.count == 1)
        let rank = reopened.rankings(for: network)[0]
        precondition(rank.received == 18 && rank.sent == 20 && abs((rank.meanMS ?? 0) - 55.91) < 0.00001)
        expectRejection(other)
        try write("ping-results.jsonl", result.replacingOccurrences(of: "55.91", with: "56.0"))
        expectRejection(network)
        try write("ping-results.jsonl", result.replacingOccurrences(of: "ipsec0", with: "utun4"))
        expectRejection(network)
        try write("ping-results.jsonl", result.replacingOccurrences(of: #""loss_pct":10"#, with: #""loss_pct":0"#))
        expectRejection(network)
        try write("ping-results.jsonl", result)
        try write("recovered.json", #"{"ok":false,"errors":["proxy"]}"#)
        expectRejection(network)
        try write("recovered.json", #"{"ok":true,"errors":[]}"#)
        try write("events.jsonl", #"{"stage":"worker-finished","ok":false}"#)
        expectRejection(network)
        precondition(store.runs.count == 1)

        // A separate Wi-Fi pilot with no replies remains visible as 100% loss.
        let wifiRun = root.appendingPathComponent(UUID().uuidString + "-puma-pilot")
        try FileManager.default.moveItem(at: directory, to: wifiRun)
        let loss = result.replacingOccurrences(of: "16:44:", with: "16:48:")
            .replacingOccurrences(of: #""received":18,"loss_pct":10,"average_ms":55.91,"minimum_ms":53.889,"maximum_ms":59.102"#,
                                  with: #""received":0,"loss_pct":100,"average_ms":null,"minimum_ms":null,"maximum_ms":null"#)
        try Data(loss.utf8).write(to: wifiRun.appendingPathComponent("ping-results.jsonl"))
        try Data(#"{"device":"en0"}"#.utf8).write(to: wifiRun.appendingPathComponent("plan.json"))
        try Data(#"{"stage":"worker-finished","ok":true}"#.utf8).write(to: wifiRun.appendingPathComponent("events.jsonl"))
        let added = try store.importLocalPuma(from: wifiRun, into: wifi)
        precondition(added && store.runs.last?.rows.first?.outcome == .noReply && store.rankings(for: wifi).first?.lossPercent == 100)

        let speedRun = root.appendingPathComponent(UUID().uuidString + "-puma-pilot")
        try FileManager.default.copyItem(at: wifiRun, to: speedRun)
        try FileManager.default.removeItem(at: speedRun.appendingPathComponent("ping-results.jsonl"))
        let speed = #"{"measurement":"https","valid":true,"server":"puma.coreavpn.net","target":"speed.cloudflare.com","peer_ipv4":"104.16.132.229","tunnel":"ipsec2","started":"2026-11-26T06:00:00Z","ended":"2026-11-26T06:00:20Z","speed":{"sent":20,"received":19,"average_ms":95,"download_mbps":100,"upload_mbps":20,"download_loaded_ms":130,"download_bytes":16000000,"upload_bytes":4000000}}"#
        try Data(speed.utf8).write(to: speedRun.appendingPathComponent("https-results.jsonl"))
        let addedSpeed = try store.importLocalPuma(from: speedRun, into: wifi)
        precondition(addedSpeed && store.runs.last?.rows.first?.httpsSample?.qualifies == false)
        precondition(store.runs.last?.rows.first?.sample == nil)
        precondition(store.rankings(for: wifi).first?.runCount == 1 && store.httpsRankings(for: wifi).first?.downloadMbps == 100)
        // The worker can exit before an independent watchdog verifies the proxy for 30 seconds.
        try FileManager.default.removeItem(at: speedRun.appendingPathComponent("finished"))
        let retryEvents = [
            "{\"stage\":\"https-complete\",\"result\":" + speed + "}",
            #"{"stage":"recovery-complete","ok":false}"#,
            #"{"stage":"worker-finished","ok":false}"#,
            #"{"stage":"system-proxy-stable","seconds":30}"#,
            #"{"stage":"verify-stable-flclash-proxy","ok":true}"#,
            #"{"stage":"recovery-complete","ok":true}"#
        ].joined(separator: "\n")
        let eventFile = speedRun.appendingPathComponent("events.jsonl")
        try Data(retryEvents.utf8).write(to: eventFile)
        let afterRetry = try LocalPumaMeasurement.load(from: speedRun)
        precondition(afterRetry.httpsSample?.downloadMbps == 100)
        try Data(retryEvents.replacingOccurrences(of: "speed.cloudflare.com", with: "example.org").utf8).write(to: eventFile)
        let mismatched = try? LocalPumaMeasurement.load(from: speedRun)
        precondition(mismatched == nil)
        try Data().write(to: speedRun.appendingPathComponent("finished"))
        try Data(#"{"stage":"worker-finished","ok":true}"#.utf8).write(to: eventFile)
        let planURL = speedRun.appendingPathComponent("plan.json")
        try Data(#"{"device":"en0","measurement":"icmp"}"#.utf8).write(to: planURL)
        let missingPing = try? LocalPumaMeasurement.readProbe(from: speedRun)
        precondition(missingPing == nil)
        try Data(loss.utf8).write(to: speedRun.appendingPathComponent("ping-results.jsonl"))
        let chosenPing = try LocalPumaMeasurement.load(from: speedRun)
        precondition(chosenPing.sample?.lossPercent == 100 && chosenPing.httpsSample == nil)
        try Data(#"{"device":"en0","measurement":"https"}"#.utf8).write(to: planURL)
        let chosenSpeed = try LocalPumaMeasurement.load(from: speedRun)
        precondition(chosenSpeed.httpsSample?.downloadMbps == 100 && chosenSpeed.sample == nil)
        let oldRunCount = store.runs.count
        let timed = speed.replacingOccurrences(of: #""download_bytes":16000000"#,
                                               with: #""download_seconds":1.28,"download_bytes":16000000"#)
        try Data(timed.utf8).write(to: speedRun.appendingPathComponent("https-results.jsonl"))
        let upgraded = try store.importLocalPuma(from: speedRun, into: wifi)
        let duplicate = try store.importLocalPuma(from: speedRun, into: wifi)
        precondition(upgraded && !duplicate && store.runs.count == oldRunCount)
        precondition(store.runs.last?.rows.first?.httpsSample?.qualifies == true)
    }

    @MainActor
    static func main() async throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: path) }
        try localPumaImport(in: path)
        let store = try BenchmarkStore(fileURL: path.appendingPathComponent("records.json"))
        let reference = BenchmarkNetwork.beijingReference
        let oldCSV = try String(contentsOfFile: CommandLine.arguments[1], encoding: .utf8)
        try store.importBeijingBaseline(csv: oldCSV)
        try store.importBeijingBaseline(csv: oldCSV)
        precondition(CoreaServer.catalog.filter(\.iPhoneSupported).count == 11)
        precondition(store.runs.count == 1 && store.runs[0].rows.count == 23)
        precondition(abs(store.rankings(for: reference)[0].meanMS! - 52.965) < 0.00001)
        precondition(store.runs[0].rows.filter { $0.sample?.qualifies == true }.count == 10)
        let network = BenchmarkNetwork(deviceID: "test", label: "Office", interface: "en0", transport: "wifi")
        precondition(store.rankings(for: network).isEmpty)
        let candidate = Array(CoreaServer.catalog.prefix(4))
        let hosts = candidate.map(\.host)
        let driver = TrialDriver()
        let baseline = driver.state
        driver.results[hosts[0]] = try PingSample(sent: 20, received: 19, meanMS: 25)
        driver.results[hosts[1]] = try PingSample(sent: 20, received: 20, meanMS: 100)
        driver.results[hosts[2]] = try PingSample(sent: 20, received: 0, meanMS: nil)
        let downloadable = HTTPSBenchmarkSample(sent: 20, received: 17, averageMS: 150, downloadMbps: 12,
                                     uploadMbps: nil, downloadLoadedMS: 220, uploadLoadedMS: nil,
                                     downloadBytes: 12_000_000, uploadBytes: nil, downloadSeconds: 8)
        func qualifies(_ rate: Double, seconds: Double?) -> Bool {
            HTTPSBenchmarkSample(sent: 20, received: 0, averageMS: nil, downloadMbps: rate, uploadMbps: nil,
                                 downloadLoadedMS: nil, uploadLoadedMS: nil, downloadBytes: 1_250_000,
                                 uploadBytes: nil, downloadSeconds: seconds).qualifies
        }
        precondition(qualifies(10, seconds: 1) && !qualifies(9.99, seconds: 10 / 9.99))
        precondition(!qualifies(10, seconds: nil) && !qualifies(10, seconds: 0) && !qualifies(10, seconds: 2))
        precondition(!qualifies(10, seconds: .nan) && !qualifies(10, seconds: .infinity))
        precondition(qualifies(10.000000001, seconds: 1) && !qualifies(10.0001, seconds: 1))
        driver.speeds[hosts[2]] = downloadable
        let scan = BenchmarkScanner(store: store, driver: driver)
        let all = try await scan.run(mode: .all, network: network, candidates: candidate)
        precondition(all.phase == .completed && all.selectedHost == nil && driver.state == baseline && driver.chosen.isEmpty)
        precondition(all.rows.count == 23 && driver.visits == hosts)
        let mixed = all.rows.first { $0.host == hosts[2] }!
        precondition(mixed.outcome == .partial && mixed.sample?.received == 0 && mixed.httpsSample?.downloadMbps == 12)
        let chosen = try await scan.connectSelected(host: hosts[0], runID: all.id, network: network, isNetworkCurrent: { true })
        precondition(chosen.selectedHost == hosts[0] && driver.chosen == [hosts[0]])
        let beforeFailedSelection = driver.state
        driver.failHosts = [hosts[1]]
        do {
            _ = try await scan.connectSelected(host: hosts[1], runID: all.id, network: network, isNetworkCurrent: { true })
            preconditionFailure("A failed selection was accepted")
        } catch { }
        precondition(driver.state == beforeFailedSelection && driver.chosen == [hosts[0], hosts[1]])
        let savedSelection = store.runs.first { $0.id == all.id }!
        precondition(savedSelection.selectedHost == hosts[0] && savedSelection.rows.first { $0.host == hosts[1] }?.selectionError != nil)
        let selectedCSV = store.csv(network: network)
        precondition(selectedCSV.contains("selected_server,download_seconds,upload_seconds,selection_error"))
        precondition(selectedCSV.contains(hosts[1] + " 연결 실패"))
        driver.failHosts = []
        precondition(all.rows.filter { $0.outcome == .failed }.count == 1)
        let quick = try await scan.run(mode: .quick, network: network, candidates: candidate)
        precondition(quick.selectedHost == hosts[1] && quick.rows.filter { $0.sample != nil }.count == 1)
        driver.results[hosts[1]] = try PingSample(sent: 20, received: 18, meanMS: 80)
        let fast = try await scan.run(mode: .quick, network: network, candidates: candidate)
        precondition(fast.phase == .completed && fast.selectedHost == hosts[1] && fast.rows.filter { $0.sample != nil }.count == 1)
        let aggregate = store.rankings(for: network).first { $0.host == hosts[1] }!
        precondition(aggregate.received == 58 && abs(aggregate.meanMS! - 5440.0/58) < 0.00001)
        precondition(abs(aggregate.lossPercent - 200.0/60) < 0.00001)
        driver.results[hosts[0]] = try PingSample(sent: 20, received: 19, meanMS: 100.001)
        driver.results[hosts[1]] = try PingSample(sent: 20, received: 17, meanMS: 80)
        let speedOnly = try await scan.run(mode: .fastQuick, network: network, candidates: candidate)
        precondition(speedOnly.selectedHost == hosts[2] && speedOnly.rows.allSatisfy { $0.sample == nil })
        driver.failAfterSpeedCheckpoint = true
        let invalidated = try await scan.run(mode: .fastQuick, network: network, candidates: [candidate[2]])
        let retainedCheckpoint = invalidated.rows.first { $0.host == hosts[2] }!
        precondition(invalidated.selectedHost == nil && retainedCheckpoint.httpsSample == downloadable)
        precondition(retainedCheckpoint.outcome == .partial && !retainedCheckpoint.qualifies)
        driver.failAfterSpeedCheckpoint = false
        let beforeNoMatch = driver.state
        let noMatch = try await scan.run(mode: .quick, network: network, candidates: candidate)
        precondition(noMatch.phase == .completed && noMatch.selectedHost == nil && driver.state == beforeNoMatch)
        let noReply = try await scan.run(mode: .all, network: network, candidates: [candidate[2]])
        precondition(noReply.selectedHost == nil && driver.state == beforeNoMatch)

        // Pause while a host is being measured and ensure it is retried exactly once on resume.
        driver.state = baseline
        driver.delay = 50_000_000
        let job = Task { try await scan.run(mode: .all, network: network, candidates: candidate) }
        while store.runs.last?.rows.contains(where: { $0.host == hosts[0] && $0.sample != nil }) != true {
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        try await scan.pause()
        let paused = try await job.value
        precondition(paused.phase == .paused && driver.state == baseline)
        let before = driver.visits.filter { $0 == hosts[0] }.count
        driver.delay = 0
        let resumed = try await scan.run(mode: .all, network: network, candidates: candidate, resumeID: paused.id)
        precondition(resumed.id == paused.id && resumed.phase == .completed)
        precondition(driver.visits.filter { $0 == hosts[0] }.count == before)

        // Stop after one completed server and during the second. A later background pause
        // must not make this run resumable or select a server from its partial results.
        for mode in [ScanMode.quick, .all] {
            let previousState = driver.state
            let visitCount = driver.visits.count
            let selectedCount = driver.chosen.count
            driver.delay = 50_000_000
            var backgroundPause: Task<Void, Error>?
            driver.onRestore = { backgroundPause = Task { try await scan.pause() } }
            let job = Task { try await scan.run(mode: mode, network: network, candidates: candidate) }
            while driver.visits.count < visitCount + 2 { try await Task.sleep(nanoseconds: 1_000_000) }
            try await scan.stopScan()
            try await backgroundPause?.value
            driver.onRestore = nil
            let stopped = try await job.value
            precondition(stopped.phase == .cancelled && !stopped.canResume && stopped.finished != nil)
            precondition(stopped.selectedHost == nil && stopped.activeHost == nil)
            precondition(stopped.rows.filter { [.partial, .measured, .failed, .noReply].contains($0.outcome) }.count == 1)
            precondition(stopped.rows.filter { $0.outcome == .stopped }.count == 1)
            precondition(driver.state == previousState && driver.visits.count == visitCount + 2)
            precondition(driver.chosen.count == selectedCount)
            let persisted = try BenchmarkStore(fileURL: path.appendingPathComponent("records.json"))
            precondition(persisted.runs.last?.id == stopped.id && persisted.runs.last?.phase == .cancelled)
        }

        driver.delay = 100_000_000
        let stopping = Task { try await scan.run(mode: .all, network: network, candidates: candidate) }
        while store.runs.last?.phase != .scanning { try await Task.sleep(nanoseconds: 1_000_000) }
        try await scan.disconnect()
        _ = try await stopping.value
        precondition(!driver.state.connected && !driver.state.onDemand && store.runs.last?.phase == .cancelled)

        var stale = BenchmarkRun(id: UUID(), network: network, mode: .all, started: Date(),
                                 order: hosts, baseline: baseline)
        stale.activeHost = hosts[1]
        try store.save(stale)
        let reopened = try BenchmarkStore(fileURL: path.appendingPathComponent("records.json"))
        precondition(reopened.runs.last?.recoveryNeeded == true)
        let recovery = BenchmarkScanner(store: reopened, driver: driver)
        try await recovery.recoverInterrupted()
        precondition(driver.state == baseline && reopened.runs.last?.recoveryNeeded == false)
        precondition(store.csv(network: network).contains(",\"IKEv2\",\"168.126.63.1\","))
        print("Benchmark checks passed (catalog, historical import, ranking, no-reply, pause/resume, disconnect, restart recovery, export)")
    }
}
