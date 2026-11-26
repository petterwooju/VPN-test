import Foundation

@main enum QuickBridgeChecks {
    @MainActor static func main() throws {
        // A persisted request belongs to the app even if the original UI quits
        // before the outside worker and watchdog finish.
        let id = UUID()
        let base = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("quick-bridge-" + id.uuidString)
        defer { try? FileManager.default.removeItem(at: base) }
        let support = base.appendingPathComponent("Library/Application Support", isDirectory: true)
        let runtime = support.appendingPathComponent("CoreaVPN/LocalRuntime", isDirectory: true)
        let documents = base.appendingPathComponent("Documents/CoreaVPN", isDirectory: true)
        precondition(LocalTerminal.runtimeDirectory(configuredPath: documents.path, applicationSupport: support) == nil)
        precondition(LocalTerminal.runtimeDirectory(configuredPath: runtime.path, applicationSupport: support) == runtime)

        let runs = runtime.appendingPathComponent("runs", isDirectory: true)
        let run = runs.appendingPathComponent(id.uuidString + "-quick-search")
        try FileManager.default.createDirectory(at: run, withIntermediateDirectories: true)
        let pumaName = id.uuidString + "-puma-pilot"
        let oldPuma = documents.appendingPathComponent("runs/" + pumaName, isDirectory: true)
        try FileManager.default.createDirectory(at: oldPuma, withIntermediateDirectories: true)
        let localPuma = runs.appendingPathComponent(pumaName, isDirectory: true)
        let pointer = runs.appendingPathComponent("latest-puma-run.txt")
        try Data((oldPuma.path + "\n").utf8).write(to: pointer)
        precondition(LocalTerminal.latestPumaDirectory(in: runs) == nil)
        try Data((localPuma.path + "\n").utf8).write(to: pointer)
        try FileManager.default.createSymbolicLink(at: localPuma, withDestinationURL: oldPuma)
        precondition(LocalTerminal.latestPumaDirectory(in: runs) == nil)
        try FileManager.default.removeItem(at: localPuma)
        try FileManager.default.copyItem(at: oldPuma, to: localPuma)
        precondition(LocalTerminal.latestPumaDirectory(in: runs) == localPuma)
        let suite = "net.petterwooju.coreavpn.check." + id.uuidString
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let host = "leo.coreavpn.net", other = "puma.coreavpn.net"
        let network = BenchmarkNetwork(deviceID: "local", label: "test", interface: "en6", transport: "ethernet")
        struct Request: Codable {
            let id: UUID
            let hosts: [String]
            let network: BenchmarkNetwork
            let started: Date
            var measurement: LocalMeasurement?
            var operation: String?
            var comparisonID: UUID?
        }
        let request = Request(id: id, hosts: [host, other], network: network, started: Date())
        defaults.set(try JSONEncoder().encode(request), forKey: "localQuickSearchRequest.v1")
        func json(_ object: Any, _ file: String) throws {
            try JSONSerialization.data(withJSONObject: object).write(to: run.appendingPathComponent(file), options: .atomic)
        }
        let ping: [String: Any] = ["server": host, "valid": true, "target": PingSample.target, "tunnel": "ipsec2",
                                  "started": "2026-11-25T10:00:00Z", "ended": "2026-11-25T10:00:20Z",
                                  "ping": ["sent": 20, "received": 18, "loss_pct": 10, "minimum_ms": 49,
                                           "average_ms": 100, "maximum_ms": 125]]
        try json(ping, "ping-results.jsonl")
        try json(ping, "winner.json")
        try json(["phase": "retained", "host": host], "quick-state.json")
        try json(["device": "en0"], "plan.json")
        try Data().write(to: run.appendingPathComponent("engine-stop-sent"))

        var held = true
        let bridge = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
        precondition(bridge.latestDirectory?.path == run.path)
        let history = base.appendingPathComponent("benchmarks.json")
        var store = try BenchmarkStore(fileURL: history)
        precondition(bridge.results.count == 1 && bridge.results[0].sample?.qualifies == true)
        precondition(bridge.retainedHost == host && !bridge.recoveryVerified)
        var added = try bridge.importCompleted(into: store)
        precondition(!added, "A result must not be assigned to a different physical interface")
        try json(["device": "en6"], "plan.json")
        added = try bridge.importCompleted(into: store)
        precondition(added && store.runs.first?.phase == .retained && store.runs.first?.finished == nil)
        precondition(store.runs.first?.selectedHost == host && store.runs.first?.canResume == false)
        added = try bridge.importCompleted(into: store)
        precondition(!added && store.rankings(for: network).first?.lossPercent == 10)
        store = try BenchmarkStore(fileURL: history)
        precondition(store.runs.first?.phase == .retained && store.runs.first?.recoveryNeeded != true)

        precondition(bridge.canRelease && bridge.releaseButtonTitle == "CoreaVPN 해제 · FlClash 복구")
        bridge.release()
        precondition(!bridge.canRelease && bridge.status.contains("연결 해제"))

        try json(["phase": "released", "host": host, "recovered": true], "quick-state.json")
        try json(["ok": true, "errors": []], "recovered.json")
        held = false
        bridge.refresh()
        precondition(bridge.recoveryVerified && !bridge.running && !bridge.canRelease && bridge.retainedHost == nil)
        added = try bridge.importCompleted(into: store)
        precondition(added && store.runs.count == 1 && store.runs.first?.id == id && store.runs.first?.phase == .completed)
        precondition(store.runs.first?.finished != nil && store.rankings(for: network).first?.runCount == 1)
        added = try bridge.importCompleted(into: store)
        precondition(!added && store.rankings(for: network).first?.sent == 20)

        try json(["phase": "failed", "recovered": false], "quick-state.json")
        try json(["ok": false, "errors": ["restore"]], "recovered.json")
        bridge.refresh()
        precondition(bridge.canRelease && !bridge.recoveryVerified && !bridge.running)
        added = try bridge.importCompleted(into: store)
        precondition(!added, "Recovery is required before adding results to rankings")
        var invalid = ping
        invalid["tunnel"] = "utun4"
        try json(invalid, "ping-results.jsonl")
        bridge.refresh()
        precondition(bridge.results.isEmpty, "Only IKEv2-bound 20-probe samples count")

        try FileManager.default.removeItem(at: run.appendingPathComponent("engine-stop-sent"))
        try FileManager.default.removeItem(at: run.appendingPathComponent("recovered.json"))
        try json(["phase": "released", "recovered": true], "quick-state.json")
        bridge.refresh()
        precondition(!bridge.canRelease && !bridge.recoveryVerified && bridge.status.contains("전환 전에"))

        let marker = runs.appendingPathComponent(run.lastPathComponent + ".release")
        try FileManager.default.removeItem(at: marker)
        try json(["phase": "preparing"], "quick-state.json")
        held = true
        bridge.refresh()
        precondition(bridge.canRelease && bridge.releaseButtonTitle == "검사 중지")
        try json(["phase": "searching", "host": other], "quick-state.json")
        try json(ping, "ping-results.jsonl")
        bridge.refresh()
        precondition(bridge.activeHost == other && bridge.releaseButtonTitle == "검사 중지")
        bridge.release()
        bridge.release()
        let reopened = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
        precondition(!reopened.canRelease && reopened.status.contains("중지를 요청"))
        precondition(reopened.releaseButtonTitle == "검사 중지 중…")
        try json(["phase": "recovering"], "quick-state.json")
        reopened.refresh()
        precondition(!reopened.canRelease && reopened.releaseButtonTitle == "FlClash 복구 중…")
        try Data().write(to: run.appendingPathComponent("engine-stop-sent"))
        try json(["phase": "released", "recovered": true], "quick-state.json")
        try json(["ok": true, "errors": []], "recovered.json")
        held = false
        reopened.refresh()
        precondition(reopened.recoveryVerified && reopened.status.contains("검사를 중지"))
        let partial = try BenchmarkStore(fileURL: base.appendingPathComponent("partial.json"))
        added = try reopened.importCompleted(into: partial)
        precondition(added && partial.runs.first?.phase == .cancelled && partial.runs.first?.rows.count == 1)
        precondition(partial.runs.first?.selectedHost == nil)

        let https: [String: Any] = [
            "measurement": "https", "valid": true, "server": other,
            "target": "speed.cloudflare.com", "peer_ipv4": "104.16.132.229", "tunnel": "ipsec2",
            "started": "2026-11-25T10:00:00+08:00", "ended": "2026-11-25T10:00:20+08:00",
            "speed": ["sent": 20, "received": 18, "average_ms": 100,
                      "download_mbps": 130.5, "upload_mbps": 20.5, "download_loaded_ms": 135.0,
                      "upload_loaded_ms": 116.0, "download_bytes": 4_000_000, "upload_bytes": 800_000,
                      "download_seconds": 32.0 / 130.5, "upload_seconds": 6.4 / 20.5]
        ]
        try FileManager.default.removeItem(at: marker)
        try FileManager.default.removeItem(at: run.appendingPathComponent("ping-results.jsonl"))
        try json(https, "https-results.jsonl")
        try json(https, "winner.json")
        try json(["phase": "retained", "host": other], "quick-state.json")
        held = true
        reopened.refresh()
        precondition(reopened.results.count == 1 && reopened.results.first?.httpsSample?.qualifies == true)
        precondition(reopened.results.first?.sample == nil && reopened.retainedHost == other)
        let httpsFile = base.appendingPathComponent("https-only.json")
        let speedStore = try BenchmarkStore(fileURL: httpsFile)
        let imported = try reopened.importCompleted(into: speedStore)
        precondition(imported && speedStore.runs.first?.selectedHost == other)
        let speedReopened = try BenchmarkStore(fileURL: httpsFile)
        precondition(speedReopened.rankings(for: network).isEmpty && speedReopened.httpsRankings(for: network).count == 1)
        precondition(speedReopened.httpsRankings(for: network).first?.downloadMbps == 130.5)
        let csv = speedReopened.csv(network: network)
        precondition(csv.contains("https_failure_pct") && csv.contains("\"speed.cloudflare.com\""))
        precondition(csv.contains(",\"HTTPS\",\"104.16.132.229\",\"20\",\"18\",\"10.0\","))
        precondition(!csv.contains("168.126.63.1"))
        precondition(csv.contains(String(32.0 / 130.5)) && csv.contains(String(6.4 / 20.5)))
        var failedUpload = https
        var idleFree = https["speed"] as! [String: Any]
        idleFree["upload_seconds"] = 2.0
        idleFree["sent"] = 0
        idleFree["received"] = 0
        idleFree.removeValue(forKey: "average_ms")
        failedUpload["speed"] = idleFree
        let usable = try LocalMeasurement.https.decode(JSONSerialization.data(withJSONObject: failedUpload), host: other)
        precondition(usable.qualifies && usable.httpsSample?.uploadMbps == nil && usable.httpsSample?.failurePercent == nil)

        // New fast searches must decline an old un-timed reading or a forged throughput.
        var fastRequest = request
        fastRequest.operation = "quick"
        fastRequest.measurement = .https
        defaults.set(try JSONEncoder().encode(fastRequest), forKey: "localQuickSearchRequest.v1")
        let guarded = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
        try json(failedUpload, "https-results.jsonl")
        try json(failedUpload, "winner.json")
        guarded.refresh()
        precondition(guarded.retainedHost == other && guarded.results.first?.outcome == .partial)
        precondition(guarded.results.first?.httpsError?.contains("미송신") == true)
        for seconds in [nil, 2.0] as [Double?] {
            var unconfirmed = https
            var stats = https["speed"] as! [String: Any]
            stats["download_seconds"] = seconds
            unconfirmed["speed"] = stats
            try json(unconfirmed, "https-results.jsonl")
            try json(unconfirmed, "winner.json")
            guarded.refresh()
            precondition(guarded.retainedHost == nil)
        }
        try json(https, "https-results.jsonl")
        try json(https, "winner.json")
        guarded.refresh()
        precondition(guarded.retainedHost == other)
        defaults.set(try JSONEncoder().encode(request), forKey: "localQuickSearchRequest.v1")

        var mismatched = https
        mismatched["peer_ipv4"] = "104.16.132.230"
        try json(mismatched, "winner.json")
        let unverified = try reopened.importCompleted(into: speedStore)
        precondition(!unverified, "The retained winner must match the recorded endpoint and measurements")
        var failedSample = https
        var metrics = failedSample["speed"] as! [String: Any]
        metrics["received"] = 17
        failedSample["speed"] = metrics
        try json(failedSample, "https-results.jsonl")
        reopened.refresh()
        precondition(reopened.results.first?.httpsSample?.qualifies == true && reopened.retainedHost == nil)

        precondition(LocalMeasurement.https.arguments == ["--measurement", "https"])
        precondition(LocalMeasurement.icmp.arguments == ["--measurement", "icmp"])
        try json(https, "https-results.jsonl")
        try json(ping, "ping-results.jsonl")
        for method in LocalMeasurement.allCases {
            var selectedRequest = request
            selectedRequest.measurement = method
            // The selection can change for a future run. This run must keep the
            // protocol in its own receipt through app restarts.
            let otherMethod: LocalMeasurement = method == .https ? .icmp : .https
            defaults.set(otherMethod.rawValue, forKey: LocalMeasurement.preferenceKey)
            defaults.set(try JSONEncoder().encode(selectedRequest), forKey: "localQuickSearchRequest.v1")
            let winnerHost = method == .https ? other : host
            try json(["phase": "searching", "host": winnerHost], "quick-state.json")
            let selected = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
            precondition(selected.lastMeasurement == method && selected.status.contains(method.title))
            precondition(selected.results.map(\.host) == [winnerHost])
            precondition(selected.results.first?.httpsSample?.downloadMbps == (method == .https ? 130.5 : nil))
            try json(method == .https ? ping : https, "winner.json")
            try json(["phase": "retained", "host": winnerHost], "quick-state.json")
            selected.refresh()
            let selectedStore = try BenchmarkStore(fileURL: base.appendingPathComponent("selected-\(method.rawValue).json"))
            added = try selected.importCompleted(into: selectedStore)
            precondition(!added, "Winner evidence must use the selected measurement")
            try json(method == .https ? https : ping, "winner.json")
            selected.refresh()
            added = try selected.importCompleted(into: selectedStore)
            precondition(added && selectedStore.runs.first?.selectedHost == winnerHost)
        }
        var comparisonRequest = request
        comparisonRequest.operation = "all"
        let comparisonData = try JSONEncoder().encode(comparisonRequest)
        defaults.set(comparisonData, forKey: "localQuickSearchRequest.v1")
        defaults.set(comparisonData, forKey: "localFullComparisonRequest.v1")
        func writeEvents(_ items: [[String: Any]]) throws {
            var data = Data()
            for item in items {
                data.append(try JSONSerialization.data(withJSONObject: item))
                data.append(10)
            }
            try data.write(to: run.appendingPathComponent("events.jsonl"), options: .atomic)
        }
        var hostSpeed = https
        hostSpeed["server"] = host
        let validEvents: [[String: Any]] = [
            ["stage": "server-start", "server": host],
            ["stage": "server-connected", "server": host, "tunnel": "ipsec2", "interface_index": 12],
            ["stage": "ping-complete", "server": host, "result": ping],
            ["stage": "https-complete", "server": host, "result": hostSpeed],
            ["stage": "server-finished", "server": host],
            ["stage": "server-start", "server": other],
            ["stage": "server-connected", "server": other, "tunnel": "ipsec3", "interface_index": 13],
            ["stage": "https-complete", "server": other, "result": https], // wrong tunnel
            ["stage": "probe-failed", "server": other, "step": "icmp", "error": "timeout"],
            ["stage": "server-finished", "server": other]
        ]
        try writeEvents(validEvents)
        try json(["device": "en6", "operation": "all"], "plan.json")
        try json(["phase": "completed", "recovered": true], "quick-state.json")
        try json(["ok": true, "errors": []], "recovered.json")
        held = false
        let all = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
        precondition(!all.comparisonReady, "Manual selection requires stable proxy verification")
        try writeEvents(validEvents + [["stage": "verify-stable-flclash-proxy", "ok": true]])
        all.refresh()
        precondition(!all.running && all.comparisonReady && all.retainedHost == nil && all.comparisonRows.count == 23)
        var idleOnly = hostSpeed
        var idleOnlyStats: [String: Any] = ["sent": 20, "received": 18, "average_ms": 60.0]
        idleOnly["speed"] = idleOnlyStats
        try writeEvents(Array(validEvents.prefix(3)) + [["stage": "https-idle-complete", "server": host, "result": idleOnly]])
        try json(["phase": "released", "recovered": true], "quick-state.json")
        all.refresh()
        precondition(all.comparisonRows.first(where: { $0.host == host })?.httpsSample?.averageMS == 60)
        idleOnlyStats["upload_mbps"] = 1.63
        idleOnlyStats["upload_bytes"] = 1_000_000
        idleOnly["speed"] = idleOnlyStats
        idleOnly["errors"] = ["download": "No confirmed HTTPS transfer"]
        try writeEvents(Array(validEvents.prefix(3)) + [["stage": "https-complete", "server": host, "result": idleOnly]])
        all.refresh()
        let oneDirection = all.comparisonRows.first(where: { $0.host == host })
        precondition(oneDirection?.httpsError?.contains("다운로드 전송량 미확인") == true && oneDirection?.httpsSample?.uploadMbps == 1.63)
        try json(["phase": "completed", "recovered": true], "quick-state.json")
        try writeEvents(validEvents + [["stage": "verify-stable-flclash-proxy", "ok": true]])
        all.refresh()
        let paired = all.comparisonRows.first { $0.host == host }
        precondition(paired?.sample?.received == 18 && paired?.httpsSample?.downloadMbps == 130.5 && paired?.outcome == .measured)
        let crossTunnel = all.comparisonRows.first { $0.host == other }
        precondition(crossTunnel?.httpsSample == nil && crossTunnel?.pingError == "timeout")
        let comparedStore = try BenchmarkStore(fileURL: base.appendingPathComponent("compared.json"))
        added = try all.importCompleted(into: comparedStore)
        precondition(added && comparedStore.runs.first?.mode == .all && comparedStore.runs.first?.paired == true)
        precondition(comparedStore.runs.first?.selectedHost == nil)
        added = try all.importCompleted(into: comparedStore)
        precondition(!added)

        // A user can pick a tested server regardless of its quick-mode thresholds.
        let selectedID = UUID()
        let manual = Request(id: selectedID, hosts: [other], network: network, started: Date(),
                             operation: "select", comparisonID: comparisonRequest.id)
        defaults.set(try JSONEncoder().encode(manual), forKey: "localQuickSearchRequest.v1")
        let manualDir = runs.appendingPathComponent(selectedID.uuidString + "-quick-search")
        try FileManager.default.createDirectory(at: manualDir, withIntermediateDirectories: true)
        func selection(_ value: Any, _ file: String) throws {
            try JSONSerialization.data(withJSONObject: value).write(to: manualDir.appendingPathComponent(file), options: .atomic)
        }
        try selection(["device": "en6", "operation": "select"], "plan.json")
        try selection(["phase": "retained", "host": other], "quick-state.json")
        held = true
        let selected = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { held })
        precondition(selected.retainedHost == nil)
        try selection(["measurement": "connection", "target": PingSample.target, "server": other, "tunnel": "ipsec3",
                       "interface_index": 13, "valid": true], "winner.json")
        selected.refresh()
        precondition(selected.retainedHost == other && selected.comparisonRows == all.comparisonRows)
        added = try selected.importCompleted(into: comparedStore)
        precondition(added && comparedStore.runs.count == 1 && comparedStore.runs.first?.selectedHost == other)
        precondition(comparedStore.runs.first?.httpsRanks.first?.host == host)
        added = try selected.importCompleted(into: comparedStore)
        precondition(!added)
        held = false
        try json([host, other], "quick-hosts.json")
        let cliStart: [String: Any] = ["stage": "physical-route-confirmed", "time": "2026-11-26T09:00:00.000000+08:00"]
        let cliEnd: [String: Any] = ["stage": "recovery-complete", "time": "2026-11-26T09:10:00.000000+08:00", "ok": true]
        let verifiedEvents = [cliStart] + validEvents + [["stage": "verify-stable-flclash-proxy", "ok": true], cliEnd]
        try writeEvents(verifiedEvents)
        let cliRun = runtime.appendingPathComponent("cli-evidence")
        try FileManager.default.copyItem(at: run, to: cliRun)
        let importedStore = try BenchmarkStore(fileURL: base.appendingPathComponent("cli-history.json"))
        defaults.removeObject(forKey: "localQuickSearchRequest.v1")
        defaults.removeObject(forKey: "localFullComparisonRequest.v1")
        let observer = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { false })
        added = try observer.importComparison(from: cliRun, into: network, store: importedStore)
        precondition(added && observer.comparisonReady)
        precondition(observer.comparisonRows.filter { ![host, other].contains($0.host) }.allSatisfy {
            $0.outcome == .notRun && $0.detail == "이번 검사 범위 밖"
        })
        added = try observer.importComparison(from: cliRun, into: network, store: importedStore)
        precondition(!added && importedStore.runs.count == 1)
        try FileManager.default.removeItem(at: cliRun)
        let relaunched = LocalQuickSearch(workspace: runtime, defaults: defaults, pilotLockHeld: { false })
        precondition(relaunched.comparisonReady && relaunched.comparisonID == importedStore.runs.first?.id)
        precondition(relaunched.comparisonRows == importedStore.runs.first?.rows && relaunched.retainedHost == nil)
        // A legacy standalone download can look successful in the result while timed-out
        // data lanes are documented in the worker log. Warm-up failures are independent.
        try json([host], "quick-hosts.json")
        try writeEvents([cliStart] + Array(validEvents.prefix(5)) + [
            ["stage": "verify-stable-flclash-proxy", "ok": true], cliEnd])
        let diagnostic = runtime.appendingPathComponent("single-server-diagnostic")
        try FileManager.default.copyItem(at: run, to: diagnostic)
        let log = diagnostic.appendingPathComponent("worker.log")
        try Data("download read failed after 10/65536 bytes: timeout: warmup".utf8).write(to: log)
        added = try observer.importComparison(from: diagnostic, into: network, store: importedStore)
        precondition(added && observer.comparisonRows.first(where: { $0.host == host })?.httpsSample?.downloadMbps == 130.5)
        try Data("download read failed after 1000/4194304 bytes: timeout: slow".utf8).write(to: log)
        added = try observer.importComparison(from: diagnostic, into: network, store: importedStore)
        precondition(added)
        let corrected = observer.comparisonRows.first { $0.host == host }
        precondition(corrected?.httpsError?.contains("측정 실패") == true && corrected?.outcome == .partial)
        precondition(corrected?.httpsSample?.downloadMbps == nil && corrected?.httpsSample?.uploadMbps == 20.5)
        try FileManager.default.removeItem(at: log)
        added = try observer.importComparison(from: diagnostic, into: network, store: importedStore)
        precondition(!added && observer.comparisonRows.first(where: { $0.host == host }) == corrected)
        print("Local bridge checks passed (independent quick criteria, paired tunnel evidence, recovery, manual selection and idempotent historical import across restart)")

    }
}
