import Foundation

@MainActor
protocol BenchmarkDriver: AnyObject {
    func snapshot() async throws -> ScanBaseline
    func begin(host: String) async throws
    func ping(host: String) async throws -> PingSample
    func speed(host: String, checkpoint: @escaping (HTTPSBenchmarkSample) throws -> Void) async throws -> HTTPSBenchmarkSample
    func select(host: String) async throws
    func restore(_ baseline: ScanBaseline) async throws
    func disconnect() async throws
}

@MainActor
final class BenchmarkScanner {
    private struct SelectionFailure: LocalizedError {
        let errorDescription: String?
    }
    private enum Stop { case pause, cancel, disconnect }
    private let store: BenchmarkStore
    private let driver: any BenchmarkDriver
    private var active: Task<BenchmarkRun, Error>?
    private var generation: UUID?
    private var stop: Stop?
    private var disconnecting = false

    init(store: BenchmarkStore, driver: any BenchmarkDriver) {
        self.store = store
        self.driver = driver
    }

    func run(mode: ScanMode, network: BenchmarkNetwork, candidates: [CoreaServer],
             resumeID: UUID? = nil, paired: Bool = true, isNetworkCurrent: @escaping () -> Bool = { true },
             onProgress: @escaping (BenchmarkRun) -> Void = { _ in }) async throws -> BenchmarkRun {
        try await runExclusive {
            try await self.execute(mode: mode, network: network, candidates: candidates, resumeID: resumeID,
                                   paired: paired, isNetworkCurrent: isNetworkCurrent, progress: onProgress)
        }
    }

    private func runExclusive(_ operation: @escaping @MainActor () async throws -> BenchmarkRun) async throws -> BenchmarkRun {
        guard active == nil, !disconnecting else { throw BenchmarkError.busy }
        let token = UUID()
        generation = token
        stop = nil
        let task = Task { try await operation() }
        active = task
        defer {
            if generation == token {
                active = nil
                stop = nil
                generation = nil
            }
        }
        return try await withTaskCancellationHandler(operation: { try await task.value }, onCancel: { task.cancel() })
    }

    // Waiting here prevents a stop/restart race while the previous driver is restoring its baseline.
    func pause() async throws {
        try await interrupt(.pause)
    }

    func stopScan() async throws {
        try await interrupt(.cancel)
    }

    private func interrupt(_ reason: Stop) async throws {
        guard let task = active else { return }
        // Backgrounding or changing networks must not turn a user stop into a resumable pause.
        if stop == nil || stop == .pause { stop = reason }
        task.cancel()
        _ = try await task.value
    }

    func disconnect() async throws {
        guard !disconnecting else { throw BenchmarkError.busy }
        disconnecting = true
        defer { disconnecting = false }
        if let task = active {
            stop = .disconnect
            task.cancel()
            // A run may already be restoring its previous fallback when the explicit stop arrives.
            // Finish that operation before issuing the final, authoritative disconnect.
            _ = await task.result
        }
        try await driver.disconnect()
        for var run in store.runs where run.canResume || run.recoveryNeeded == true {
            run.phase = .cancelled
            run.recoveryNeeded = false
            run.selectionBaseline = nil
            run.activeHost = nil
            run.finished = Date()
            try store.save(run)
        }
    }

    func recoverInterrupted() async throws {
        guard active == nil, !disconnecting else { throw BenchmarkError.busy }
        guard var interrupted = store.runs.last(where: { $0.recoveryNeeded == true }) else { return }
        disconnecting = true
        defer { disconnecting = false }
        _ = try await driver.snapshot()
        try await driver.restore(interrupted.selectionBaseline ?? interrupted.baseline)
        if interrupted.mode == .direct { interrupted.phase = .cancelled; interrupted.finished = Date() }
        interrupted.selectionBaseline = nil
        interrupted.recoveryNeeded = false
        try store.save(interrupted)
    }

    private func check(_ isNetworkCurrent: () -> Bool) throws {
        try Task.checkCancellation()
        guard isNetworkCurrent() else { throw BenchmarkError.wrongNetwork }
    }

    private func execute(mode: ScanMode, network: BenchmarkNetwork, candidates: [CoreaServer],
                         resumeID: UUID?, paired: Bool, isNetworkCurrent: @escaping () -> Bool,
                         progress: @escaping (BenchmarkRun) -> Void) async throws -> BenchmarkRun {
        guard mode != .direct else { throw BenchmarkError.invalidResume }
        let hosts = candidates.map(\.host)
        guard Set(hosts).count == hosts.count, Set(hosts).isSubset(of: Set(CoreaServer.catalog.map(\.host)))
        else { throw BenchmarkError.duplicate }
        let allowed = Set(hosts.filter { mode != .puma || $0 == "puma.coreavpn.net" })
        guard !allowed.isEmpty else { throw BenchmarkError.noCandidates }
        try check(isNetworkCurrent)

        var run: BenchmarkRun
        if let resumeID {
            guard let previous = store.runs.first(where: { $0.id == resumeID }), previous.canResume, previous.recoveryNeeded != true,
                  previous.network == network, previous.mode == mode, Set(previous.order) == allowed,
                  mode != .all || (previous.paired == true) == paired
            else { throw BenchmarkError.invalidResume }
            let current = try await driver.snapshot()
            guard current == previous.baseline else { throw BenchmarkError.invalidResume }
            try check(isNetworkCurrent)
            run = previous
            run.phase = .scanning
            run.message = nil
            run.recoveryNeeded = nil
        } else {
            guard !store.runs.contains(where: { $0.recoveryNeeded == true }) else { throw BenchmarkError.invalidResume }
            var order = hosts.filter(allowed.contains)
            if mode == .quick || mode == .fastQuick {
                let ranked = mode == .fastQuick ? store.httpsRankings(for: network).map(\.host)
                    : store.rankings(for: network).filter { $0.received > 0 }.map(\.host)
                var seen = Set<String>()
                order = (["leo.coreavpn.net"] + ranked + order).filter { allowed.contains($0) && seen.insert($0).inserted }
            }
            let baseline = try await driver.snapshot()
            try check(isNetworkCurrent)
            run = BenchmarkRun(id: UUID(), network: network, mode: mode, started: Date(), order: order, baseline: baseline)
            run.paired = mode == .all && paired
            if mode != .puma {
                run.rows = CoreaServer.catalog.filter { !allowed.contains($0.host) }.map {
                    BenchmarkAttempt(host: $0.host, time: Date(), outcome: .skipped, detail: "기기·계정 또는 선택한 그룹에서 제외")
                }
            }
            if run.paired == true {
                run.rows += order.map { BenchmarkAttempt(host: $0, time: run.started, outcome: .notRun) }
            }
        }

        func publish() throws {
            try store.save(run)
            progress(run)
        }
        func saveRow(_ row: BenchmarkAttempt) throws {
            if let index = run.rows.firstIndex(where: { $0.host == row.host }) { run.rows[index] = row }
            else { run.rows.append(row) }
            try publish()
        }

        func qualifies(_ row: BenchmarkAttempt) -> Bool {
            guard row.retentionInvalidated != true, row.outcome == .partial || row.outcome == .measured else { return false }
            switch mode {
            case .quick: return row.sample?.qualifies == true
            case .fastQuick: return row.httpsSample?.qualifies == true
            default: return false
            }
        }

        func propagateInterrupt(_ error: Error) throws {
            if error is CancellationError { throw error }
            if (error as? BenchmarkError) == .wrongNetwork { throw error }
            try check(isNetworkCurrent)
        }
        // Must persist original state and resume order before changing the connection.
        try publish()
        do {
            for host in run.order {
                try check(isNetworkCurrent)
                if run.rows.contains(where: qualifies) { break }
                if run.rows.contains(where: { $0.host == host && $0.outcome != .stopped && $0.outcome != .notRun }) { continue }
                run.activeHost = host
                var row = BenchmarkAttempt(host: host, time: Date(), outcome: .stopped)
                try saveRow(row)
                do {
                    try await driver.begin(host: host)
                    try check(isNetworkCurrent)
                } catch {
                    try propagateInterrupt(error)
                    row.outcome = .failed
                    row.detail = error.localizedDescription
                    try saveRow(row)
                    continue
                }
                if mode != .fastQuick {
                    do {
                        let sample = try await driver.ping(host: host)
                        try check(isNetworkCurrent)
                        row.sample = sample
                    } catch {
                        try propagateInterrupt(error)
                        row.pingError = error.localizedDescription
                    }
                    try saveRow(row)
                }
                if mode == .fastQuick || run.paired == true {
                    do {
                        let sample = try await driver.speed(host: host) { result in
                            try self.check(isNetworkCurrent)
                            row.httpsSample = result
                            try saveRow(row)
                        }
                        try check(isNetworkCurrent)
                        row.httpsSample = sample
                        let missing: [String] = [(sample.downloadMbps, "다운로드"), (sample.uploadMbps, "업로드"),
                                       (sample.averageMS, "평상시 지연"), (sample.downloadLoadedMS, "다운로드 중 지연"),
                                       (sample.uploadLoadedMS, "업로드 중 지연")].compactMap { value, label in
                            value == nil ? label : nil
                        }
                        if !missing.isEmpty {
                            row.httpsError = missing.joined(separator: " · ") + " 측정 실패"
                        }
                    } catch {
                        try propagateInterrupt(error)
                        // A checkpoint is accepted only while the original route is verified. Its
                        // measurements remain useful even if a later stage loses that connection.
                        row.retentionInvalidated = true
                        row.httpsError = error.localizedDescription
                    }
                }
                let hasEvidence = row.sample != nil || row.httpsSample.map {
                    $0.received > 0 || $0.downloadMbps != nil || $0.uploadMbps != nil
                } == true
                if row.pingError != nil || row.httpsError != nil {
                    row.outcome = hasEvidence ? .partial : .failed
                } else if row.sample?.received == 0 {
                    row.outcome = row.httpsSample?.downloadMbps == nil ? .noReply : .partial
                } else {
                    row.outcome = .measured
                }
                run.activeHost = nil
                try saveRow(row)
                if mode == .all { try await driver.disconnect() }
            }

            try check(isNetworkCurrent)
            let winner = run.rows.first(where: qualifies)?.host
                ?? (mode == .all && run.paired != true ? run.ranks.first(where: { $0.received > 0 })?.host : nil)
            if let winner {
                try await driver.select(host: winner)
                try check(isNetworkCurrent)
                run.selectedHost = winner
                run.selectedAt = Date()
            } else {
                try await driver.restore(run.baseline)
                try check(isNetworkCurrent)
                if run.paired == true { run.message = "검사를 마치고 이전 연결을 복구했습니다. 결과표에서 서버를 선택하세요." }
                else if mode != .puma { run.message = "선택 가능한 측정 결과가 없어 이전 연결 상태를 복구했습니다." }
            }
            run.phase = .completed
            run.finished = Date()
            try publish()
            return run
        } catch {
            let cause = error
            let interrupted = cause is CancellationError || (cause as? BenchmarkError) == .wrongNetwork || Task.isCancelled
            let explicitStop = stop == .disconnect
            run.activeHost = nil
            run.selectedHost = nil
            run.selectedAt = nil
            run.message = cause.localizedDescription
            // Cleanup includes polling and must run outside the already-cancelled task.
            do {
                try await Task { @MainActor in
                    if explicitStop { try await driver.disconnect() }
                    else { try await driver.restore(run.baseline) }
                }.value
            } catch {
                run.phase = .failed
                run.recoveryNeeded = true
                run.message = "복구 실패: " + error.localizedDescription
                run.finished = Date()
                try publish()
                throw error
            }
            if stop == .cancel {
                run.phase = .cancelled
                run.message = "검사를 중지하고 이전 VPN 상태로 복구했습니다."
            } else {
                run.phase = stop == .disconnect ? .cancelled : (interrupted ? .paused : .failed)
            }
            if run.paired == true {
                for host in run.order where !run.rows.contains(where: { $0.host == host }) {
                    run.rows.append(BenchmarkAttempt(host: host, time: Date(), outcome: .notRun))
                }
            }
            run.finished = run.phase == .paused ? nil : Date()
            try publish()
            if interrupted { return run }
            throw cause
        }
    }

    func connectSelected(host: String, runID: UUID? = nil, network: BenchmarkNetwork,
                         isNetworkCurrent: @escaping () -> Bool) async throws -> BenchmarkRun {
        try await runExclusive {
            guard CoreaServer.catalog.contains(where: { $0.host == host }),
                  !self.store.runs.contains(where: { $0.recoveryNeeded == true }) else { throw BenchmarkError.invalidResume }
            var comparison: BenchmarkRun?
            var index = 0
            if let runID {
                guard let existing = self.store.runs.first(where: { $0.id == runID }), existing.network == network,
                      existing.paired == true, existing.phase == .completed, existing.order.contains(host),
                      let row = existing.rows.firstIndex(where: { $0.host == host }) else { throw BenchmarkError.invalidResume }
                comparison = existing
                index = row
            }
            let baseline: ScanBaseline
            do {
                try self.check(isNetworkCurrent)
                baseline = try await self.driver.snapshot()
                try self.check(isNetworkCurrent)
            } catch {
                let reason = "\(host) 연결 준비 실패: " + error.localizedDescription
                if var comparison {
                    comparison.rows[index].selectionError = reason
                    comparison.message = reason
                    try self.store.save(comparison)
                }
                throw SelectionFailure(errorDescription: reason)
            }
            var run = comparison ?? BenchmarkRun(id: UUID(), network: network, mode: .direct,
                started: Date(), order: [host], baseline: baseline,
                rows: [BenchmarkAttempt(host: host, time: Date(), outcome: .notRun, detail: "속도 검사 생략")])
            run.selectionBaseline = baseline
            run.recoveryNeeded = true
            run.message = nil
            run.rows[index].selectionError = nil
            try self.store.save(run)
            let previousSelection = run.selectedHost
            let previousSelectionDate = run.selectedAt
            do {
                try await self.driver.select(host: host)
                try self.check(isNetworkCurrent)
                if run.mode == .direct { run.phase = .completed; run.finished = Date() }
                run.selectedHost = host
                run.selectedAt = Date()
                run.selectionBaseline = nil
                run.recoveryNeeded = false
                try self.store.save(run)
                return run
            } catch {
                let failure = error
                if run.mode == .direct { run.phase = .failed; run.finished = Date() }
                run.selectedHost = previousSelection
                run.selectedAt = previousSelectionDate
                run.message = "\(host) 연결 실패: " + failure.localizedDescription
                run.rows[index].selectionError = run.message
                do {
                    try await Task { @MainActor in try await self.driver.restore(baseline) }.value
                    run.selectionBaseline = nil
                    run.recoveryNeeded = false
                } catch {
                    run.recoveryNeeded = true
                    run.selectionBaseline = baseline
                    run.message = (run.rows[index].selectionError ?? host) + " · 이전 연결 복구 실패: " + error.localizedDescription
                    run.rows[index].selectionError = run.message
                }
                try self.store.save(run)
                throw SelectionFailure(errorDescription: run.message)
            }
        }
    }
}
