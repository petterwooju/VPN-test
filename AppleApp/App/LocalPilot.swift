#if os(macOS)
import AppKit
import Foundation

struct LocalPilotResult {
    let directory: URL
    let sample: PingSample?
    let httpsSample: HTTPSBenchmarkSample?
    let recovered: Bool?
    let finalRoute: String?
    let started: Date?
    let interface: String?
    let importable: Bool
    let recovering: Bool
    let status: String

    fileprivate struct Event: Decodable {
        let stage: String
        let ok: Bool?
        let interface: String?
    }

    fileprivate struct Recovery: Decodable { let ok: Bool }

    static func inspect(_ directory: URL) -> (result: Self, terminal: Bool) {
        let decoder = JSONDecoder()
        let log = LocalTerminal.read(directory.appendingPathComponent("events.jsonl"), limit: 512 * 1024) ?? Data()
        let events = log.split(separator: 10).compactMap { try? decoder.decode(Event.self, from: Data($0)) }
        let recovered = LocalTerminal.read(directory.appendingPathComponent("recovered.json"), limit: 16 * 1024)
            .flatMap { try? decoder.decode(Recovery.self, from: $0).ok }
        let flVerified = events.last { $0.stage == "verify-stable-flclash-proxy" }?.ok == true
        let verified: Bool? = recovered == false ? false : (recovered == true && flVerified ? true : nil)
        let worker = events.last { $0.stage == "worker-finished" }?.ok
        let measurement = recovered == true ? try? LocalPumaMeasurement.load(from: directory) : nil
        let probe = measurement?.probe ?? (try? LocalPumaMeasurement.readProbe(from: directory))
        let failedPreflight = events.contains { $0.stage == "preparation-failed" }
        let stopped = events.contains { $0.stage == "measurement-stopped" }
        let recovering = stopped || events.contains {
            ["ping-complete", "https-complete", "measurement-interrupted", "watchdog-recovery"].contains($0.stage)
        }
        let status: String
        if failedPreflight { status = "사전 점검에서 중단됐습니다. 실행 폴더와 Terminal에서 원인을 확인하세요." }
        else if recovered == false { status = "복구 점검을 통과하지 못했습니다. 실행 폴더의 recovered.json을 확인하세요." }
        else if stopped {
            status = verified == true ? "Puma 검사를 중지하고 FlClash 복구를 확인했습니다."
                : "Puma 검사를 중지했습니다. FlClash를 복구하고 있습니다."
        }
        else if worker == false { status = measurement == nil ? "Puma 측정을 마치지 못했습니다." : "Puma 측정 완료 · FlClash 복구 재시도 후 정상" }
        else if worker == true {
            status = measurement == nil ? "측정 기록을 검증할 수 없습니다." : "Puma 터널의 측정을 마쳤습니다."
        } else if recovering {
            status = "FlClash와 네트워크 복구를 확인하고 있습니다."
        } else if events.contains(where: { $0.stage == "puma-connected" }) { status = "Puma 터널에서 측정 중입니다." }
        else if events.contains(where: { $0.stage == "stopping-flclash-engine" }) { status = "로컬 복구 감시가 시작됐습니다. Puma에 연결하고 있습니다." }
        else if events.contains(where: { $0.stage == "prepared" }) { status = "사전 점검을 통과했습니다. Terminal에서 관리자 인증을 진행하세요." }
        else { status = "Puma와 FlClash의 현재 상태를 확인하고 있습니다." }
        let rawRoute = events.last { $0.stage == "final-route" }?.interface
        let route = rawRoute.flatMap { $0.range(of: #"^[a-zA-Z][a-zA-Z0-9]{0,15}$"#, options: .regularExpression) != nil ? $0 : nil }
        let item = Self(directory: directory, sample: probe?.sample, httpsSample: probe?.httpsSample,
                        recovered: verified, finalRoute: route, started: probe?.started, interface: measurement?.interface,
                        importable: measurement != nil && verified == true, recovering: recovering, status: status)
        return (item, failedPreflight || worker != nil)
    }
}

@MainActor
final class LocalPilot: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var canStop = false
    @Published private(set) var status = ""
    @Published private(set) var latest: LocalPilotResult?
    private let workspace: URL?
    private let fm = FileManager.default
    private let defaults = UserDefaults.standard
    private let requestKey = "localPumaTerminalRequest"
    private var monitor: Task<Void, Never>?

    init() {
        workspace = LocalTerminal.workspace
    }

    private var launcher: URL? { workspace?.appendingPathComponent("Run-Puma.command") }

    var available: Bool {
        guard let launcher, fm.isExecutableFile(atPath: launcher.path),
              let attr = try? launcher.resourceValues(forKeys: [.isRegularFileKey,.isSymbolicLinkKey]) else { return false }
        return attr.isRegularFile == true && attr.isSymbolicLink != true
    }

    private func receipt(_ id: UUID) -> URL {
        fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CoreaVPN/LocalPilot/\(id.uuidString)", isDirectory: true)
    }

    @discardableResult
    func start(measurement: LocalMeasurement) -> UUID? {
        refresh()
        guard !running, available, let launcher else { return nil }
        guard !LocalTerminal.anotherPilotIsRunning() else {
            status = "이 Mac에서 다른 VPN 검사 또는 복구가 진행 중입니다."
            return nil
        }
        let id = UUID(), folder = receipt(id)
        do {
            let command = "COREAVPN_PUMA_RUN_ID=" + LocalTerminal.quoted(id.uuidString) + " " + LocalTerminal.quoted(launcher.path)
                + " " + measurement.arguments.map(LocalTerminal.quoted).joined(separator: " ")
            try LocalTerminal.launch(folder: folder, name: "Puma.command", command: command) { [weak self] error in
                Task { @MainActor in
                    guard let self, self.defaults.string(forKey: self.requestKey) == id.uuidString else { return }
                    if error != nil {
                        self.refresh()
                        self.status = "Terminal에서 검사 파일을 열 수 없습니다."
                    } else { self.refresh() }
                }
            }
            defaults.set(id.uuidString, forKey: requestKey)
            latest = nil
            running = true
            status = "Terminal에서 Puma 점검을 시작하고 있습니다."
            poll()
            return id
        } catch { status = error.localizedDescription; return nil }
    }

    func stopMeasurement() {
        refresh()
        guard canStop, let directory = latest?.directory else { return }
        do {
            try Data().write(to: directory.appendingPathComponent("stop-measurement"), options: .withoutOverwriting)
            refresh()
        } catch { status = error.localizedDescription }
    }

    func refresh() {
        canStop = false
        guard let workspace, available else {
            status = "이 Mac의 실행 가능한 Run-Puma.command가 필요합니다."
            running = false
            return
        }
        let runs = workspace.appendingPathComponent("runs", isDirectory: true)
        let request = defaults.string(forKey: requestKey).flatMap(UUID.init(uuidString:))
        if let request {
            let folder = receipt(request), directory = runs.appendingPathComponent(request.uuidString + "-puma-pilot")
            let exists = fm.fileExists(atPath: directory.path)
            let report = exists ? LocalPilotResult.inspect(directory) : nil
            latest = report?.result
            let exitCode = LocalTerminal.read(folder.appendingPathComponent("exit-code"), limit: 16) != nil
            let attributes = try? folder.resourceValues(forKeys: [.creationDateKey])
            let age = -(attributes?.creationDate?.timeIntervalSinceNow ?? -.infinity)
            let pid = LocalTerminal.read(folder.appendingPathComponent("shell-pid"), limit: 20)
                .flatMap { Int32(String(decoding: $0, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) }
            let shellAlive = pid.map { $0 > 1 && kill($0, 0) == 0 } ?? false
            // The watchdog runs in its own process group and may still be performing cleanup after Terminal closes.
            let armed = try? directory.appendingPathComponent("watchdog-ready").resourceValues(forKeys: [.creationDateKey])
            let watchdogRecent = (armed?.creationDate?.timeIntervalSinceNow ?? -.infinity) > -360
            let awaitingWorker = report?.terminal != true && !exitCode && (shellAlive || (pid == nil && age < 60))
            let awaitingRecovery = watchdogRecent && report?.result.recovered != true && LocalTerminal.anotherPilotIsRunning()
            running = awaitingWorker || awaitingRecovery
            status = report?.result.status ?? "Terminal에서 사전 점검을 기다리고 있습니다."
            if running && awaitingWorker && armed?.creationDate != nil && report?.result.recovering == false {
                if fm.fileExists(atPath: directory.appendingPathComponent("stop-measurement").path) {
                    status = "Puma 검사 중지를 요청했습니다. 복구를 기다리고 있습니다."
                } else { canStop = true }
            }
            if awaitingRecovery && report?.terminal == true {
                status = "검사가 중단되어 독립 복구 프로세스의 최종 결과를 기다리고 있습니다."
            }
            if running { poll(); return }
            if report?.terminal != true {
                status = report?.result.recovered == true ? "FlClash 복구가 확인됐습니다. 측정 종료 기록은 없습니다."
                    : "검사가 종료되거나 중단됐습니다. Terminal과 실행 폴더를 확인하세요."
            }
            if LocalTerminal.latestPumaDirectory(in: runs) == directory { return }
        }
        // A manually started run is historical evidence. Never trust a pointer outside this workspace.
        if let last = LocalTerminal.latestPumaDirectory(in: runs) {
            let report = LocalPilotResult.inspect(last)
            latest = report.result
            status = report.terminal ? "지난 검사 · " + report.result.status : "이전 Terminal 실행 기록입니다."
        }
    }

    private func poll() {
        guard monitor == nil else { return }
        monitor = Task { [weak self] in
            while self?.running == true {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard !Task.isCancelled else { break }
                self?.refresh()
            }
            self?.monitor = nil
        }
    }

    deinit { monitor?.cancel() }
}
#endif
