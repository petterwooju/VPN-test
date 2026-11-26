#if os(macOS)
import SwiftUI
import AppKit

struct LocalQuickSection: View {
    @ObservedObject var model: SessionModel
    @ObservedObject var quick: LocalQuickSearch
    @ObservedObject var pilot: LocalPilot
    @State private var importMessage = ""

    private func hosts(for method: LocalMeasurement) -> [String] {
        let candidates = model.candidates.map(\.host)
        let ranked = method == .https ? model.store.httpsRankings(for: model.network).map(\.host) :
            model.store.rankings(for: model.network).filter { $0.received > 0 }.map(\.host)
        var seen = Set<String>()
        return (["leo.coreavpn.net"] + ranked + candidates)
            .filter { candidates.contains($0) && seen.insert($0).inserted }
    }

    private var blocked: Bool {
        !quick.available || quick.running || quick.canRelease || pilot.running || model.busy ||
            !model.link.available || model.network.label.isEmpty
    }

    private func run(_ method: LocalMeasurement) {
        importMessage = ""
        quick.start(hosts: hosts(for: method), network: model.network, measurement: method)
    }

    var body: some View {
        Section("CoreaVPN_TEST") {
            Button { run(.icmp) } label: {
                Label("168.126.63.1 100ms 이하 서버 연결", systemImage: "waveform.path.ecg")
            }
            .accessibilityIdentifier("quick-start")
            .disabled(blocked || model.candidates.isEmpty)
            Button { run(.https) } label: {
                Label("FAST 다운로드 10Mbps 이상 서버 연결", systemImage: "arrow.down.circle")
            }
            .accessibilityIdentifier("quick-fast-start")
            .disabled(blocked || model.candidates.isEmpty)
            Button {
                importMessage = ""
                quick.startAll(network: model.network)
            } label: {
                Label("전체 테스트 후 서버 선택", systemImage: "list.number")
            }
            .accessibilityIdentifier("comparison-start")
            .disabled(blocked)
            QuickReleaseButton(title: quick.releaseButtonTitle, enabled: quick.canRelease) { quick.release() }
                .frame(maxWidth: .infinity, alignment: .leading)
            if model.network.label.isEmpty { Text("설정에서 현재 회선 이름을 입력하세요.") }
            if !quick.status.isEmpty { Text(quick.status).textSelection(.enabled) }
            if let retained = quick.retainedHost { LabeledContent("연결 유지 중", value: retained) }
            else if let host = quick.activeHost { LabeledContent("검사 중", value: host) }
            if let last = quick.lastMeasurement, quick.showingQuick, !quick.results.isEmpty {
                LabeledContent("최근 검사 방식", value: last.title)
            }
            ForEach(quick.results) { attempt in
                if let sample = attempt.httpsSample {
                    HTTPSMeasurementRow(host: attempt.host, sample: sample)
                } else if let sample = attempt.sample {
                    LabeledContent(attempt.host) {
                        Text("\(sample.received)/\(sample.sent) · " +
                             (sample.meanMS.map { String(format: "%.3f ms", $0) } ?? "응답 없음") +
                             " · 손실 \(sample.lossPercent.formatted())%")
                    }
                } else { LabeledContent(attempt.host, value: attempt.outcome.displayName) }
            }
            if quick.recoveryVerified { Label("FlClash 복구 확인", systemImage: "checkmark.circle") }
            if !importMessage.isEmpty { Text(importMessage).font(.caption) }
            if let run = quick.latestDirectory {
                Button("검사 기록 열기") { NSWorkspace.shared.open(run) }
            }
        }
        .onAppear { quick.refresh(); saveCompleted() }
        .onChange(of: quick.running) { _, running in if !running { saveCompleted() } }
        .onChange(of: quick.retainedHost) { _, host in if host != nil { saveCompleted() } }
        .onChange(of: quick.phase) { _, _ in saveCompleted() }
        .onChange(of: quick.recoveryVerified) { _, recovered in if recovered { saveCompleted() } }
        if !quick.comparisonRows.isEmpty {
            Section("전체 검사 결과") {
                if let network = quick.comparisonNetwork {
                    Text("\(network.label) · \(network.interface)").font(.caption)
                }
                let record = model.store.runs.first { $0.id == quick.comparisonID }
                let rows = quick.comparisonRows.map { attempt in
                    var row = attempt
                    row.selectionError = row.host == quick.failedSelectionHost ? quick.selectionFailure :
                        record?.rows.first(where: { $0.host == row.host })?.selectionError
                    return row
                }
                ServerComparisonTable(rows: rows, selectedHost: record?.selectedHost,
                                      selectionEnabled: quick.comparisonReady && !blocked &&
                                          quick.comparisonNetwork == model.network) { host in
                    do { _ = try quick.select(host: host, network: model.network, store: model.store) }
                    catch { importMessage = error.localizedDescription }
                }
            }
        }
    }

    private func saveCompleted() {
        do {
            _ = try quick.updateImportedScope(in: model.store)
            if try quick.importCompleted(into: model.store) { importMessage = "이 회선의 측정 기록에 저장했습니다." }
        } catch { importMessage = error.localizedDescription }
    }
}

private struct QuickReleaseButton: NSViewRepresentable {
    let title: String
    let enabled: Bool
    let release: () -> Void

    class Coordinator: NSObject {
        var release: () -> Void
        init(_ release: @escaping () -> Void) { self.release = release }
        @objc func pressed() { release() }
    }
    func makeCoordinator() -> Coordinator { Coordinator(release) }
    func makeNSView(context: Context) -> NSButton {
        let button = NSButton(title: title, target: context.coordinator,
                              action: #selector(Coordinator.pressed))
        button.setAccessibilityIdentifier("quick-release")
        button.bezelStyle = .rounded
        return button
    }
    func updateNSView(_ button: NSButton, context: Context) {
        context.coordinator.release = release
        button.title = title
        button.isEnabled = enabled
    }
}
#endif
