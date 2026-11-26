import SwiftUI
import UniformTypeIdentifiers

struct CSVReport: FileDocument {
    static var readableContentTypes: [UTType] { [.commaSeparatedText] }
    let data: Data
    init(_ text: String) { data = Data(text.utf8) }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

extension AttemptOutcome {
    var displayName: String {
        switch self { case .measured: return "측정"; case .failed: return "실패"; case .skipped: return "제외"; case .noReply: return "응답 없음"; case .partial: return "부분 성공"; case .notRun: return "미실행"; case .stopped: return "중지" }
    }
}
extension ScanMode {
    var displayName: String {
        switch self { case .all: return "전체 검사"; case .quick: return "빠른 연결"; case .fastQuick: return "FAST 다운로드 10Mbps 검색"; case .puma: return "Puma 점검" }
    }
}
extension ScanPhase {
    var displayName: String {
        switch self { case .retained: return "연결 유지"; case .completed: return "완료"; case .cancelled: return "취소"; case .failed: return "실패"; case .paused: return "일시 정지"; case .scanning: return "진행 중" }
    }
}

struct HTTPSMeasurementRow: View {
    let host: String
    let sample: HTTPSBenchmarkSample

    private func speed(_ value: Double?) -> String { value.map { String(format: "%.1f Mbps", $0) } ?? "측정값 없음" }
    private func latency(_ value: Double?) -> String { value.map { String(format: "%.1f ms", $0) } ?? "측정값 없음" }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(host)
            Text("다운로드 \(speed(sample.downloadMbps)) · 업로드 \(speed(sample.uploadMbps))")
            Text("평상시 \(latency(sample.averageMS)) · 다운로드 중 \(latency(sample.downloadLoadedMS)) · 업로드 중 \(latency(sample.uploadLoadedMS))")
            Text("HTTPS 응답 \(sample.received)/\(sample.sent)")
        }.font(.caption).foregroundStyle(.secondary)
    }
}

struct HistoryView: View {
    @ObservedObject var store: BenchmarkStore
    @ObservedObject var model: SessionModel
    @State private var selected: BenchmarkNetwork?
    @State private var exporting = false
    @State private var failure = ""
    private var networks: [BenchmarkNetwork] {
        store.runs.reversed().reduce(into: [BenchmarkNetwork]()) { items, run in
            if !items.contains(run.network) { items.append(run.network) }
        }
    }
    private var scope: BenchmarkNetwork {
        selected ?? (networks.contains(model.network) ? model.network : networks.first ?? model.network)
    }
    private var runs: [BenchmarkRun] { store.runs.filter { $0.network == scope }.sorted { $0.started > $1.started } }
    private var pingRanks: [ServerRank] { store.rankings(for: scope) }
    private var httpsRanks: [HTTPSServerRank] { store.httpsRankings(for: scope) }
    private func rankText(_ rank: ServerRank?) -> String {
        guard let rank else { return "측정값 없음" }
        guard let mean = rank.meanMS else { return "\(rank.host) · \(rank.sent)회 모두 무응답" }
        return String(format: "%@ · %.3f ms · 손실 %.1f%%", rank.host, mean, rank.lossPercent)
    }
    private func httpsRankText(_ rank: HTTPSServerRank) -> String {
        let upload = rank.uploadMbps.map { String(format: "%.1f Mbps", $0) } ?? "미측정"
        return String(format: "%@ · 다운로드 %.1f Mbps · 업로드 %@", rank.host, rank.downloadMbps, upload)
    }
    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker("기기·회선", selection: Binding(get: { scope }, set: { selected = $0 })) {
                        ForEach(networks, id: \.self) { entry in
                            Text("\(entry.label) · \(entry.interface)").tag(entry)
                        }
                    }
                }
                if let first = httpsRanks.first {
                    Section("동일 회선 HTTPS 순위") {
                        Text("다운로드 처리량 기준 · \(HTTPSBenchmarkSample.target)").font(.caption).foregroundStyle(.secondary)
                        if let latest = runs.lazy.compactMap({ $0.httpsRanks.first }).first {
                            VStack(alignment: .leading) { Text("최근 검사 1위").font(.caption); Text(httpsRankText(latest)) }
                        }
                        VStack(alignment: .leading) { Text("누적 1위").font(.caption); Text(httpsRankText(first)) }
                        ForEach(httpsRanks) { rank in
                            HStack { Text(httpsRankText(rank)); Spacer(); Text("\(rank.runCount)회").foregroundStyle(.secondary) }.font(.caption)
                        }
                    }
                }
                if !pingRanks.isEmpty {
                    Section("동일 회선 ping 순위") {
                        Text("터널 안에서 \(PingSample.target)로 서버당 20회 측정").font(.caption).foregroundStyle(.secondary)
                        if let latest = runs.first(where: { !$0.ranks.isEmpty }) {
                            VStack(alignment: .leading) {
                                Text("최근 \(latest.mode.displayName) · 1위").font(.caption)
                                Text(rankText(latest.ranks.first(where: { $0.received > 0 })))
                            }
                        }
                        VStack(alignment: .leading) { Text("누적 1위").font(.caption); Text(rankText(pingRanks.first(where: { $0.received > 0 }))) }
                        ForEach(pingRanks) { rank in
                            HStack { Text(rankText(rank)); Spacer(); Text("\(rank.runCount)회").foregroundStyle(.secondary) }.font(.caption)
                        }
                    }
                }
                Section("검사별 결과") {
                    ForEach(runs) { run in
                        DisclosureGroup {
                            if let msg = run.message { Text(msg).foregroundStyle(.secondary) }
                            if let fastest = run.httpsRanks.first {
                                LabeledContent("이번 다운로드 1위", value: fastest.host)
                            }
                            if let host = run.selectedHost {
                                LabeledContent(run.mode == .all && run.paired == true ? "사용자가 연결한 서버" : "연결한 서버", value: host)
                            }
                            ForEach(run.rows) { row in
                                VStack(alignment: .leading) {
                                    Text(row.host)
                                    if let ping = row.sample {
                                        let mean = ping.meanMS.map { String(format: "%.3f ms", $0) } ?? "응답 없음"
                                        Text("ping \(ping.received)/\(ping.sent) · \(mean) · 손실 \(ping.lossPercent.formatted())%")
                                    } else if row.httpsSample != nil {
                                        Text("ICMP 미측정")
                                    }
                                    if let speed = row.httpsSample {
                                        HTTPSMeasurementRow(host: HTTPSBenchmarkSample.target, sample: speed)
                                    }
                                    if let error = row.pingError { Text("ping · " + error) }
                                    if let error = row.httpsError { Text("FAST · " + error) }
                                    if row.sample == nil && row.httpsSample == nil {
                                        Text([row.outcome.displayName, row.detail].compactMap { $0 }.joined(separator: " · "))
                                    }
                                }.font(.caption)
                            }
                        } label: { Text("\(run.started.formatted(date:.abbreviated,time:.shortened)) · \(run.mode.displayName) · \(run.phase.displayName)") }
                    }
                }
                if !failure.isEmpty { Text(failure) }
            }.navigationTitle("측정 기록")
             .toolbar { Button { exporting = true } label: { Label("현재 회선 CSV 내보내기", systemImage: "square.and.arrow.up") } }
             .fileExporter(isPresented: $exporting, document: CSVReport(store.csv(network: scope)), contentType: .commaSeparatedText,
                           defaultFilename: "CoreaVPN-측정기록") { result in
                 if case .failure(let error) = result { failure = error.localizedDescription }
             }
        }
    }
}
