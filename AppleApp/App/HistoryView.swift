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
        switch self { case .direct: return "서버 바로 연결"; case .all: return "전체 검사"; case .quick: return "빠른 연결"; case .fastQuick: return "FAST 다운로드 빠른 연결"; case .puma: return "Puma 점검" }
    }
}
extension ScanPhase {
    var displayName: String {
        switch self { case .retained: return "연결 유지"; case .completed: return "완료"; case .cancelled: return "취소"; case .failed: return "실패"; case .paused: return "일시 정지"; case .scanning: return "진행 중" }
    }
}

extension BenchmarkAttempt {
    var downloadFailed: Bool {
        httpsSample?.downloadMbps == nil && httpsError?.contains("다운로드") == true
    }
}

struct HTTPSMeasurementRow: View {
    let host: String
    let sample: HTTPSBenchmarkSample
    var downloadFailed = false

    private func speed(_ value: Double?) -> String { value.map { String(format: "%.1f Mbps", $0) } ?? "측정값 없음" }
    private func latency(_ value: Double?) -> String { value.map { String(format: "%.1f ms", $0) } ?? "측정값 없음" }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(host)
            Text("다운로드 \(downloadFailed ? "측정 실패" : speed(sample.downloadMbps)) · 업로드 \(speed(sample.uploadMbps))")
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
    #if os(macOS)
    @State private var tab = HistoryTab.scan
    @State private var ranking = RankingKind.ping
    @State private var selectedRun: UUID?

    private enum HistoryTab: String, CaseIterable {
        case scan = "이번 검사"
        case ranking = "누적 순위"
    }

    private enum RankingKind: String, CaseIterable {
        case ping = "ping"
        case https = "FAST"
    }
    #endif

    private var networks: [BenchmarkNetwork] {
        let known = store.runs.reversed().reduce(into: [BenchmarkNetwork]()) { items, run in
            if !items.contains(run.network) { items.append(run.network) }
        }
        #if os(macOS)
        if model.link.available && !known.contains(model.network) { return [model.network] + known }
        #endif
        return known
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
        #if os(macOS)
        macHistory
            .fileExporter(isPresented: $exporting, document: CSVReport(store.csv(network: scope)), contentType: .commaSeparatedText,
                          defaultFilename: "CoreaVPN-측정기록") { result in
                if case .failure(let error) = result { failure = error.localizedDescription }
            }
        #else
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
                                        HTTPSMeasurementRow(host: HTTPSBenchmarkSample.target, sample: speed,
                                                            downloadFailed: row.downloadFailed)
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
        #endif
    }

    #if os(macOS)
    private var selectedScan: BenchmarkRun? {
        runs.first { $0.id == selectedRun } ?? runs.first { $0.mode != .direct } ?? runs.first
    }

    private var macHistory: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 12) {
                ViewThatFits(in: .horizontal) {
                    HStack { heading; Spacer(minLength: 12); exportButton }
                    VStack(alignment: .leading, spacing: 8) { heading; exportButton }
                }
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 14) { networkPicker; Spacer(minLength: 0); tabPicker }
                    VStack(alignment: .leading, spacing: 10) { networkPicker; tabPicker }
                }
                if !failure.isEmpty {
                    Label(failure, systemImage: "exclamationmark.circle").foregroundStyle(.red).font(.callout)
                }
            }
            .padding(.horizontal, 20).padding(.vertical, 14)
            Divider()
            if runs.isEmpty {
                ContentUnavailableView("이 회선의 측정 기록 없음", systemImage: "clock")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List {
                    if tab == .scan { scanContent } else { rankingContent }
                }
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .controlSize(.large)
    }

    private var heading: some View {
        Text("측정 기록").font(.system(size: 27, weight: .bold))
            .accessibilityAddTraits(.isHeader)
    }

    private var exportButton: some View {
        Button {
            failure = ""
            exporting = true
        } label: {
            Label("선택 회선 CSV", systemImage: "square.and.arrow.up")
        }
        .disabled(runs.isEmpty)
        .help("선택한 기기와 회선의 모든 측정 기록 내보내기")
        .accessibilityIdentifier("history-export")
    }

    private var networkPicker: some View {
        Picker("기기·회선", selection: Binding(get: { scope }, set: { network in
            selected = network
            selectedRun = nil
            failure = ""
        })) {
            ForEach(networks.isEmpty ? [scope] : networks, id: \.self) { network in
                Text(networkTitle(network)).tag(network)
            }
        }
        .pickerStyle(.menu)
        .accessibilityIdentifier("history-network")
    }

    private var tabPicker: some View {
        Picker("기록 보기", selection: $tab) {
            ForEach(HistoryTab.allCases, id: \.self) { view in Text(view.rawValue).tag(view) }
        }
        .labelsHidden()
        .pickerStyle(.segmented)
        .fixedSize()
        .accessibilityIdentifier("history-view")
    }

    private func networkTitle(_ network: BenchmarkNetwork) -> String {
        let device: String
        if network.deviceID == model.deviceID { device = "이 Mac" }
        else if network == .beijingReference { device = "기준선" }
        else { device = "기기 \(network.deviceID.prefix(8))" }
        let label = network.label.isEmpty ? "이름 없는 회선" : network.label
        var parts = [device, label, network.interface].filter { !$0.isEmpty }
        if networks.contains(where: { $0 != network && $0.deviceID == network.deviceID &&
                                      $0.label == network.label && $0.interface == network.interface }) {
            parts.append(network.fingerprint ?? (network.transport.isEmpty ? "식별 정보 없음" : network.transport))
        }
        return parts.joined(separator: " · ")
    }

    @ViewBuilder private var scanContent: some View {
        if let run = selectedScan {
            Section {
                Picker("검사 기록", selection: Binding(get: { selectedScan?.id }, set: { selectedRun = $0 })) {
                    ForEach(runs) { entry in
                        Text(entry.started.formatted(date: .abbreviated, time: .shortened) + " · " + entry.mode.displayName)
                            .tag(Optional(entry.id))
                    }
                }.accessibilityIdentifier("history-scan")
                LabeledContent("상태", value: run.phase.displayName)
                let measured = run.rows.filter { $0.sample != nil || $0.httpsSample != nil }.count
                if run.mode != .direct { LabeledContent("측정값이 있는 서버", value: "\(measured)개") }
                if let fastest = run.httpsRanks.first {
                    LabeledContent("이번 다운로드 1위", value: fastest.host)
                }
                if let host = run.selectedHost { LabeledContent("연결한 서버", value: host) }
                if let msg = run.message, !msg.isEmpty { Text(msg).foregroundStyle(.secondary) }
            }

            Section("서버별 결과") {
                if run.rows.isEmpty { Text("저장된 서버 결과가 없습니다.").foregroundStyle(.secondary) }
                ForEach(run.rows) { row in
                    DisclosureGroup {
                        attemptDetails(row)
                    } label: {
                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 12) {
                                Text(row.host).font(.system(.body, design: .monospaced)).fixedSize(horizontal: true, vertical: false)
                                Spacer(minLength: 0)
                                Text(attemptSummary(row)).fixedSize(horizontal: true, vertical: false)
                                    .font(.caption).monospacedDigit().foregroundStyle(.secondary)
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                Text(row.host).font(.system(.body, design: .monospaced))
                                Text(attemptSummary(row)).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 3)
                    }
                }
            }
            .id(run.id)
        }
    }

    private func attemptSummary(_ row: BenchmarkAttempt) -> String {
        var parts = [String]()
        if let ping = row.sample {
            let mean = ping.meanMS.map { String(format: "%.1f ms", $0) } ?? "응답 없음"
            parts.append("ping \(mean) (\(ping.received)/\(ping.sent))")
        }
        if let down = row.httpsSample?.downloadMbps {
            parts.append("FAST " + String(format: "%.1f Mbps", down))
        } else if row.downloadFailed {
            parts.append("FAST 다운로드 실패")
        }
        return parts.isEmpty ? row.outcome.displayName : parts.joined(separator: " · ")
    }

    @ViewBuilder private func attemptDetails(_ row: BenchmarkAttempt) -> some View {
        Text(row.time, format: .dateTime.year().month().day().hour().minute().second())
            .font(.caption).foregroundStyle(.secondary)
        if let ping = row.sample {
            let mean = ping.meanMS.map { String(format: "%.3f ms", $0) } ?? "응답 없음"
            Text("ping \(ping.received)/\(ping.sent) · \(mean) · 손실 \(ping.lossPercent.formatted())%")
        } else if row.httpsSample != nil && row.pingError == nil {
            Text("ICMP 미측정")
        }
        if let speed = row.httpsSample {
            HTTPSMeasurementRow(host: HTTPSBenchmarkSample.target, sample: speed, downloadFailed: row.downloadFailed)
        }
        if let error = row.pingError { Text("ping · " + error) }
        if let error = row.httpsError { Text("FAST · " + error) }
        if let error = row.selectionError { Text("연결 · " + error) }
        if let detail = row.detail, !detail.isEmpty { Text(detail).foregroundStyle(.secondary) }
    }

    @ViewBuilder private var rankingContent: some View {
        let ranks = ranking == .ping ? makePingRows() : makeHTTPSRows()
        Section {
            Picker("측정 방식", selection: $ranking) {
                ForEach(RankingKind.allCases, id: \.self) { kind in Text(kind.rawValue).tag(kind) }
            }
            .pickerStyle(.segmented)
            .fixedSize()
            .accessibilityIdentifier("history-rank-method")
            Text(ranking == .ping ? "손실률이 낮은 순 · 같으면 평균 ping이 낮은 순" : "성공한 FAST 다운로드의 평균 속도가 높은 순")
                .font(.caption).foregroundStyle(.secondary)
        }
        Section("이 회선의 누적 순위") {
            if ranks.isEmpty { Text("순위에 포함할 측정값이 없습니다.").foregroundStyle(.secondary) }
            ForEach(Array(ranks.enumerated()), id: \.element.host) { index, row in
                HStack(alignment: .top, spacing: 12) {
                    Text("\(index + 1)").monospacedDigit().foregroundStyle(.secondary)
                        .frame(width: 24, alignment: .trailing)
                        .accessibilityLabel("\(index + 1)위")
                    VStack(alignment: .leading, spacing: 4) {
                        Text(row.host).font(.system(.body, design: .monospaced))
                            .lineLimit(1).truncationMode(.middle)
                        row.metadata
                    }
                    Spacer(minLength: 8)
                    Text(row.metrics).font(.callout).monospacedDigit().multilineTextAlignment(.trailing)
                }
                .padding(.vertical, 2)
            }
        }
    }

    private struct RankingRow {
        let host: String
        let metrics: String
        let count: Int
        let lastMeasuredAt: Date?

        var metadata: some View {
            let date = lastMeasuredAt?.formatted(date: .abbreviated, time: .shortened) ?? "—"
            return Text("\(count)회 · 마지막 측정 \(date)").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func makePingRows() -> [RankingRow] {
        let latest = lastDates { $0.sample != nil }
        return pingRanks.map { rank in
            let mean = rank.meanMS.map { String(format: "%.1f ms", $0) } ?? "응답 없음"
            let loss = String(format: "%.1f%%", rank.lossPercent)
            return RankingRow(host: rank.host, metrics: "\(mean) · 손실 \(loss)", count: rank.runCount, lastMeasuredAt: latest[rank.host])
        }
    }

    private func makeHTTPSRows() -> [RankingRow] {
        let latest = lastDates { $0.httpsSample?.valid == true && $0.httpsSample?.downloadMbps != nil &&
            ($0.httpsSample?.downloadBytes ?? 0) > 0 }
        return httpsRanks.map { rank in
            let download = String(format: "%.1f Mbps", rank.downloadMbps)
            let upload = rank.uploadMbps.map { String(format: "%.1f Mbps", $0) } ?? "미측정"
            return RankingRow(host: rank.host, metrics: "다운 \(download) · 업 \(upload)", count: rank.runCount,
                              lastMeasuredAt: latest[rank.host])
        }
    }

    private func lastDates(where included: (BenchmarkAttempt) -> Bool) -> [String: Date] {
        runs.lazy.flatMap(\.rows).filter(included).reduce(into: [:]) { dates, row in
            dates[row.host] = max(dates[row.host] ?? .distantPast, row.time)
        }
    }
    #endif
}
