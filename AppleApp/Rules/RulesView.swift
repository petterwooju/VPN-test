import Foundation
import SwiftUI
import UniformTypeIdentifiers
#if os(macOS)
import AppKit
#endif

private struct RulesFile: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    let content: Data
    init(_ content: Data) { self.content = content }
    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else { throw CocoaError(.fileReadCorruptFile) }
        content = data
    }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: content) }
}

private struct RuleEditorRequest: Identifiable {
    var rule: RoutingRule
    var isNew: Bool
    var priority: Int
    var id: UUID { rule.id }
}

struct RulesView: View {
    #if os(macOS)
    private let focusedRuleID: UUID?
    @State private var activeRuleID: UUID?

    init(focusedRuleID: UUID? = nil) {
        self.focusedRuleID = focusedRuleID
        _activeRuleID = State(initialValue: focusedRuleID)
    }
    #endif
    @State private var document = RoutingDocument()
    @State private var hasLoaded = false
    @State private var loadFailed = false
    @State private var filter = ""
    @State private var onlyIssues = false
    @State private var editor: RuleEditorRequest?
    @State private var importer = false
    @State private var exporter = false
    @State private var exportFile: RulesFile?
    @State private var showPreview = false
    @State private var showRouteLab = false
    @State private var importCandidate: RoutingDocument?
    @State private var showImport = false
    @State private var errorText: String?
    @State private var confirmDeletion: RoutingRule?
    @State private var busy = false

    static var storage: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CoreaVPN", isDirectory: true).appendingPathComponent("routing-v1.json")
    }

    var body: some View {
        let names = document.knownTargets
        let rows = document.rules.enumerated().compactMap { index, rule -> RuleRow? in
            #if os(macOS)
            if let activeRuleID, rule.id != activeRuleID { return nil }
            #endif
            let issue = rule.issue(groups: names, supportsProcess: RoutingDocument.supportsProcess)
            if !showsTrackedRule {
                guard !onlyIssues || issue != nil,
                      filter.isEmpty || rule.displayText.localizedCaseInsensitiveContains(filter) ||
                        rule.policy.title.localizedCaseInsensitiveContains(filter) else { return nil }
            }
            return RuleRow(position: index + 1, rule: rule, issue: issue)
        }
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("라우팅 규칙").font(.title2.bold())
                Spacer()
                Button { showPreview = true } label: { Label("미리보기", systemImage: "magnifyingglass") }
                    .disabled(document.rules.isEmpty)
                Menu {
                    Button("경로 검증") { showRouteLab = true }
                    #if os(macOS)
                    Button("이 Mac의 FlClash 설정 선택…") { chooseActiveFlClash() }
                    #endif
                    Button("FlClash 설정 또는 규칙 파일 가져오기") { importer = true }
                    Button("공유용 규칙 JSON 내보내기") {
                        do {
                            exportFile = RulesFile(try JSONEncoder().encode(document))
                            exporter = true
                        } catch { errorText = error.localizedDescription }
                    }.disabled(document.rules.isEmpty)
                } label: { Image(systemName: "square.and.arrow.up.on.square") }.accessibilityLabel("규칙 파일")
            }
            #if os(macOS) && DIRECT_ROUTING
            MacRoutingControls(document: document)
            #else
            Text("규칙 편집 및 경로 미리보기 · 실제 트래픽 분리 미적용")
                .font(.subheadline).foregroundStyle(.secondary)
            #endif
            #if os(macOS)
            if showsTrackedRule {
                HStack {
                    Label("실시간 연결에서 선택한 규칙", systemImage: "link")
                    Spacer()
                    Button("전체 규칙 보기") { activeRuleID = nil }
                }.accessibilityIdentifier("tracked-routing-rule")
            } else {
                searchBar(resultCount: rows.count)
            }
            #else
            searchBar(resultCount: rows.count)
            #endif
            if busy { ProgressView("설정을 읽는 중") }
            if showsTrackedRule && hasLoaded && rows.isEmpty {
                ContentUnavailableView("현재 저장된 규칙에서 찾을 수 없습니다", systemImage: "link",
                                       description: Text("실시간 연결에 사용된 규칙을 찾으려면 해당 규칙 파일을 확인하세요."))
            } else if document.rules.isEmpty {
                Spacer()
                Button("FlClash 설정 가져오기") { importer = true }.frame(maxWidth: .infinity)
                Spacer()
            } else {
                List(rows) { row in
                    Button {
                        editor = RuleEditorRequest(rule: row.rule, isNew: false, priority: row.position)
                    } label: {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(alignment: .firstTextBaseline) {
                                Text("#\(row.position)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                                Text(row.rule.displayText).lineLimit(2)
                            }
                            #if os(macOS)
                            Text("예상 출구 · \(row.rule.policy.title)").font(.caption)
                            #else
                            Text(row.rule.policy.title).font(.caption)
                            #endif
                            if let reason = row.issue {
                                Label(reason, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                            }
                        }
                        #if os(macOS)
                        .padding(.vertical, 4)
                        #endif
                        .frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                    }.buttonStyle(.plain)
                }
            }
        }
        .padding()
        #if os(macOS)
        .controlSize(.large)
        .onChange(of: focusedRuleID) { _, value in activeRuleID = value }
        #endif
        .onAppear {
            guard !hasLoaded else { return }
            hasLoaded = true
            do {
                if FileManager.default.fileExists(atPath: Self.storage.path) {
                    document = try RoutingDocument.decode(Data(contentsOf: Self.storage))
                }
            } catch {
                loadFailed = true
                errorText = "저장된 규칙을 읽을 수 없습니다. 새 파일을 가져와 복원할 수 있습니다. " + error.localizedDescription
            }
        }
        .fileImporter(isPresented: $importer, allowedContentTypes: [.data], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                loadImport(url)
            case .failure(let error): if !Self.isCancelled(error) { errorText = error.localizedDescription }
            }
        }
        .fileExporter(isPresented: $exporter, document: exportFile, contentType: .json, defaultFilename: "CoreaVPN-rules") { result in
            if case let .failure(error) = result, !Self.isCancelled(error) { errorText = error.localizedDescription }
        }
        .sheet(item: $editor) { request in
            RuleEditorSheet(request: request, groups: document.groups.map(\.name), count: document.rules.count) { changed, priority in
                var draft = document
                draft.rules.removeAll { $0.id == changed.id }
                draft.rules.insert(changed, at: max(0, min(priority - 1, draft.rules.count)))
                save(draft)
            } delete: {
                editor = nil
                confirmDeletion = request.rule
            }
        }
        .sheet(isPresented: $showPreview) { RulePreviewSheet(document: document) }
        .sheet(isPresented: $showRouteLab) { RouteLabView(document: document) }
        .alert("가져온 규칙 적용", isPresented: $showImport, presenting: importCandidate) { candidate in
            Button("편집 목록 교체") { save(candidate); importCandidate = nil }
            Button("취소", role: .cancel) { importCandidate = nil }
        } message: { candidate in
            let names = candidate.knownTargets
            let issues = candidate.rules.filter { $0.issue(groups: names, supportsProcess: RoutingDocument.supportsProcess) != nil }.count
            let blocked = candidate.rules.filter { $0.policy == .reject }.count
            Text("규칙 \(candidate.rules.count)개, 그룹 \(candidate.groups.count)개, REJECT \(blocked)개, 확인할 조건·대상 \(issues)개입니다. 순서와 그룹 참조를 가져옵니다. 프록시 암호와 구독 주소는 복사하지 않습니다.")
        }
        .alert("이 규칙을 삭제할까요?", isPresented: Binding(get: { confirmDeletion != nil }, set: { if !$0 { confirmDeletion = nil } }), presenting: confirmDeletion) { rule in
            Button("삭제", role: .destructive) {
                var draft = document
                draft.rules.removeAll { $0.id == rule.id }
                save(draft)
                confirmDeletion = nil
            }
            Button("취소", role: .cancel) { confirmDeletion = nil }
        } message: { Text($0.displayText) }
        .alert("규칙 파일", isPresented: Binding(get: { errorText != nil }, set: { if !$0 { errorText = nil } })) {
            Button("확인") { errorText = nil }
        } message: { Text(errorText ?? "") }
    }

    private var showsTrackedRule: Bool {
        #if os(macOS)
        activeRuleID != nil
        #else
        false
        #endif
    }

    private func searchBar(resultCount: Int) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                TextField("도메인, 조건 또는 정책 검색", text: $filter).textFieldStyle(.roundedBorder)
                Button { onlyIssues.toggle() } label: {
                    Image(systemName: onlyIssues ? "line.3.horizontal.decrease.circle.fill" : "line.3.horizontal.decrease.circle")
                }.accessibilityLabel("확인할 규칙만 보기")
                Button {
                    let position = (document.rules.firstIndex(where: { $0.kind == "MATCH" }) ?? document.rules.count) + 1
                    editor = RuleEditorRequest(rule: RoutingRule(kind: "DOMAIN", value: "", policy: .direct), isNew: true, priority: position)
                } label: { Image(systemName: "plus") }.accessibilityLabel("규칙 추가").disabled(loadFailed)
            }
            Text("규칙 \(document.rules.count)개 · 프록시 그룹 \(document.groups.count)개 · 검색 결과 \(resultCount)개")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func save(_ draft: RoutingDocument) {
        do {
            let data = try JSONEncoder().encode(draft)
            try FileManager.default.createDirectory(at: Self.storage.deletingLastPathComponent(), withIntermediateDirectories: true)
            try data.write(to: Self.storage, options: .atomic)
            document = draft
            loadFailed = false
        } catch { errorText = error.localizedDescription }
    }

    private static func isCancelled(_ error: Error) -> Bool {
        let ns = error as NSError
        return ns.domain == NSCocoaErrorDomain && ns.code == NSUserCancelledError
    }

    #if os(macOS)
    private func chooseActiveFlClash() {
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectoryForUser(NSUserName()) ?? NSHomeDirectory())
            .appendingPathComponent("Library/Application Support/com.follow.clash")
        panel.prompt = "가져오기"
        panel.message = "현재 FlClash 규칙은 config.yaml에 있습니다."
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.begin { response in
            if response == .OK, let url = panel.url { loadImport(url) }
        }
    }
    #endif

    private func loadImport(_ url: URL) {
        guard !busy else { return }
        busy = true
        Task {
            do {
                let imported = try await Task.detached(priority: .userInitiated) {
                    let scope = url.startAccessingSecurityScopedResource()
                    defer { if scope { url.stopAccessingSecurityScopedResource() } }
                    let limit = 16 * 1024 * 1024
                    guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0) <= limit else {
                        throw RuleProblem.message("16MB 이하의 설정 파일을 선택해 주세요.")
                    }
                    let data = try Data(contentsOf: url)
                    guard data.count <= limit else { throw RuleProblem.message("파일이 16MB를 넘습니다.") }
                    if url.pathExtension.lowercased() == "json" { return try RoutingDocument.decode(data) }
                    guard let text = String(data: data, encoding: .utf8) else { throw RuleProblem.message("UTF-8 설정 파일이 필요합니다.") }
                    return try ClashRuleImport.parse(text)
                }.value
                importCandidate = imported
                showImport = true
            } catch { errorText = error.localizedDescription }
            busy = false
        }
    }

    private struct RuleRow: Identifiable {
        let position: Int
        let rule: RoutingRule
        let issue: String?
        var id: UUID { rule.id }
    }
}

private struct RuleEditorSheet: View {
    let request: RuleEditorRequest
    let groups: [String]
    let count: Int
    var save: (RoutingRule, Int) -> Void
    var delete: () -> Void
    @State private var rule: RoutingRule
    @State private var priority: String
    @State private var warning: String?
    @Environment(\.dismiss) private var dismiss

    init(request: RuleEditorRequest, groups: [String], count: Int, save: @escaping (RoutingRule, Int) -> Void, delete: @escaping () -> Void) {
        self.request = request
        self.groups = groups
        self.count = count
        self.save = save
        self.delete = delete
        _rule = State(initialValue: request.rule)
        _priority = State(initialValue: String(request.priority))
    }

    private var policies: [RoutingPolicy] {
        var all: [RoutingPolicy] = [.direct, .coreaVPN] + groups.map { .group($0) }
        if !all.contains(rule.policy) { all.append(rule.policy) }
        return all
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(request.isNew ? "규칙 추가" : "규칙 편집").font(.title2.bold())
            Form {
                if RoutingRule.editableKinds.contains(request.rule.kind) {
                    Picker("조건", selection: $rule.kind) {
                        ForEach(RoutingRule.editableKinds, id: \.self) { Text($0).tag($0) }
                    }
                    TextField("도메인 또는 IP 대역", text: $rule.value)
                } else {
                    Text(rule.displayText)
                }
                Picker(exitLabel, selection: $rule.policy) {
                    ForEach(policies, id: \.self) { Text($0.title).tag($0) }
                }
                TextField("우선순위 (1부터)", text: $priority)
                if let warning { Text(warning).foregroundStyle(.red) }
            }
            HStack {
                if !request.isNew {
                    Button("삭제", role: .destructive) { dismiss(); delete() }
                }
                Spacer()
                Button("취소") { dismiss() }
                Button("저장") {
                    do {
                        guard let pos = Int(priority), (1...max(1, count + (request.isNew ? 1 : 0))).contains(pos) else {
                            throw RuleProblem.message("목록 안의 우선순위 번호를 입력해 주세요.")
                        }
                        rule.value = rule.value.trimmingCharacters(in: .whitespacesAndNewlines)
                        if RoutingRule.editableKinds.contains(rule.kind) { try rule.validateEdit() }
                        if rule.kind != request.rule.kind, !["IP-CIDR", "IP-CIDR6"].contains(rule.kind) { rule.qualifiers = [] }
                        if rule != request.rule { rule.original = nil }
                        save(rule, pos)
                        dismiss()
                    } catch { warning = error.localizedDescription }
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        #if os(macOS)
        .controlSize(.large)
        .frame(minWidth: 410, minHeight: 250)
        #endif
    }

    private var exitLabel: LocalizedStringKey {
        #if os(macOS)
        "예상 출구"
        #else
        "연결 경로"
        #endif
    }
}

private struct RulePreviewSheet: View {
    let document: RoutingDocument
    @State private var query = RouteQuery()
    @State private var port = ""
    @State private var result: RoutePreview?
    @State private var error: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("규칙 경로 미리보기").font(.title2.bold())
            Form {
                TextField("도메인", text: $query.domain)
                TextField("목적지 IP", text: $query.ip)
                TextField("목적지 포트", text: $port)
                TextField("국가 코드 (GEOIP 검사 시)", text: $query.country)
                Picker("전송 방식", selection: $query.transport) {
                    Text("지정 안 함").tag("")
                    Text("TCP").tag("TCP")
                    Text("UDP").tag("UDP")
                }
                #if os(macOS)
                TextField("프로세스 이름", text: $query.processName)
                TextField("프로세스 경로", text: $query.processPath)
                #endif
            }
            if let error { Text(error).foregroundStyle(.red) }
            if let result {
                if !result.undecided.isEmpty {
                    Text("앞선 규칙 \(result.undecided.count)개를 판정할 수 없어 실제 경로가 달라질 수 있습니다. 첫 조건: \(result.undecided[0].displayText)")
                        .font(.callout).foregroundStyle(.orange)
                }
                if let rule = result.match {
                    #if os(macOS)
                    LabeledContent("예상 출구", value: rule.policy.title).textSelection(.enabled)
                    Text(rule.displayText).font(.callout).textSelection(.enabled)
                    #else
                    Text("\(rule.displayText) → \(rule.policy.title)").textSelection(.enabled)
                    #endif
                    if let issue = rule.issue(groups: document.knownTargets, supportsProcess: RoutingDocument.supportsProcess) {
                        Text(issue).foregroundStyle(.orange)
                    }
                } else { Text("확인된 일치 규칙 없음") }
            }
            HStack {
                Spacer()
                Button("닫기") { dismiss() }
                Button("경로 확인") {
                    var inputs = query
                    if !port.isEmpty, let n = Int(port), (0...65535).contains(n) { inputs.port = n }
                    else if !port.isEmpty { error = "포트는 0~65535 범위입니다."; result = nil; return }
                    guard inputs.hasInput else { error = "조회할 목적지나 조건을 입력해 주세요."; result = nil; return }
                    error = nil
                    result = document.preview(inputs)
                }.keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        #if os(macOS)
        .controlSize(.large)
        .frame(minWidth: 450, minHeight: 360)
        #endif
    }
}
