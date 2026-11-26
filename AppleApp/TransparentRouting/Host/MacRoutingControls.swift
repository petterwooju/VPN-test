#if os(macOS) && DIRECT_ROUTING
import SwiftUI

struct MacRoutingControls: View {
    let document: RoutingDocument
    @EnvironmentObject private var routing: MacRouting
    @EnvironmentObject private var model: SessionModel
    @State private var chooseFile = false
    @State private var pickingCountries = false
    @State private var editGroups = false
    @State private var details = ""
    @State private var imported: ProxyLeafCatalog?
    @State private var leafName = ""
    @State private var certificateName = ""
    @State private var fingerprint = ""
    @State private var selections = UserDefaults.standard.dictionary(forKey: "routing.groupSelections") as? [String: String] ?? [:]

    var body: some View {
        HStack {
            Button(routing.enabled ? "변경된 규칙 적용" : "규칙 적용") { Task { await routing.apply(document: document, selections: selections, model: model) } }
                .disabled(routing.busy || document.rules.isEmpty || model.busy)
            Button("적용 해제") { Task { await routing.disable() } }.disabled(routing.busy || !routing.enabled)
            Button("프록시 그룹 설정") { editGroups = true }
            Text(routing.status).font(.caption).textSelection(.enabled)
        }
        .sheet(isPresented: $editGroups) {
            VStack(alignment: .leading) {
                Text("프록시 그룹 설정").font(.headline)
                Button("원본 FlClash 파일에서 노드를 키체인에 저장…") { pickingCountries = false; chooseFile = true }
                Button("GEOIP.dat에서 국가별 IP 범위 가져오기…") { pickingCountries = true; chooseFile = true }
                Form {
                    if let imported, imported.allLeaves.contains(where: { $0.kind == "anytls" }) {
                        Section("AnyTLS 인증서 확인") {
                            Picker("노드", selection: $leafName) {
                                Text("노드 선택").tag("")
                                ForEach(imported.allLeaves.filter { $0.kind == "anytls" }, id: \.name) { Text($0.name).tag($0.name) }
                            }
                            TextField("공급자가 확인한 인증서 이름", text: $certificateName)
                            TextField("공급자가 제공한 SHA-256 지문", text: $fingerprint)
                            Button("이 노드에 저장") {
                                guard let leaf = imported.allLeaves.first(where: { $0.name == leafName }) else { return }
                                do {
                                    try routing.importLeaf(leaf, name: certificateName, fingerprint: fingerprint)
                                    details = leafName + " 인증 설정을 저장했습니다."
                                } catch { details = error.localizedDescription }
                            }.disabled(leafName.isEmpty || (certificateName.isEmpty && fingerprint.isEmpty))
                        }
                    }
                    ForEach(document.groups.filter { $0.type.lowercased() == "select" }, id: \.name) { group in
                        Picker(group.name, selection: Binding(get: { selections[group.name] ?? group.members.first ?? "" }, set: {
                            selections[group.name] = $0; UserDefaults.standard.set(selections, forKey: "routing.groupSelections")
                        })) { ForEach(group.members, id: \.self) { Text($0).tag($0) } }
                    }
                }
                if !details.isEmpty { ScrollView { Text(details).textSelection(.enabled) }.frame(maxHeight: 120) }
                Button("닫기") { editGroups = false }
            }.onDisappear { imported = nil }.padding().frame(minWidth: 500, minHeight: 320)
            .fileImporter(isPresented: $chooseFile, allowedContentTypes: [.data]) { result in
                do {
                    let url = try result.get()
                    if pickingCountries {
                        try routing.importCountries(from: url, document: document)
                        details = "가져온 규칙에 필요한 국가별 IP 범위를 저장했습니다."
                        return
                    }
                    let scope = url.startAccessingSecurityScopedResource()
                    defer { if scope { url.stopAccessingSecurityScopedResource() } }
                    guard (try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? Int.max) <= 12 * 1024 * 1024 else {
                        throw ClientIssue.message("12MB 이하의 FlClash 설정을 선택해 주세요.")
                    }
                    let catalog = try ProxyLeafCatalog(text: String(contentsOf: url, encoding: .utf8))
                    imported = catalog; leafName = ""; certificateName = ""; fingerprint = ""
                    let result = try routing.importNodes(catalog)
                    details = (["키체인에 저장한 노드 \(result.saved)개"] + result.failures).joined(separator: "\n")
                } catch { details = error.localizedDescription }
            }
        }
    }
}
#endif
