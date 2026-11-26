import SwiftUI
import UniformTypeIdentifiers

struct ProxyLeafSettings: View {
    @State private var catalog: ProxyLeafCatalog?
    @State private var group = ""
    @State private var member = ""
    @State private var name = ""
    @State private var pin = ""
    @State private var saved: [String: String] = [:]
    @State private var choosingFile = false
    @State private var message: String?
    private let store = ExperimentalProxyStore()
    private var members: [ImportedProxyLeaf] { catalog?.members(of: group) ?? [] }
    private var selected: ImportedProxyLeaf? { members.first { $0.name == member } }

    var body: some View {
        Form {
            Section("기존 프록시 그룹") {
                Button("원본 FlClash 설정 가져오기") { choosingFile = true }
                Text("사용할 그룹과 노드를 선택하십시오. 선택한 노드의 접속 정보는 이 기기의 키체인에 저장됩니다.")
                if let catalog {
                    Picker("그룹", selection: $group) {
                        ForEach(catalog.groups, id: \.name) { Text($0.name).tag($0.name) }
                    }
                    if members.isEmpty { Text("이 그룹에는 파일에 직접 정의된 노드가 없습니다.") }
                    else {
                        Picker("노드", selection: $member) {
                            ForEach(members, id: \.name) { node in Text("\(node.name) · \(node.kind)").tag(node.name) }
                        }
                    }
                }
                if let selected {
                    if selected.kind == "anytls" {
                        TextField("신뢰한 인증서의 서버 이름 (선택)", text: $name)
                        TextField("공급자가 제공한 SHA-256 인증서 지문 (선택)", text: $pin)
                    }
                    if let error = validationMessage(selected) {
                        Text(error).foregroundStyle(.secondary)
                    }
                    Button("이 그룹에 노드 저장") {
                        do {
                            try store.save(group: group, leaf: selected, verifiedName: name, trustedPin: pin)
                            saved = try store.selections()
                            message = "\(group) 그룹에 선택한 노드를 저장했습니다."
                        } catch { message = error.localizedDescription }
                    }.disabled(validationMessage(selected) != nil)
                }
            }
            if !saved.isEmpty {
                Section("저장된 그룹") {
                    ForEach(saved.keys.sorted(), id: \.self) { key in
                        LabeledContent(key, value: saved[key] ?? "")
                    }
                }
            }
            if let message { Text(message) }
        }
        .formStyle(.grouped)
        .onAppear { do { saved = try store.selections() } catch { message = error.localizedDescription } }
        .onChange(of: group) { member = members.first?.name ?? ""; clearOverrides() }
        .onChange(of: member) { clearOverrides() }
        .fileImporter(isPresented: $choosingFile, allowedContentTypes: [.data]) { result in
            do {
                let url = try result.get()
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                let file = try FileHandle(forReadingFrom: url)
                defer { try? file.close() }
                let data = try file.read(upToCount: 12 * 1024 * 1024 + 1) ?? Data()
                guard let text = String(data: data, encoding: .utf8) else { throw ProxyLeafError("UTF-8 YAML 파일이 필요합니다.") }
                let parsed = try ProxyLeafCatalog(text: text)
                catalog = parsed
                group = parsed.groups.first?.name ?? ""
                member = parsed.members(of: group).first?.name ?? ""
                clearOverrides()
            } catch { message = error.localizedDescription }
        }
    }

    private func clearOverrides() { name = ""; pin = ""; message = nil }
    private func validationMessage(_ leaf: ImportedProxyLeaf) -> String? {
        do { _ = try leaf.configuration(verifiedName: name, trustedPin: pin); return nil }
        catch { return error.localizedDescription }
    }
}
