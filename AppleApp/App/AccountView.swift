import SwiftUI
import UniformTypeIdentifiers

struct AccountView: View {
    @ObservedObject var model: SessionModel
    @State private var user = ""
    @State private var password = ""
    @State private var importing = false
    @State private var binding = false
    @State private var note = ""
    var body: some View {
        NavigationStack {
            Form {
                Section("CoreaVPN 계정") {
                    TextField("사용자 이름", text: $user)
                    SecureField("암호", text: $password)
                    Button("이 기기의 Keychain에 저장") {
                        do { try model.saveAccount(user, password); password = ""; note = "계정을 저장했습니다." }
                        catch { note = error.localizedDescription }
                    }.disabled(model.busy || user.isEmpty || password.isEmpty)
                    Button("VPN 구성 최초 승인") { Task { await model.authorize(); note = model.message } }
                        .disabled(model.busy || model.credentialName.isEmpty)
                    Button("공식 IKEv2 프로필 가져오기") { importing = true }
                        .disabled(model.busy || model.credentialName.isEmpty)
                    if !model.sharedHosts.isEmpty {
                        Text(model.sharedHosts.sorted().joined(separator: ", ")).font(.caption).foregroundStyle(.secondary)
                    }
                }
                .disabled(model.previewBuild)
                Section("회선과 사용 가능 서버") {
                    LabeledContent("물리 인터페이스", value: model.link.available ? model.link.interface : "확인 중")
                    TextField("회선 이름 (예: 베이징 사무실)", text: $model.routeLabel)
                        .onChange(of: model.routeLabel) { _,_ in model.saveSettings() }
                    Toggle("D/E 그룹 사용 가능한 계정", isOn: $model.allowDE)
                        .onChange(of: model.allowDE) { _,_ in model.saveSettings() }
                    Picker("다른 기기가 사용하는 그룹", selection: $model.excludedGroup) {
                        Text("없음").tag("")
                        ForEach(["A","B","C","D","E"], id: \.self) { Text($0).tag($0) }
                    }.onChange(of: model.excludedGroup) { _,_ in model.saveSettings() }
                    #if os(macOS)
                    if model.link.interface == "en6", model.link.transport == "ethernet" {
                        Button("기존 베이징 유선 기록을 현재 회선에 연결") { binding = true }
                            .disabled(model.routeLabel.isEmpty)
                    }
                    #endif
                }.disabled(model.busy)
                if !model.previewBuild { Section("Puma 점검") {
                    Button("Puma 연결 · ping 20회 · 복구") { Task { await model.start(.puma); note = model.message } }
                        .disabled(model.busy || model.credentialName.isEmpty)
                } }
                if !note.isEmpty { Text(note).textSelection(.enabled) }
            }
            #if os(macOS)
            .formStyle(.grouped)
            #endif
            .navigationTitle("설정")
            .onAppear { if user.isEmpty { user = model.credentialName } }
            .onChange(of: model.credentialName) { _,name in if user.isEmpty { user = name } }
            .alert("2026년 11월 25일 측정한 Mac과 사무실 유선망이 맞습니까?", isPresented: $binding) {
                Button("현재 회선에 연결") { model.bindBaseline(); note = model.message }
                Button("취소", role: .cancel) {}
            }
            .fileImporter(isPresented: $importing, allowedContentTypes: [.data]) { result in
                do {
                    let file = try result.get()
                    let access = file.startAccessingSecurityScopedResource()
                    defer { if access { file.stopAccessingSecurityScopedResource() } }
                    let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard (1...2_000_000).contains(size) else { throw ClientIssue.message("2MB 이하의 공식 프로필을 선택해 주세요.") }
                    let host = try model.importOfficial(Data(contentsOf: file))
                    note = "\(host) 공식 인증 설정을 저장했습니다."
                } catch { note = error.localizedDescription }
            }
        }
    }
}
