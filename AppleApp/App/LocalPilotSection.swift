#if os(macOS)
import AppKit
import SwiftUI

struct LocalPilotSection: View {
    @ObservedObject var model: SessionModel
    @ObservedObject var pilot: LocalPilot
    @AppStorage(LocalMeasurement.preferenceKey) private var measurement = LocalMeasurement.https
    @State private var importRequest: ImportRequest?
    @State private var importMessage = ""
    @AppStorage("pumaLaunchNetwork.v1") private var launchData = Data()
    private struct Launch: Codable {
        let folder: String
        let network: BenchmarkNetwork
    }

    private struct ImportRequest: Identifiable {
        let id: URL
        let network: BenchmarkNetwork
    }

    var body: some View {
        Section("CoreaVPN_TEST로 Puma 측정") {
            Picker("Puma 측정 방식", selection: $measurement) {
                ForEach(LocalMeasurement.allCases, id: \.self) { method in
                    Text(method.title).tag(method)
                }
            }
            .accessibilityIdentifier("measurement-method")
            .disabled(pilot.running || model.busy)
            Button {
                importMessage = ""
                if let request = pilot.start(measurement: measurement), model.link.available, !model.network.label.isEmpty {
                    launchData = (try? JSONEncoder().encode(Launch(folder: request.uuidString + "-puma-pilot", network: model.network))) ?? Data()
                }
            } label: {
                Label("Puma 연결 · \(measurement.title) 측정 · FlClash 복구", systemImage: "waveform.path.ecg")
            }.disabled(!pilot.available || pilot.running || model.busy)
            if pilot.running {
                Button {
                    pilot.stopMeasurement()
                } label: {
                    Label("검사 중지", systemImage: "stop.circle")
                }
                .accessibilityIdentifier("puma-stop")
                .disabled(!pilot.canStop)
            }
            Text("Terminal의 관리자 인증 후 검사를 시작합니다. 검사 중에는 Mac을 잠금 해제하고 FlClash와 VPN 창을 열어 두세요.")
                .font(.caption).foregroundStyle(.secondary)
            if !pilot.status.isEmpty { Text(pilot.status).textSelection(.enabled) }
            if let result = pilot.latest {
                LabeledContent("실행 기록", value: result.directory.lastPathComponent)
                if let sample = result.httpsSample {
                    HTTPSMeasurementRow(host: HTTPSBenchmarkSample.target, sample: sample)
                } else if let sample = result.sample {
                    LabeledContent("ping 응답", value: "\(sample.received)/\(sample.sent) · 손실 \(sample.lossPercent.formatted())%")
                    if let mean = sample.meanMS {
                        LabeledContent("평균 지연", value: String(format: "%.3f ms", mean))
                    }
                }
                if let recovered = result.recovered {
                    LabeledContent("FlClash 복구", value: recovered ? "확인됨" : "복구 기록 확인 필요")
                }
                if let route = result.finalRoute { LabeledContent("종료 시 경로", value: route) }
                HStack {
                    Button("실행 폴더 열기") { NSWorkspace.shared.open(result.directory) }
                    if result.importable && result.recovered == true && !pilot.running {
                        Button("현재 회선 기록에 추가") {
                            importMessage = ""
                            let network = model.network
                            guard model.link.available, result.interface == network.interface else {
                                importMessage = "기록을 측정한 Mac의 물리 회선에서 추가할 수 있습니다."
                                return
                            }
                            guard !network.label.isEmpty else {
                                importMessage = "설정에서 현재 회선 이름을 먼저 입력해 주세요."
                                return
                            }
                            importRequest = ImportRequest(id: result.directory, network: network)
                        }
                    }
                }
                if !importMessage.isEmpty { Text(importMessage).font(.caption) }
            }
        }
        .onAppear { pilot.refresh() }
        .onChange(of: model.network) { _, _ in saveLaunch(pilot.latest) }
        .onReceive(pilot.$latest) { saveLaunch($0) }
        .alert(item: $importRequest) { request in
            Alert(title: Text("이 Mac의 ‘\(request.network.label)’에서 측정했습니까?"),
                  message: Text(request.id.lastPathComponent + " 검사 결과를 이 회선의 누적 순위에 반영합니다."),
                  primaryButton: .default(Text("기록 추가")) {
                      do {
                          guard model.link.available, model.network == request.network else { throw BenchmarkError.wrongNetwork }
                          let added = try model.store.importLocalPuma(from: request.id, into: request.network)
                          importMessage = added ? "측정 기록에 추가했습니다." : "이미 추가한 기록입니다."
                      } catch { importMessage = error.localizedDescription }
                  }, secondaryButton: .cancel(Text("취소")))
        }
    }
    private func saveLaunch(_ result: LocalPilotResult?) {
        guard let launch = try? JSONDecoder().decode(Launch.self, from: launchData),
              let result, result.importable, result.recovered == true, result.directory.lastPathComponent == launch.folder,
              result.interface == launch.network.interface, model.link.available, model.network == launch.network else { return }
        do {
            _ = try model.store.importLocalPuma(from: result.directory, into: launch.network)
            launchData = Data()
            importMessage = "‘" + launch.network.label + "’ 측정 기록에 저장했습니다."
        } catch { importMessage = error.localizedDescription }
    }
}
#endif
