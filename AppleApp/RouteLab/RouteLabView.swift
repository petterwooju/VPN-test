import SwiftUI
import Darwin

private enum EchoCheck {
    static func address(_ input: String) -> String? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        var a4 = in_addr(), a6 = in6_addr()
        if inet_pton(AF_INET, text, &a4) == 1, inet_ntop(AF_INET, &a4, &output, socklen_t(output.count)) != nil {
            return String(cString: output)
        }
        if inet_pton(AF_INET6, text, &a6) == 1, inet_ntop(AF_INET6, &a6, &output, socklen_t(output.count)) != nil {
            return String(cString: output)
        }
        return nil
    }
    static func observed(_ url: URL) async throws -> String {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForResource = 10
        config.urlCache = nil; config.httpShouldSetCookies = false; config.urlCredentialStorage = nil
        let session = URLSession(configuration: config, delegate: SameDestination(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 10)
        request.setValue("application/json, text/plain", forHTTPHeaderField: "Accept")
        let (stream, response) = try await session.bytes(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw ClientIssue.message("HTTP 200 응답을 받지 못했습니다.") }
        var data = Data()
        for try await byte in stream {
            guard data.count < 4096 else { throw ClientIssue.message("출구 IP 응답이 4KB를 초과했습니다.") }
            data.append(byte)
        }
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let ip = (object["ip"] ?? object["origin"]) as? String, let normalized = address(ip) { return normalized }
        guard let text = String(data: data, encoding: .utf8), let normalized = address(text) else {
            throw ClientIssue.message("한 개의 IP 주소를 텍스트 또는 JSON ip 필드로 돌려주는 URL이 필요합니다.")
        }
        return normalized
    }
    private final class SameDestination: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    }
}

private struct ExitCheck: Identifiable {
    let id = UUID()
    var endpoint = ""
    var expected = ""
    var output = ""
}

struct RouteLabView: View {
    let document: RoutingDocument
    @Environment(\.dismiss) var dismiss
    @State private var checks = [ExitCheck(), ExitCheck(), ExitCheck()]
    @State private var checking = false
    @State private var task: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("테스트 URL에 HTTPS 요청을 보내 현재 출구 IP를 확인합니다. 각 URL은 요청자의 IP 한 개를 반환해야 합니다.")
                    Text("규칙 편집 화면의 예상 경로와 실제 네트워크에서 관측한 출구를 대조할 수 있습니다.").foregroundStyle(.secondary)
                }
                ForEach($checks) { $entry in
                    Section {
                        TextField("HTTPS 테스트 URL", text: $entry.endpoint)
                        TextField("예상 출구 IP", text: $entry.expected)
                        if !entry.output.isEmpty { Text(entry.output).font(.caption).textSelection(.enabled) }
                    }
                }
                Button(checking ? "검증 중…" : "현재 출구 확인") {
                    task = Task { await verify() }
                }.disabled(checking || checks.allSatisfy { $0.endpoint.isEmpty })
            }
            .disabled(checking)
            #if os(macOS)
            .formStyle(.grouped).frame(minWidth: 500, minHeight: 440)
            #endif
            .navigationTitle("경로 검증")
            .toolbar { Button("닫기") { task?.cancel(); dismiss() } }
            .onDisappear { task?.cancel() }
        }
    }

    @MainActor private func verify() async {
        checking = true
        defer { checking = false }
        for i in checks.indices {
            checks[i].output = ""
            let entry = checks[i]
            guard !entry.endpoint.isEmpty else { continue }
            do {
                try Task.checkCancellation()
                guard let url = URL(string: entry.endpoint), url.scheme?.lowercased() == "https", let host = url.host,
                      url.user == nil, url.password == nil, url.fragment == nil else { throw ClientIssue.message("유효한 HTTPS URL을 입력해 주세요.") }
                let expected = EchoCheck.address(entry.expected)
                guard expected != nil || entry.expected.isEmpty else { throw ClientIssue.message("예상 출구 IP 형식을 확인해 주세요.") }
                var q = RouteQuery(); q.domain = host; q.port = url.port ?? 443; q.ip = EchoCheck.address(host) ?? ""
                let routing = document.preview(q)
                if routing.match?.policy == .reject && routing.undecided.isEmpty { throw ClientIssue.message("REJECT 규칙이 일치하여 요청을 중단했습니다.") }
                let route = routing.undecided.isEmpty ? (routing.match?.policy.title ?? "일치하는 규칙 없음") : "추가 조건 확인 필요"
                let ip = try await EchoCheck.observed(url)
                let status = expected.map { $0 == ip ? "예상 IP와 일치" : "예상 IP와 다름" } ?? "관측"
                checks[i].output = "규칙: \(route)\n출구: \(ip) · \(status)"
            } catch is CancellationError { return }
            catch { checks[i].output = error.localizedDescription }
        }
    }
}
