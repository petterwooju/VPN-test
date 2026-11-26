#if os(macOS)
import Foundation
import Darwin
import CoreaSpeed

/// Fixed, authenticated Cloudflare endpoints. Each TLS socket is pinned to a public A
/// record and bound with IP_BOUND_IF to the IKEv2 interface before its TCP connect.
enum NativeSpeedProbe {
    private static let target = HTTPSBenchmarkSample.target

    private static func background<T>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
        let task = Task.detached(priority: .utility) {
            try Task.checkCancellation()
            return try work()
        }
        return try await withTaskCancellationHandler(operation: { try await task.value },
                                                     onCancel: { task.cancel() })
    }
    private static var now: Double { ProcessInfo.processInfo.systemUptime }

    private final class Lane: @unchecked Sendable {
        // A lane is used serially; idle latency and concurrent transfers each have their own lane.
        let handle: UnsafeMutablePointer<CSLane>
        init(_ name: String, _ index: UInt32, _ peer: String) throws {
            guard let handle = csOpen(name, index, peer, { _ in Task.isCancelled ? 1 : 0 }, nil) else {
                throw VPNNetworkError.message("FAST 측정 소켓을 터널에 연결할 수 없습니다.")
            }
            self.handle = handle
        }
        deinit { csClose(handle) }

        func request(size: Int = 0, payload: Data? = nil, timeout: Int) -> CSResult {
            let path = payload == nil ? "__down?bytes=\(size)&" : "__up?"
            let url = "https://\(target)/\(path)nonce=\(UUID().uuidString)"
            if let payload {
                return payload.withUnsafeBytes { csRequest(handle, url, payload.count, $0.baseAddress, timeout) }
            }
            return csRequest(handle, url, size, nil, timeout)
        }
    }

    private struct Transfer {
        let bytes: Int?
        let mbps: Double?
        let loadedMS: Double?
        let seconds: Double?
        var diagnostics: [HTTPSDownloadLane]? = nil
    }
    private static func mean(_ values: [Double]) -> Double? {
        values.isEmpty ? nil : values.reduce(0, +) / Double(values.count)
    }

    private static let downloadSize = 4 * 1024 * 1024

    static func completedDownloadBytes(_ total: Int, lanes: Int) -> Int? {
        lanes > 0 && total == lanes * downloadSize ? total : nil
    }

    static func diagnostic(_ result: CSResult, expected: Int, elapsed: Double) -> HTTPSDownloadLane.Phase {
        var reason = result.errorReason.map { String(cString: $0) }
        let category = result.errorType.map { String(cString: $0) }
        if category == "http_status", result.httpStatus > 0 { reason = "HTTP \(result.httpStatus)" }
        return HTTPSDownloadLane.Phase(status: result.success == 1 ? "complete" : "failed",
            stage: result.stage.map { String(cString: $0) } ?? "request", receivedBytes: result.receivedBytes,
            expectedBytes: expected, elapsedSeconds: elapsed, errorType: category, error: reason)
    }

    private static func phase(interface: String, index: UInt32, peer: String, upload: Bool, idle: Lane) async throws -> Transfer {
        let warmBytes = 65_536
        let warmups = await withTaskGroup(of: (Lane?, HTTPSDownloadLane).self) { group in
            for number in 1...4 {
                group.addTask {
                    let began = now
                    do {
                        return try await background {
                            let lane = try Lane(interface, index, peer)
                            let result = lane.request(size: warmBytes, timeout: 2000)
                            let report = diagnostic(result, expected: warmBytes, elapsed: now - began)
                            return (result.success == 1 ? lane : nil, HTTPSDownloadLane(lane: number, warmup: report))
                        }
                    } catch {
                        let report = HTTPSDownloadLane.Phase(status: "failed", stage: "setup", receivedBytes: 0,
                            expectedBytes: warmBytes, elapsedSeconds: now - began, errorType: "setup", error: error.localizedDescription)
                        return (nil, HTTPSDownloadLane(lane: number, warmup: report))
                    }
                }
            }
            var entries: [(Lane?, HTTPSDownloadLane)] = []
            for await entry in group { entries.append(entry) }
            return entries.sorted { $0.1.lane < $1.1.lane }
        }
        try Task.checkCancellation()
        let lanes = warmups.compactMap { lane, report in lane.map { (report.lane, $0) } }
        var diagnostics = warmups.map(\.1)
        guard !lanes.isEmpty else {
            return Transfer(bytes: 0, mbps: nil, loadedMS: nil, seconds: nil, diagnostics: upload ? nil : diagnostics)
        }

        // Four 256 KiB requests per upload lane; only server-acknowledged requests count.
        var payload: Data?
        if upload {
            var bytes = Data(count: 256 * 1024)
            bytes.withUnsafeMutableBytes { arc4random_buf($0.baseAddress!, $0.count) }
            payload = bytes
        }
        let uploadBody = payload
        let start = now
        let loaded = Task { () -> [(Double, Double)] in
            var samples: [(Double, Double)] = []
            while !Task.isCancelled && now - start < 6 {
                guard let reply = try? await background({ idle.request(timeout: 1000) }) else { break }
                if reply.success == 1 { samples.append((now, reply.responseMS)) }
                do { try await Task.sleep(nanoseconds: 75_000_000) } catch { break }
            }
            return samples
        }
        defer { loaded.cancel() }
        var bytes = 0, lastCompletion = start
        try await withThrowingTaskGroup(of: (Int, Double, Int, HTTPSDownloadLane.Phase?).self) { group in
            for (number, lane) in lanes {
                group.addTask {
                    try await background {
                        if let uploadBody {
                            var count = 0
                            for _ in 0..<4 {
                                let left = Int((start + 6 - now) * 1000)
                                guard left > 0, !Task.isCancelled else { break }
                                let result = lane.request(payload: uploadBody, timeout: left)
                                guard result.success == 1 else { break }
                                count += result.bytes
                            }
                            return (count, now, number, nil)
                        }
                        let left = Int((start + 6 - now) * 1000)
                        let began = now
                        let result = lane.request(size: downloadSize, timeout: left)
                        let end = now
                        return (result.bytes, end, number, diagnostic(result, expected: downloadSize, elapsed: end - began))
                    }
                }
            }
            for try await (count, end, number, report) in group {
                diagnostics[number - 1].transfer = report
                bytes += count
                lastCompletion = max(lastCompletion, end)
            }
        }
        loaded.cancel()
        let measuredLatencies = await loaded.value.filter { $0.0 <= lastCompletion }.map(\.1)
        try Task.checkCancellation()
        let duration = lastCompletion - start
        let completed = upload ? bytes : completedDownloadBytes(bytes, lanes: lanes.count)
        guard let completed, completed > 0, duration > 0 else {
            return Transfer(bytes: completed, mbps: nil, loadedMS: mean(measuredLatencies), seconds: nil, diagnostics: upload ? nil : diagnostics)
        }
        return Transfer(bytes: completed, mbps: Double(completed) * 8 / duration / 1_000_000,
                        loadedMS: mean(measuredLatencies), seconds: duration, diagnostics: upload ? nil : diagnostics)
    }

    @MainActor static func measure(interface: String, validate: @escaping (String) throws -> Void,
                                   checkpoint: @escaping (HTTPSBenchmarkSample) throws -> Void) async throws -> HTTPSBenchmarkSample {
        let index = if_nametoindex(interface)
        guard index > 0 else { throw VPNNetworkError.message("측정 터널을 찾을 수 없습니다.") }
        let peer = try await background {
            var address = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard csResolve(&address, address.count, { _ in Task.isCancelled ? 1 : 0 }, nil) == 1 else {
                try Task.checkCancellation()
                throw VPNNetworkError.message("FAST 측정 서버 DNS 조회에 실패했습니다.")
            }
            return String(cString: address)
        }
        guard VPNEndpoints.isPublicIPv4(peer) else { throw VPNNetworkError.message("측정 서버 공인 IPv4 주소가 필요합니다.") }
        func verify() throws {
            try Task.checkCancellation()
            guard if_nametoindex(interface) == index, try TunnelProbe.routeInterface(destination: peer) == interface else {
                throw VPNNetworkError.message("FAST 측정 대상의 VPN 경로가 변경되었습니다.")
            }
            try validate(peer)
        }
        try verify()
        let idle = try Lane(interface, index, peer)
        let idleResult = try await background { () -> (sent: Int, values: [Double]) in
            var values: [Double] = [], sent = 0
            for _ in 0..<20 {
                try Task.checkCancellation()
                let result = idle.request(timeout: 1000)
                sent += Int(result.requestSent)
                if result.success == 1 { values.append(result.responseMS) }
            }
            return (sent, values)
        }
        func sample(_ download: Transfer?, _ upload: Transfer?) -> HTTPSBenchmarkSample {
            HTTPSBenchmarkSample(sent: idleResult.sent, received: idleResult.values.count, averageMS: mean(idleResult.values),
                 downloadMbps: download?.mbps, uploadMbps: upload?.mbps, downloadLoadedMS: download?.loadedMS,
                 uploadLoadedMS: upload?.loadedMS, downloadBytes: download?.bytes, uploadBytes: upload?.bytes,
                 downloadSeconds: download?.seconds, uploadSeconds: upload?.seconds, peerIPv4: peer, downloadLanes: download?.diagnostics)
        }
        try verify()
        if idleResult.sent > 0 { try checkpoint(sample(nil, nil)) }
        let download = try await phase(interface: interface, index: index, peer: peer, upload: false, idle: idle)
        try verify()
        try checkpoint(sample(download, nil))
        let upload = try await phase(interface: interface, index: index, peer: peer, upload: true, idle: idle)
        try verify()
        return sample(download, upload)
    }
}
#endif
