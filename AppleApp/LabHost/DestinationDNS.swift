#if ROUTE_LAB
import Foundation
import dnssd
import Darwin

/// Resolves only the user-entered test destinations, through the normal system
/// resolver. A and AAAA snapshots have independent TTLs; neither is inferred.
enum DestinationDNS {
    struct Answer { let ip: String; let expires: Date? }

    static func addresses(for input: String) async throws -> [Answer] {
        let host = RoutingRule.normalizeDomain(input)
        guard !host.isEmpty else { throw SplitRouteError.invalid("목적지 주소를 입력해 주세요.") }
        if RoutingCIDR(host + (host.contains(":") ? "/128" : "/32")) != nil {
            return [Answer(ip: host, expires: nil)]
        }
        try RoutingRule(kind: "DOMAIN", value: host, policy: .direct).validateEdit()
        async let v4 = read(host, family: AF_INET)
        async let v6 = read(host, family: AF_INET6)
        let results = try await v4 + v6
        guard !results.isEmpty else { throw SplitRouteError.invalid("\(host)의 A/AAAA 응답이 없습니다.") }
        return results
    }

    private static func read(_ host: String, family: Int32) async throws -> [Answer] {
        let job = Query(host: host, family: family)
        return try await withTaskCancellationHandler(operation: {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in job.start(continuation) }
        }, onCancel: { job.cancel() })
    }

    // All DNS-SD state and cleanup is confined to one serial queue.
    private final class Query: @unchecked Sendable {
        let host: String, family: Int32
        let queue = DispatchQueue(label: "CoreaVPN.Lab.DNS")
        private var ref: DNSServiceRef?
        private var continuation: CheckedContinuation<[Answer], Error>?
        private var records: [String: Date] = [:]
        private var cancelled = false
        init(host: String, family: Int32) { self.host = host; self.family = family }
        func cancel() { queue.async { self.cancelled = true; self.finish(.failure(CancellationError())) } }
        func start(_ waiter: CheckedContinuation<[Answer], Error>) {
            queue.async {
                self.continuation = waiter
                if self.cancelled { self.finish(.failure(CancellationError())); return }
                let family = self.family == AF_INET ? kDNSServiceProtocol_IPv4 : kDNSServiceProtocol_IPv6
                let result = DNSServiceGetAddrInfo(&self.ref, 0, 0, UInt32(family), self.host + ".", {
                    _, flags, _, error, _, address, ttl, context in
                    guard let context else { return }
                    let job = Unmanaged<Query>.fromOpaque(context).takeUnretainedValue()
                    job.update(flags: flags, error: error, address: address, ttl: ttl)
                }, Unmanaged.passUnretained(self).toOpaque())
                guard result == 0, let ref = self.ref, DNSServiceSetDispatchQueue(ref, self.queue) == 0 else {
                    self.finish(.failure(SplitRouteError.invalid("\(self.host) DNS 요청을 시작하지 못했습니다."))); return
                }
                self.queue.asyncAfter(deadline: .now() + 6) {
                    self.finish(.failure(SplitRouteError.invalid("\(self.host) DNS 응답 시간이 초과되었습니다.")))
                }
            }
        }
        private func update(flags: UInt32, error: Int32, address: UnsafePointer<sockaddr>?, ttl: UInt32) {
            guard continuation != nil else { return }
            if error == kDNSServiceErr_NoSuchRecord { finish(.success([])); return }
            guard error == 0, let address, Int32(address.pointee.sa_family) == family else {
                finish(.failure(SplitRouteError.invalid("\(host) DNS 응답 오류 (\(error))"))); return
            }
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(address, socklen_t(address.pointee.sa_len), &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 else {
                finish(.failure(SplitRouteError.invalid("DNS 응답 주소를 읽지 못했습니다."))); return
            }
            let ip = String(cString: buf)
            if flags & UInt32(kDNSServiceFlagsAdd) != 0 && ttl > 0 { records[ip] = Date().addingTimeInterval(Double(ttl)) }
            else { records.removeValue(forKey: ip) }
            if flags & UInt32(kDNSServiceFlagsMoreComing) == 0 {
                finish(.success(records.map { Answer(ip: $0.key, expires: $0.value) }.sorted { $0.ip < $1.ip }))
            }
        }
        private func finish(_ result: Result<[Answer], Error>) {
            guard let waiter = continuation else { return }
            continuation = nil
            if let ref { DNSServiceRefDeallocate(ref); self.ref = nil }
            waiter.resume(with: result)
        }
    }
}
#endif
