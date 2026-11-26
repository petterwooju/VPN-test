import Darwin
import Foundation
import NetworkExtension
import Security

typealias LegacyFlowEndpoint = NWEndpoint

private let blocked = NSError(domain: NEAppProxyErrorDomain, code: NEAppProxyFlowError.refused.rawValue)

struct FlowTarget: Hashable {
    let host: String
    let port: Int
    init?(_ endpoint: NWEndpoint) {
        guard let endpoint = endpoint as? NWHostEndpoint, !endpoint.hostname.isEmpty,
              let value = UInt16(endpoint.port), value > 0 else { return nil }
        host = endpoint.hostname; port = Int(value)
    }
    var numeric: Bool {
        var bytes = in6_addr()
        return inet_pton(AF_INET, host, &bytes) == 1 || inet_pton(AF_INET6, host, &bytes) == 1
    }
}

private struct SourceApplication {
    let path: String
    let name: String
    let bundleID: String?

    init(flow: NEAppProxyFlow) {
        let fields = Self.signingInformation(token: flow.metaData.sourceAppAuditToken)
        let plist = fields?[kSecCodeInfoPList as String] as? [String: Any]
        let executable = fields?[kSecCodeInfoMainExecutable as String] as? URL
        path = executable?.path ?? ""
        bundleID = plist?["CFBundleIdentifier"] as? String
        let labels = [plist?["CFBundleDisplayName"] as? String, plist?["CFBundleName"] as? String,
                      executable?.lastPathComponent, flow.metaData.sourceAppSigningIdentifier]
        name = labels.compactMap { $0 }.first { !$0.isEmpty } ?? "알 수 없는 앱"
    }

    private static func signingInformation(token: Data?) -> [String: Any]? {
        guard let token else { return nil }
        var code: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        let attrs = [kSecGuestAttributeAudit: token as CFData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess else { return nil }
        return info as? [String: Any]
    }
}

/// One read at a time and one bounded write at a time. The NE flow provides
/// backpressure for both TCP and framed UDP through the connected socketpair.
private final class RouteChannel {
    let exit: FlowExit
    let connection: ProviderLiveConnection
    private let queue: DispatchQueue
    private let fd: Int32
    private let source: DispatchSourceRead
    private let output: DispatchIO
    private var closed = false
    private var paused = false
    private var eof = false
    private let incoming: (Data?, Error?, @escaping () -> Void) -> Void

    init?(fd: Int32, exit: FlowExit, connection: ProviderLiveConnection, queue: DispatchQueue,
          onRead: @escaping (Data?, Error?, @escaping () -> Void) -> Void) {
        let duplicate = dup(fd)
        guard duplicate >= 0 else { Darwin.close(fd); return nil }
        self.exit = exit; self.connection = connection; self.queue = queue; self.fd = fd; self.incoming = onRead
        self.source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        self.output = DispatchIO(type: .stream, fileDescriptor: duplicate, queue: queue) { _ in Darwin.close(duplicate) }
        source.setEventHandler { [weak self] in self?.read() }
        source.setCancelHandler { Darwin.close(fd) }
        source.activate()
    }

    private func read() {
        guard !closed, !paused, !eof else { return }
        var bytes = [UInt8](repeating: 0, count: 65_536)
        let count = recv(fd, &bytes, bytes.count, MSG_DONTWAIT)
        if count < 0 && [EWOULDBLOCK, EINTR].contains(errno) { return }
        paused = true; source.suspend()
        guard count > 0 else {
            eof = true
            incoming(nil, count == 0 ? nil : blocked, {})
            return
        }
        incoming(Data(bytes.prefix(count)), nil) { [weak self] in
            guard let self, !self.closed, self.paused else { return }
            self.paused = false; self.source.resume()
        }
    }

    func write(_ value: Data, then: @escaping (Bool) -> Void) {
        guard !closed else { then(false); return }
        let payload = value.withUnsafeBytes { DispatchData(bytes: $0) }
        output.write(offset: 0, data: payload, queue: queue) { done, _, error in
            if done { then(error == 0) }
        }
    }

    func finishWriting() { if !closed { shutdown(fd, SHUT_WR) } }

    func close() {
        guard !closed else { return }
        closed = true
        shutdown(fd, SHUT_RDWR)
        if paused { paused = false; source.resume() }
        source.cancel()
        output.close(flags: .stop)
    }
}

/// Calls occur on the provider's state queue. Each UDP peer gets its own
/// rule decision, bound socket and originating endpoint for replies.
final class FlowRelay {
    let acceptedAt = ProcessInfo.processInfo.systemUptime
    private let flow: NEAppProxyFlow
    private let firstTarget: FlowTarget?
    private let session: RoutingSession
    private let queue: DispatchQueue
    private let workers: OperationQueue
    private let application: SourceApplication
    private let done: () -> Void
    private var closed = false
    private var channels = [FlowTarget: RouteChannel]()
    private var connecting = [FlowTarget: [FlowExit]]()
    private var opening = [FlowTarget: BlockOperation]()
    private var udpBuffers = [FlowTarget: Data]()
    private var udpActivity = [FlowTarget: Date]()
    private var readEOF = false
    private var writeEOF = false

    init(_ flow: NEAppProxyFlow, initial: FlowTarget?, session: RoutingSession,
         queue: DispatchQueue, workers: OperationQueue, done: @escaping () -> Void) {
        self.flow = flow; self.firstTarget = initial; self.session = session
        self.queue = queue; self.workers = workers; self.done = done
        self.application = SourceApplication(flow: flow)
    }

    func start() {
        if let tcp = flow as? NEAppProxyTCPFlow, let target = FlowTarget(tcp.remoteEndpoint) {
            connect(target: target, endpoint: tcp.remoteEndpoint, udp: false) { [weak self] channel in
                guard let self, let channel else { self?.stop(); return }
                tcp.open(withLocalEndpoint: nil) { [weak self] error in
                    self?.queue.async { [weak self] in
                        guard let self, !self.closed else { return }
                        guard error == nil else { self.stop(); return }
                        self.openTCPRelay(tcp, channel)
                    }
                }
            }
        } else if let udp = flow as? NEAppProxyUDPFlow {
            udp.open(withLocalEndpoint: nil) { [weak self] error in
                self?.queue.async { [weak self] in
                    guard let self, !self.closed else { return }
                    if error == nil { self.readUDP(udp) } else { self.stop() }
                }
            }
        } else { stop() }
    }

    private var tcpOpened = false
    private var deferredRead: (() -> Void)?
    private func openTCPRelay(_ tcp: NEAppProxyTCPFlow, _ channel: RouteChannel) {
        tcpOpened = true
        let pending = deferredRead
        deferredRead = nil
        pending?()
        readTCP(tcp, channel)
    }

    private func connect(target: FlowTarget, endpoint: NWEndpoint, udp: Bool, then: @escaping (RouteChannel?) -> Void) {
        if let existing = channels[target] { then(existing); return }
        guard !closed, channels.count < 64 else { then(nil); return }
        var query = RouteQuery()
        if !target.numeric { query.domain = target.host }
        else {
            query.ip = target.host
            if !udp || firstTarget == target { query.domain = flow.remoteHostname ?? "" }
        }
        query.transport = udp ? "UDP" : "TCP"; query.port = target.port
        query.processPath = application.path; query.processName = (application.path as NSString).lastPathComponent
        guard let (rule, exits) = session.decision(for: query) else { then(nil); return }
        let flowQuery = query
        connecting[target] = exits
        let op = BlockOperation()
        opening[target] = op
        op.addExecutionBlock { [weak self, weak op, queue] in
            guard let op, !op.isCancelled else { return }
            let deadline = ProcessInfo.processInfo.systemUptime + 16
            // Try only members authorized by this rule and group. Open before
            // the NE flow consumes any application bytes, so retries are safe.
            var connected: (Int32, FlowExit)?
            for exit in exits {
                guard !op.isCancelled, ProcessInfo.processInfo.systemUptime < deadline else { break }
                let fd = exit.open(host: target.host, port: target.port, udp: udp)
                if fd >= 0 { connected = (fd, exit); break }
            }
            let result = connected
            queue.async { [weak self] in
                guard let self, !self.closed else { if let result { Darwin.close(result.0) }; return }
                self.opening.removeValue(forKey: target)
                self.connecting.removeValue(forKey: target)
                guard let (fd, exit) = result else { then(nil); return }
                guard !self.session.physicalInvalidated, (!exit.isVPN || self.session.vpnLeaseValid), exit.binding.available else { Darwin.close(fd); then(nil); return }
                let connection = ProviderLiveConnection(app: self.application.name, bundleID: self.application.bundleID,
                    query: flowQuery, rule: rule, exit: exit, server: self.session.server)
                let channel = RouteChannel(fd: fd, exit: exit, connection: connection, queue: queue) { [weak self] data, error, resume in
                    self?.receive(data, error: error, target: target, endpoint: endpoint, resume: resume)
                }
                if let channel { self.channels[target] = channel }
                then(channel)
            }
        }
        workers.addOperation(op)
    }

    private func readTCP(_ tcp: NEAppProxyTCPFlow, _ channel: RouteChannel) {
        guard !closed else { return }
        tcp.readData { [weak self] data, error in
            self?.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                guard error == nil else { self.stop(); return }
                guard let data, !data.isEmpty else {
                    self.readEOF = true; channel.finishWriting()
                    tcp.closeReadWithError(nil)
                    if self.writeEOF { self.stop(nil) }
                    return
                }
                channel.write(data) { [weak self] ok in
                    if ok { self?.readTCP(tcp, channel) } else { self?.stop() }
                }
            }
        }
    }

    private func readUDP(_ udp: NEAppProxyUDPFlow) {
        guard !closed else { return }
        udp.readDatagrams { [weak self] packets, endpoints, error in
            self?.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                guard error == nil, let packets, let endpoints, packets.count == endpoints.count, !packets.isEmpty else {
                    self.stop(error); return
                }
                self.sendBatch(udp, packets, endpoints, index: 0)
            }
        }
    }

    private func sendBatch(_ udp: NEAppProxyUDPFlow, _ packets: [Data], _ endpoints: [NWEndpoint], index: Int) {
        guard !closed else { return }
        guard index < packets.count else { readUDP(udp); return }
        let endpoint = endpoints[index]
        let packet = packets[index]
        guard let target = FlowTarget(endpoint), packet.count <= 65535 else { stop(); return }
        connect(target: target, endpoint: endpoint, udp: true) { [weak self] channel in
            guard let self, let channel else { self?.stop(); return }
            self.udpActivity[target] = Date()
            var frame = Data([UInt8(packet.count >> 8), UInt8(packet.count & 255)])
            frame.append(packet)
            channel.write(frame) { [weak self] ok in
                if ok { self?.sendBatch(udp, packets, endpoints, index: index + 1) } else { self?.stop() }
            }
        }
    }

    private func receive(_ data: Data?, error: Error?, target: FlowTarget, endpoint: NWEndpoint, resume: @escaping () -> Void) {
        guard !closed else { return }
        guard error == nil else { stop(); return }
        let finish: (Error?) -> Void = { [weak self] error in
            self?.queue.async { [weak self] in if error == nil { resume() } else { self?.stop() } }
        }
        if let tcp = flow as? NEAppProxyTCPFlow {
            guard tcpOpened else {
                deferredRead = { [weak self] in self?.receive(data, error: nil, target: target, endpoint: endpoint, resume: resume) }
                return
            }
            if let data { tcp.write(data, withCompletionHandler: finish) }
            else {
                writeEOF = true; tcp.closeWriteWithError(nil)
                if readEOF { stop(nil) }
            }
        } else if let udp = flow as? NEAppProxyUDPFlow {
            guard let data else { removePeer(target); return }
            udpActivity[target] = Date()
            var buffer = udpBuffers.removeValue(forKey: target) ?? Data()
            buffer.append(data)
            var packets: [Data] = [], start = buffer.startIndex
            while buffer.endIndex - start >= 2 {
                let size = Int(buffer[start]) * 256 + Int(buffer[start + 1])
                guard buffer.endIndex - start >= size + 2 else { break }
                packets.append(Data(buffer[start + 2..<start + 2 + size]))
                start += 2 + size
            }
            udpBuffers[target] = Data(buffer[start...])
            if packets.isEmpty { resume() }
            else { udp.writeDatagrams(packets, sentBy: Array(repeating: endpoint, count: packets.count), completionHandler: finish) }
        }
    }

    private func removePeer(_ target: FlowTarget) {
        channels.removeValue(forKey: target)?.close()
        udpActivity.removeValue(forKey: target)
        udpBuffers.removeValue(forKey: target)
    }

    var usesVPN: Bool { channels.values.contains { $0.exit.isVPN } || connecting.values.contains { $0.contains { $0.isVPN } } }

    var liveConnectionCount: Int {
        if closed || (flow is NEAppProxyTCPFlow && !tcpOpened) { return 0 }
        return channels.count
    }

    func appendLiveConnections(to rows: inout [ProviderLiveConnection], limit: Int) {
        guard liveConnectionCount > 0, rows.count < limit else { return }
        for channel in channels.values.sorted(by: { $0.connection.startedAt > $1.connection.startedAt }).prefix(limit - rows.count) {
            rows.append(channel.connection)
        }
    }

    func checkBinding(physical: Bool, vpn: Bool) {
        if !physical || (usesVPN && !vpn) { stop(); return }
        let expired = udpActivity.compactMap { Date().timeIntervalSince($0.value) > 120 ? $0.key : nil }
        for target in expired { removePeer(target) }
    }

    func stop(_ error: Error? = blocked) {
        guard !closed else { return }
        closed = true; deferredRead = nil
        for op in opening.values { op.cancel() }
        opening.removeAll()
        for channel in channels.values { channel.close() }
        channels.removeAll()
        flow.closeReadWithError(error); flow.closeWriteWithError(error)
        done()
    }
}
