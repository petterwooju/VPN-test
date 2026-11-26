import Foundation
import Network
import NetworkExtension

final class TransparentRoutingProvider: NETransparentProxyProvider {
    private let state = DispatchQueue(label: "net.petterwooju.coreavpn.transparent.state")
    private let workers: OperationQueue = {
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 16
        queue.qualityOfService = .userInitiated
        return queue
    }()
    private var session: RoutingSession?
    private var flows = [UUID: FlowRelay]()
    private var timer: DispatchSourceTimer?
    private var generation = UUID()

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        state.async {
            do {
                guard let configuration = self.protocolConfiguration as? NETunnelProviderProtocol,
                      let values = configuration.providerConfiguration else {
                    throw RuleProblem.message("투명 프록시 설정을 찾을 수 없습니다.")
                }
                let new = try RoutingSession(config: values, queue: self.state)
                let instance = UUID()
                self.generation = instance
                self.session = new
                new.replaceNodes(options?["nodeConfigurations"] as? [String: Data] ?? [:])
                let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
                settings.includedNetworkRules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0,
                    localNetwork: nil, localPrefix: 0, protocol: .any, direction: .outbound)]
                self.setTunnelNetworkSettings(settings) { error in self.state.async {
                    guard self.generation == instance else { completionHandler(NEVPNError(.configurationStale)); return }
                    if let error { self.session = nil; completionHandler(error); return }
                    let timer = DispatchSource.makeTimerSource(queue: self.state)
                    var ticks = 0
                    timer.schedule(deadline: .now(), repeating: 1)
                    timer.setEventHandler { [weak self] in
                        guard let self, let session = self.session else { return }
                        let p = session.checkPhysical()
                        let v = p && session.vpnLeaseValid && session.vpn?.available == true
                        if !v { session.updateVPN([:]) }
                        for flow in Array(self.flows.values) { flow.checkBinding(physical: p, vpn: v) }
                        if ticks % 10 == 0 { session.refreshHealth() }
                        ticks = (ticks + 1) % 10
                    }
                    self.timer = timer; timer.activate(); completionHandler(nil)
                }}
            } catch { completionHandler(error) }
        }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        state.async {
            self.generation = UUID()
            self.timer?.cancel(); self.timer = nil
            self.workers.cancelAllOperations()
            for flow in Array(self.flows.values) { flow.stop() }
            self.session = nil
            completionHandler()
        }
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        accept(flow, initial: nil)
    }

    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: LegacyFlowEndpoint) -> Bool {
        accept(flow, initial: FlowTarget(remoteEndpoint))
    }

    private func accept(_ flow: NEAppProxyFlow, initial: FlowTarget?) -> Bool {
        state.async {
            guard let session = self.session, session.checkPhysical(), self.flows.count < 1024 else {
                let error = NEVPNError(.connectionFailed)
                flow.closeReadWithError(error); flow.closeWriteWithError(error)
                return
            }
            let id = UUID()
            let relay = FlowRelay(flow, initial: initial, session: session, queue: self.state, workers: self.workers) { [weak self] in
                self?.flows.removeValue(forKey: id)
            }
            self.flows[id] = relay
            relay.start()
        }
        // Declining a flow asks the OS to bypass a transparent provider. Take
        // ownership and close rejected/unavailable flows explicitly.
        return true
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        state.async {
            guard let session = self.session, messageData.count <= 4 * 1024 * 1024,
                  let message = (try? PropertyListSerialization.propertyList(from: messageData, format: nil)) as? [String: Any] else {
                completionHandler?(nil); return
            }
            let nodes = message["nodeConfigurations"] as? [String: Data]
            if message["invalidatePhysical"] as? Bool == true {
                session.invalidatePhysical()
                for flow in Array(self.flows.values) { flow.stop() }
                completionHandler?(Data([1])); return
            }
            if let config = message["replaceConfiguration"] as? [String: Any] {
                do {
                    guard let nodes else { completionHandler?(nil); return }
                    let successor = try RoutingSession(config: config, queue: self.state)
                    guard successor.checkPhysical() else { completionHandler?(nil); return }
                    successor.updateVPN(message)
                    successor.replaceNodes(nodes)
                    self.workers.cancelAllOperations()
                    for flow in Array(self.flows.values) { flow.stop() }
                    self.session = successor
                    completionHandler?(Data([1]))
                } catch { completionHandler?(nil) }
                return
            }
            if message["replaceConfiguration"] != nil { completionHandler?(nil); return }
            if nodes != nil {
                for flow in Array(self.flows.values) { flow.stop() }
                session.replaceNodes(nodes ?? [:])
            }
            if message.isEmpty || message["selectedServer"] != nil || nodes == nil {
                let previous = session.vpn, server = session.server, date = session.sessionDate
                session.updateVPN(message)
                if session.vpn != previous || session.server != server || session.sessionDate != date {
                    for flow in Array(self.flows.values) where flow.usesVPN { flow.stop() }
                }
            }
            completionHandler?(Data([1]))
        }
    }
}

@available(macOS 15.0, *)
extension TransparentRoutingProvider: NEAppProxyUDPFlowHandling {
    func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint) -> Bool {
        guard case let .hostPort(host, port) = remoteEndpoint else { return accept(flow, initial: nil) }
        let address: String
        switch host {
        case let .name(name, _): address = name
        case let .ipv4(ip): address = ip.debugDescription
        case let .ipv6(ip): address = ip.debugDescription
        @unknown default: return accept(flow, initial: nil)
        }
        let endpoint = NetworkExtension.NWHostEndpoint(hostname: address, port: String(port.rawValue))
        return accept(flow, initial: FlowTarget(endpoint))
    }
}
