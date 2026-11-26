import Foundation

// Small local executable used by the Mac profile runner before it edits an
// endpoint. Reuse the app's certificate-verified, interface-bound DoH client.
@main enum QuickResolve {
    static func main() async {
        let args = CommandLine.arguments
        guard args.count == 3, VPNEndpoints.net.contains(args[2]) else { exit(2) }
        do {
            let address = try await VPNResolver().resolve(args[2], network: args[1], interface: args[1])
            guard VPNEndpoints.isPublicIPv4(address) else { exit(1) }
            print(address)
        } catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
