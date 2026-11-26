import AppKit
import Foundation

/// Explicitly attribute recovered local reports to the network of an enrolled history run.
@main
struct ImportLocalHistory {
    @MainActor static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }

    @MainActor private static func run() throws {
        let args = Array(CommandLine.arguments.dropFirst())
        let usage = "Usage: import-local-history.sh --store measurements.json --network-run UUID --csv result.csv [--puma RUN] [--paired RUN --runtime LocalRuntime]"
        let flags = Set(["--store", "--runtime", "--network-run", "--csv", "--puma", "--paired"])
        var options = [String: String]()
        guard args.count.isMultiple(of: 2) else { throw CLIError(usage) }
        for index in stride(from: 0, to: args.count, by: 2) {
            guard flags.contains(args[index]), options[args[index]] == nil else { throw CLIError(usage) }
            options[args[index]] = args[index+1]
        }
        guard let path = options["--store"], let id = options["--network-run"].flatMap(UUID.init(uuidString:)),
              let csv = options["--csv"], options["--paired"] == nil || options["--runtime"] != nil else { throw CLIError(usage) }
        func url(_ path: String) -> URL { URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath() }
        guard url(path) != url(csv) else { throw CLIError("Use a separate file for CSV export.") }
        if options["--puma"] != nil || options["--paired"] != nil {
            guard ["net.petterwooju.coreavpn.preview", "net.petterwooju.coreavpn"].allSatisfy({
                NSRunningApplication.runningApplications(withBundleIdentifier: $0).isEmpty
            }) else { throw CLIError("Quit CoreaVPN before updating its history.") }
            guard !LocalTerminal.anotherPilotIsRunning() else { throw CLIError("A VPN test or recovery is active.") }
        }
        let store = try BenchmarkStore(fileURL: url(path))
        guard let network = store.runs.first(where: { $0.id == id })?.network,
              network.deviceID != BenchmarkNetwork.beijingReference.deviceID, !network.label.isEmpty else {
            throw CLIError("Choose a history run enrolled on this Mac and physical network.")
        }
        if let puma = options["--puma"] {
            let added = try store.importLocalPuma(from: url(puma), into: network)
            print("Puma", added ? "added" : "already present")
        }
        if let paired = options["--paired"], let runtime = options["--runtime"] {
            let bridge = LocalQuickSearch(workspace: url(runtime))
            let added = try bridge.importComparison(from: url(paired), into: network, store: store)
            print("Comparison", added ? "added" : "already present")
        }
        try store.csv(network: network).write(to: url(csv), atomically: true, encoding: .utf8)
        print(network.label, network.interface, "CSV", csv)
    }

    struct CLIError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }
}
