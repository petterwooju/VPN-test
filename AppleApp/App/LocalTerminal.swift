#if os(macOS)
import AppKit
import Foundation

enum LocalTerminal {
    static var workspace: URL? {
        let configured = Bundle.main.object(forInfoDictionaryKey: "CoreaVPNPilotWorkspace") as? String
        return runtimeDirectory(configuredPath: configured,
                                applicationSupport: FileManager.default.urls(for: .applicationSupportDirectory,
                                                                              in: .userDomainMask)[0])
    }

    static func runtimeDirectory(configuredPath: String?, applicationSupport: URL) -> URL? {
        let runtime = applicationSupport.appendingPathComponent("CoreaVPN/LocalRuntime", isDirectory: true)
        // Compare strings before building or resolving a URL from the old Documents path.
        return runtime.path == configuredPath ? runtime : nil
    }

    static func latestPumaDirectory(in runs: URL) -> URL? {
        guard let data = read(runs.appendingPathComponent("latest-puma-run.txt"), limit: 4096),
              let text = String(data: data, encoding: .utf8) else { return nil }
        let path = text.trimmingCharacters(in: .newlines)
        let prefix = runs.path + "/"
        guard path.hasPrefix(prefix) else { return nil }
        let name = String(path.dropFirst(prefix.count))
        guard !name.contains("/"), !name.utf8.contains(0), name.hasSuffix("-puma-pilot") else { return nil }
        let directory = runs.appendingPathComponent(name, isDirectory: true)
        var info = stat()
        guard lstat(directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else { return nil }
        return directory
    }

    static func read(_ file: URL, limit: Int) -> Data? {
        guard file.standardizedFileURL.path == file.resolvingSymlinksInPath().standardizedFileURL.path,
              let attributes = try? file.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey]),
              attributes.isRegularFile == true, let size = attributes.fileSize, size <= limit,
              let stream = try? FileHandle(forReadingFrom: file) else { return nil }
        defer { try? stream.close() }
        guard let data = try? stream.read(upToCount: limit + 1), data.count <= limit else { return nil }
        return data
    }

    static func quoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func anotherPilotIsRunning() -> Bool {
        let path = "/private/tmp/coreavpn-offline-\(getuid()).lock"
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        // The worker and detached watchdog share this exclusive lock. The runner
        // still takes it atomically during startup, including simultaneous launches.
        return flock(fd, LOCK_SH | LOCK_NB) != 0 && errno == EWOULDBLOCK
    }

    @MainActor static func launch(folder: URL, name: String, command: String, onOpen: @escaping (Error?) -> Void) throws {
        guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else {
            throw CocoaError(.fileNoSuchFile)
        }
        let fm = FileManager.default
        try fm.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let script = folder.appendingPathComponent(name)
        let body = """
        #!/bin/bash
        umask 077
        cd \(quoted(folder.path)) || exit 1
        printf '%s\\n' "$$" > shell-pid
        trap 'code=$?; printf "%s\\n" "$code" > exit-code.tmp && /bin/mv -f exit-code.tmp exit-code' EXIT
        \(command)
        exit $?
        """
        try Data(body.utf8).write(to: script, options: .withoutOverwriting)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true
        NSWorkspace.shared.open([script], withApplicationAt: terminal, configuration: config) { _, error in
            if error != nil {
                try? Data("1\n".utf8).write(to: folder.appendingPathComponent("exit-code"), options: .atomic)
            }
            onOpen(error)
        }
    }
}
#endif
