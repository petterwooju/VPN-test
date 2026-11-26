"""Exercise the macOS helper's row lookup without contacting Accessibility or the network."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"), "requires the macOS Swift SDK")
class NamedVPNRowsTests(unittest.TestCase):
    def test_visible_opaque_moved_and_ambiguous_rows(self):
        source = Path(__file__).resolve().parents[1] / "scripts/offline-ui.swift"
        # Inject a test entry point before the production CLI. The lookup
        # receives the same labels as AX and a substitute for opening a sheet.
        fixture = r'''
if CommandLine.arguments.contains("--check-rows") {
    let name = "CoreaVPN_TEST"
    func check(_ labels: [Set<String>], hint: Int, count: Int?, sheets: [String],
               visits: [Int], result: Int?, errorContains: String? = nil) {
        var inspected: [Int] = []
        do {
            let found = try namedRowIndex(labels: labels, name: name, hint: hint, expectedCount: count) {
                inspected.append($0)
                return sheets[$0] == name
            }
            precondition(errorContains == nil && found.index == result)
        } catch {
            precondition(errorContains.map { String(describing: error).contains($0) } == true)
        }
        precondition(inspected == visits)
    }
    check([["Work"], [name]], hint: 0, count: nil, sheets: [], visits: [], result: 1)
    check([["Work"], ["Other"]], hint: 0, count: nil, sheets: [], visits: [], result: nil,
          errorContains: "Could not locate")
    check([[name], [name]], hint: 0, count: 2, sheets: [], visits: [], result: nil,
          errorContains: "Duplicate")
    check([[name], ["연결 안 됨"]], hint: 0, count: nil, sheets: [name, name], visits: [1],
          result: nil, errorContains: "Duplicate")
    check([[name + " (IKEv2)"], []], hint: 0, count: nil, sheets: [name, "Other"],
          visits: [0, 1], result: 0)
    check([[], [], []], hint: 1, count: 3, sheets: ["A", name, "B"], visits: [1], result: 1)
    check([["A"], [], ["B"]], hint: 2, count: 3, sheets: ["A", name, "B"], visits: [1], result: 1)
    check([[], []], hint: 0, count: 3, sheets: [name, name], visits: [0, 1],
          result: nil, errorContains: "Duplicate")
    exit(0)
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "check-rows"
            subprocess.run(["swiftc", "-module-cache-path", str(executable.parent / "cache"),
                            "-", "-o", str(executable)], input=fixture + source.read_text(), text=True,
                           capture_output=True, check=True, timeout=150)
            subprocess.run([str(executable), "--check-rows"], check=True, timeout=10)
