import Foundation
import Testing
@testable import CorrelatorCore

@Test func decoderPipesEnforceBothQuotasIncludingFastExit() throws {
    let shell = URL(fileURLWithPath: "/bin/sh")
    let limits = ProcessOutputLimits(stdoutBytes: 64, stderrBytes: 64, seconds: 2)
    let exact = String(repeating: "x", count: 64)
    let result = try runBoundedProcess(shell, arguments: ["-c", "printf '%s' '\(exact)'; printf '%s' '\(exact)' >&2"], limits: limits)
    #expect(result.0.count == 64 && result.1.count == 64)
    for script in ["printf '%s' '\(exact)x'", "printf '%s' '\(exact)x' >&2",
                   "while :; do printf 'xxxxxxxx'; printf 'xxxxxxxx' >&2; done"] {
        #expect(throws: AnalysisError.self) { try runBoundedProcess(shell, arguments: ["-c", script], limits: limits) }
    }
}

@Test func decoderDeadlineKillsChildIgnoringTermination() throws {
    let start = ProcessInfo.processInfo.systemUptime
    #expect(throws: AnalysisError.self) {
        try runBoundedProcess(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "trap '' TERM; while :; do :; done"],
            limits: ProcessOutputLimits(stdoutBytes: 64, stderrBytes: 64, seconds: 0.1))
    }
    #expect(ProcessInfo.processInfo.systemUptime - start < 3)
}

@Test func decoderDeadlineIncludesPipeHeldByExitedChild() throws {
    let start = ProcessInfo.processInfo.systemUptime
    // The task-owned descendant exits itself shortly; it keeps inherited stdout open.
    #expect(throws: AnalysisError.self) {
        try runBoundedProcess(URL(fileURLWithPath: "/bin/sh"), arguments: ["-c", "/bin/sleep 0.4 & exit 0"],
            limits: ProcessOutputLimits(stdoutBytes: 64, stderrBytes: 64, seconds: 0.1))
    }
    #expect(ProcessInfo.processInfo.systemUptime - start < 1)
}

@Test func realDecoderCrossesBatchBoundaryAndFinalizes() throws {
    let fixture = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let original = try Data(contentsOf: fixture)
    let capture = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-batch-\(UUID().uuidString).pcap")
    defer { try? FileManager.default.removeItem(at: capture) }
    var data = Data(original.prefix(24))
    let frame = Data(original.dropFirst(24))
    for _ in 0..<50_001 { data.append(frame) }
    try data.write(to: capture)
    let live = try importLiveCapture(capture, source: .iphone, sessionID: "batch", afterRecord: 0)
    #expect(live.observations.count == 50_001)
    #expect(live.observations.first?.record == 1 && live.observations.last?.record == 50_001)
    let final = try finalizeLiveCapture(capture, source: .iphone, sessionID: "batch", existing: live.observations)
    #expect(final.observations.count == 50_001 && final.artifact.sha256.count == 64)
}

@Test func aggregatePacketBudgetRejectsBeforeRetentionAndChecksOverflow() throws {
    let limit = PacketBudget(records: 2, bytes: 4096)
    let packet = Observation(id: "a:1", source: .iphone, artifactID: "a", record: 1,
        originalMicroseconds: 1, timeMicroseconds: 1, protocols: ["ip"], fields: ["ip.dst": ["203.0.113.5"]])
    #expect(try appendPacketObservations([packet], incoming: [packet], limit: limit).count == 2)
    #expect(throws: AnalysisError.self) { try appendPacketObservations([packet, packet], incoming: [packet], limit: limit) }
    #expect(throws: AnalysisError.self) { try appendPacketObservations([], incoming: [packet], limit: PacketBudget(records: 2, bytes: 400)) }
    #expect(throws: AnalysisError.self) { try addingPacketBudget(PacketBudget(records: 1, bytes: 4096), records: 0, bytes: 1, limit: limit) }
    let fixture = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    #expect(throws: AnalysisError.self) { try importLiveCapture(fixture, source: .iphone, sessionID: "cursor", afterRecord: Int.max) }
}
