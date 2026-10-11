import Foundation
import Testing
@testable import CorrelatorCore

private func logBoundaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-log-boundary-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    return directory
}

@Test func externalLogProvenanceCannotCollideObservationIdentities() throws {
    let directory = try logBoundaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let log = directory.appendingPathComponent("log.ndjson")
    let event = #"{"timestamp":"2026-09-27 09:13:03.414421+0000","eventMessage":"203.0.113.5 Unicode "# + "\u{2028}" + #" text","processID":423,"rviCaptureLine":7}"#
    try (event + "\r\n\r\n" + event + "\r\n").write(to: log, atomically: true, encoding: .utf8)
    let imported = try importUnifiedLog(log, offsetMicroseconds: 0)
    #expect(imported.observations.map(\.record) == [1, 3])
    #expect(imported.observations.map { $0.first("log.captureLine") } == ["7", "7"])
    #expect(try resolveHostnames(imported.observations).isEmpty)
    #expect(throws: AnalysisError.self) { try resolveHostnames(imported.observations + imported.observations) }
    let phoneURL = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let macURL = try #require(Bundle.module.url(forResource: "mac-pktap", withExtension: "pcap", subdirectory: "Fixtures"))
    let phone = try importCapture(phoneURL, source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(macURL, source: .mac, offsetMicroseconds: 0)
    let settings = CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 0, clocksVerified: false, alignmentMethod: "")
    #expect(try correlate([phone, mac, imported], settings: settings, isDemonstration: true).observations.count == 4)
    #expect(throws: AnalysisError.self) { try correlate([phone, mac, imported, imported], settings: settings, isDemonstration: true) }
    for value in [0, -1] {
        try event.replacingOccurrences(of: ":7", with: ":\(value)").write(to: log, atomically: true, encoding: .utf8)
        #expect(throws: AnalysisError.self) { try importUnifiedLog(log, offsetMicroseconds: 0) }
    }
    try event.replacingOccurrences(of: ",\"rviCaptureLine\":7", with: "").write(to: log, atomically: true, encoding: .utf8)
    #expect(try importUnifiedLog(log, offsetMicroseconds: 0).observations.first?.record == 1)
}

@Test func freshNormalizationOverwritesAnnotationsAndKeepsLiveIdentity() throws {
    let directory = try logBoundaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw"), normalized = directory.appendingPathComponent("normalized")
    let first = #"{"timestamp":"2026-09-27 09:13:03+0000","eventMessage":"203.0.113.5","processID":99,"rviCaptureLine":7,"rviCaptureLine":7}"#
    let second = first.replacingOccurrences(of: ":99", with: ":423")
    try (first + "\n" + second + "\n").write(to: raw, atomically: true, encoding: .utf8)
    try normalizeLiveLog(raw, destination: normalized, processIDs: [423], tokens: ["203.0.113.5"])
    let before = try stabilizeNormalizedLog(importUnifiedLog(normalized, offsetMicroseconds: 0), sessionID: "test")
    #expect(before.observations.map(\.record) == [2])
    try normalizeLiveLog(raw, destination: normalized, processIDs: [99, 423], tokens: ["203.0.113.5"])
    let after = try stabilizeNormalizedLog(importUnifiedLog(normalized, offsetMicroseconds: 0), sessionID: "test")
    #expect(after.observations.map(\.record) == [1, 2])
    #expect(before.observations.first?.id == after.observations.last?.id)
}

@Test func normalizationChecksBudgetsBeforeWriteAndPreservesDestination() throws {
    let directory = try logBoundaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw"), destination = directory.appendingPathComponent("normalized")
    let event = #"{"timestamp":"2026-09-27 09:13:03+0000","eventMessage":"203.0.113.5","processID":423}"# + "\n"
    try event.write(to: raw, atomically: true, encoding: .utf8)
    try normalizeLiveLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"])
    let accepted = try Data(contentsOf: destination)
    let limit = LogNormalizationLimits(lineBytes: 1_000_000, outputBytes: accepted.count, rawBytes: 1_000_000)
    try normalizeLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"], limits: limit)
    try (event + event).write(to: raw, atomically: true, encoding: .utf8)
    #expect(throws: AnalysisError.self) { try normalizeLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"], limits: limit) }
    #expect(try Data(contentsOf: destination) == accepted)
    try (String(repeating: "x", count: 1_000_001) + "\n").write(to: raw, atomically: true, encoding: .utf8)
    #expect(throws: AnalysisError.self) { try normalizeLiveLog(raw, destination: destination, processIDs: [], tokens: []) }
    #expect(try Data(contentsOf: destination) == accepted)
    #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted() == ["normalized", "raw"])
    try Data(repeating: 1, count: 17).write(to: raw)
    #expect(throws: AnalysisError.self) { try readBoundedFile(raw, maximumBytes: 16) }
    #expect(try readBoundedFile(raw, maximumBytes: 17).count == 17)
}

@Test func liveTailIsVisibleAndFinalTailMustValidate() throws {
    let directory = try logBoundaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw"), destination = directory.appendingPathComponent("normalized")
    let event = #"{"timestamp":"2026-09-27 09:13:03+0000","eventMessage":"203.0.113.5","processID":423}"#
    let truncated = #"{"timestamp":"2026-09-27"#
    try (" \t" + event + "\r\n" + truncated).write(to: raw, atomically: true, encoding: .utf8)
    let summary = try normalizeLiveLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"])
    #expect(summary.deferredTailBytes == truncated.utf8.count)
    let item = withLogNormalizationWarnings(try importUnifiedLog(destination, offsetMicroseconds: 0), summary: summary)
    #expect(item.observations.count == 1)
    #expect(item.artifact.warnings.contains { $0.contains("deferred") })
    let before = try Data(contentsOf: destination)
    #expect(throws: AnalysisError.self) { try normalizeFinalLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"]) }
    #expect(try Data(contentsOf: destination) == before)
    try (event + "\n" + event).write(to: raw, atomically: true, encoding: .utf8)
    try normalizeFinalLog(raw, destination: destination, processIDs: [423], tokens: ["203.0.113.5"])
    #expect(try importUnifiedLog(destination, offsetMicroseconds: 0).observations.count == 2)
}

@Test func malformedCountRecordsCannotDisappearAsSummaries() throws {
    let directory = try logBoundaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw"), destination = directory.appendingPathComponent("normalized")
    for line in [#"{"eventMessage":"count","count":bad}"#, #"{"count":-1,"finished":1}"#,
                 #"{"count":2,"finished":1,"eventMessage":"missing timestamp"}"#,
                 #"{"count":2,"finished":4}"#, #"{"count":2}"#, "unexpected diagnostic",
                 #"{"timestamp":"not-a-time","eventMessage":"unrelated","processID":99}"#] {
        try (line + "\n").write(to: raw, atomically: true, encoding: .utf8)
        #expect(throws: AnalysisError.self) { try normalizeLiveLog(raw, destination: destination, processIDs: [], tokens: []) }
        try line.write(to: raw, atomically: true, encoding: .utf8)
        #expect(throws: AnalysisError.self) { try normalizeFinalLog(raw, destination: destination, processIDs: [], tokens: []) }
    }
    try "Filtering the log data using a network predicate\n \t{\"count\":2,\"finished\":1}\r\n".write(to: raw, atomically: true, encoding: .utf8)
    let summary = try normalizeLiveLog(raw, destination: destination, processIDs: [], tokens: [])
    #expect(summary.warnings.isEmpty)
    #expect(try Data(contentsOf: destination).isEmpty)
}
