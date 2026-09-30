import Foundation
import Testing
@testable import CorrelatorCore

@Test func hostBootSidecarPreservesSeparateProvenance() throws {
    let start = try sampleHostBoot()
    let end = try sampleHostBoot()
    #expect(UUID(uuidString: start.bootSessionUUID) != nil)
    #expect(start.bootSessionUUID == end.bootSessionUUID)
    let context = CaptureContext(start: start, end: end)
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("capture-context-\(UUID().uuidString).json")
    defer { try? FileManager.default.removeItem(at: url) }
    try writeCaptureContext(context, to: url)
    let restored = try readCaptureContext(url)
    #expect(restored.end?.bootSessionUUID == start.bootSessionUUID)
    #expect(restored.logPredicate == unifiedLogPredicate)
    let mismatch = HostBootSample(sampledAt: end.sampledAt, uptimeSeconds: end.uptimeSeconds, bootSessionUUID: UUID().uuidString, method: end.method)
    #expect(CaptureContext(start: start, end: mismatch).summary.contains("disagree"))
    #expect(CaptureContext(start: start, end: nil).summary.contains("start only"))
    if let path = ProcessInfo.processInfo.environment["RVI_BOOT_TEST_OUTPUT"] {
        try writeCaptureContext(context, to: URL(fileURLWithPath: path))
    }
}

@Test func normalizationRetainsDeviceContextWithoutInventingPacketSupport() throws {
    let matcher = try compileLogTokenPatterns(["203.0.113.5", "example.apple.com", "2001:db8::1"])
    #expect(messageMatchesTokens("endpoint [2001:db8::1]:443", patterns: matcher))
    #expect(!messageMatchesTokens("endpoint [2001:db8::12]:443", patterns: matcher))
    #expect(!messageMatchesTokens("https://not-example.apple.com at 203.0.113.50", patterns: matcher))
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-context-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw.ndjson"), normalized = directory.appendingPathComponent("normalized.ndjson")
    let lines = [
        #"{"timestamp":"2026-09-27 09:13:03.414421+0000","eventMessage":"connection state changed","processImagePath":"/usr/libexec/remoted","processID":999,"bootUUID":""}"#,
        #"{"timestamp":"2026-09-27 09:13:03.414422+0000","eventMessage":"203.0.113.50","processImagePath":"/usr/libexec/apsd","processID":423}"#,
        #"{"timestamp":"2026-09-27 09:13:03.414423+0000","eventMessage":"connection state changed","processImagePath":"/usr/libexec/notremoted","processID":1000}"#,
        #"{"timestamp":"2026-09-27 09:13:03.414424+0000","eventMessage":"203.0.113.5:443","processImagePath":"/usr/libexec/apsd","processID":423}"#
    ]
    let original = lines.joined(separator: "\n") + "\n"
    try original.write(to: raw, atomically: true, encoding: .utf8)
    try normalizeLiveLog(raw, destination: normalized, processIDs: [423], tokens: ["203.0.113.5"])
    let evidence = try importUnifiedLog(normalized, offsetMicroseconds: 0)
    #expect(evidence.observations.map(\.record) == [1, 4])
    #expect(evidence.observations[0].first("log.captureSelection") == "device-service context; not a packet match")
    #expect(evidence.observations[0].first("log.bootUUID") == nil)
    #expect(sameLogActivity(evidence.observations[0], observations: evidence.observations).isEmpty)
    #expect(try String(contentsOf: raw, encoding: .utf8) == original)
}
