import Foundation
import Testing
@testable import CorrelatorCore

@Test func sessionsKeepSourcesSeparateAndDirectionIndependent() throws {
    let phoneURL = try #require(Bundle.module.url(forResource: "iphone-dns-response", withExtension: "pcap", subdirectory: "Fixtures"))
    let macURL = try #require(Bundle.module.url(forResource: "mac-pktap", withExtension: "pcap", subdirectory: "Fixtures"))
    let phone = try importCapture(phoneURL, source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(macURL, source: .mac, offsetMicroseconds: 0)
    let result = try correlate([phone, mac], settings: CorrelationSettings(windowMilliseconds: 250, uncertaintyMilliseconds: 1_000, clocksVerified: false, alignmentMethod: ""), isDemonstration: false)
    let phoneSessions = result.sessions.filter { $0.source == .iphone }
    #expect(!phoneSessions.isEmpty)
    #expect(result.sessions.allSatisfy { session in
        session.packetIDs.allSatisfy { id in result.observations.first { $0.id == id }?.source == session.source }
    })
    #expect(phoneSessions.contains { session in
        session.packetIDs.contains(phone.observations[0].id) && session.packetIDs.contains(phone.observations[1].id)
    })
    #expect(result.sessions.allSatisfy { $0.firstEndpoint <= $0.secondEndpoint })
    #expect(result.sessions.allSatisfy { $0.correlationIDs.allSatisfy { id in result.correlations.contains { $0.id == id } } })
}

@Test func rawInspectorVerifiesExactSavedByteRanges() throws {
    let url = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let imported = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
    let packet = try #require(imported.observations.first)
    let raw = try inspectRawPacket(packet, artifact: imported.artifact)
    #expect(raw.bytes.count == 77)
    #expect(raw.ranges.contains { $0.field == "ip.src" && $0.offset == 26 && $0.length == 4 })
    #expect(raw.ranges.contains { $0.field == "udp.dstport" && $0.offset == 36 && $0.length == 2 })
    #expect(raw.ranges.contains { $0.field == "dns.id" && $0.offset == 42 && $0.length == 2 })
    #expect(raw.unmappedFields.contains("frame.time_epoch"))
}

@Test func rawInspectorRejectsChangedCapture() throws {
    let fixture = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("correlator-raw-\(UUID().uuidString).pcap")
    try FileManager.default.copyItem(at: fixture, to: url)
    defer { try? FileManager.default.removeItem(at: url) }
    let imported = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
    let handle = try FileHandle(forWritingTo: url)
    try handle.seekToEnd()
    try handle.write(contentsOf: Data([0]))
    try handle.close()
    #expect(throws: AnalysisError.self) {
        try inspectRawPacket(try #require(imported.observations.first), artifact: imported.artifact)
    }
}

@Test func rawInspectorRejectsTruncatedFrame() throws {
    let fixture = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let imported = try importCapture(fixture, source: .iphone, offsetMicroseconds: 0)
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("correlator-truncated-\(UUID().uuidString).pcap")
    try Data(Data(contentsOf: fixture).prefix(35)).write(to: url)
    defer { try? FileManager.default.removeItem(at: url) }
    let (hash, bytes) = try fingerprint(url)
    let original = imported.artifact
    let truncated = Artifact(id: original.id, source: original.source, path: url.path, sha256: hash, bytes: bytes,
                             records: original.records, decoder: original.decoder, offsetMicroseconds: 0, warnings: [])
    #expect(throws: AnalysisError.self) {
        try inspectRawPacket(try #require(imported.observations.first), artifact: truncated)
    }
}
