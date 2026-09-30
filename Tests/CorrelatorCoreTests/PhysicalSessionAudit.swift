import Foundation
import Testing
@testable import CorrelatorCore

@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_AUDIT_SESSION"] != nil))
func physicalSessionAudit() throws {
    let path = try #require(ProcessInfo.processInfo.environment["RVI_AUDIT_SESSION"])
    let output = try #require(ProcessInfo.processInfo.environment["RVI_AUDIT_OUTPUT"])
    let directory = URL(fileURLWithPath: path)
    let phone = try importCapture(directory.appendingPathComponent("iphone-rvi.pcapng"), source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(directory.appendingPathComponent("mac-pktap.pcapng"), source: .mac, offsetMicroseconds: 0)
    let logs = try importUnifiedLog(directory.appendingPathComponent("unified-log.ndjson"), offsetMicroseconds: 0)
    if let normalizedPath = ProcessInfo.processInfo.environment["RVI_NORMALIZATION_OUTPUT"] {
        let normalizedURL = URL(fileURLWithPath: normalizedPath)
        let packetIDs = Set(mac.observations.compactMap { $0.pid.flatMap(Int.init) })
        let tokens = Set((phone.observations + mac.observations).flatMap { ($0.destinationIP.map { [$0] } ?? []) + $0.hostnames })
        try normalizeLiveLog(directory.appendingPathComponent("unified-log.raw"), destination: normalizedURL, processIDs: packetIDs, tokens: tokens)
        let derived = try importUnifiedLog(normalizedURL, offsetMicroseconds: 0)
        print("New normalization retained \(derived.observations.count) events in a separate validation artifact; original normalized evidence remains unchanged")
    }
    let result = try correlate([phone, mac, logs], settings: CorrelationSettings(windowMilliseconds: 250, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: ""), isDemonstration: false)
    #expect(result.observations.count == phone.observations.count + mac.observations.count + logs.observations.count)
    #expect(result.correlations.allSatisfy { $0.confidence != .high })
    struct Report: Encodable {
        let peerReview: PeerReview
        let diagnostics: CorrelationDiagnostics
        let counts: [Int]
        let candidates: Int
        let confidence: [String: Int]
        let hostnameAssociations: Int
        let examples: [String]
        let timestampDescriptions: [String]
    }
    let report = Report(peerReview: result.peerReview, diagnostics: result.diagnostics, counts: [phone.observations.count, mac.observations.count, logs.observations.count], candidates: result.correlations.count,
        confidence: Dictionary(grouping: result.correlations, by: { $0.confidence.rawValue }).mapValues(\.count), hostnameAssociations: result.hostnameEvidence.count,
        examples: result.correlations.prefix(3).map(\.id), timestampDescriptions: phone.artifact.warnings + mac.artifact.warnings)
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(report).write(to: URL(fileURLWithPath: output), options: .atomic)
    print("Physical audit: \(result.diagnostics.initiationPackets) initiations, \(result.correlations.count) candidates, \(result.hostnameEvidence.count) packets with hostname evidence")
}
