import Foundation
import Testing
@testable import CorrelatorCore

@Test func iosTimestampRequiresRecordedUTCConvention() throws {
    #expect(try iosLogEpoch("2026-09-29T03:40:39.000123") == parseEpochMicroseconds("1790653239.000123"))
    #expect(throws: AnalysisError.self) { try iosLogEpoch("2026-09-29T03:40:39-07:00") }
    #expect(throws: AnalysisError.self) { try iosLogEpoch("2026-02-30T03:40:39") }
}

/// Replays private, real device output without checking it into the repository.
@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_IOS_LOG_AUDIT"] != nil))
func physicalIOSLogImport() throws {
    let directory = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["RVI_IOS_LOG_AUDIT"]))
    let item = try importIOSLog(directory, sessionID: "audit", phoneArtifactID: "audit-phone")
    let config = try readIOSLogConfiguration(directory)
    #expect(!item.observations.isEmpty)
    #expect(item.observations.allSatisfy { $0.source == .iosLog && $0.pid == String(config.processID) && $0.originalMicroseconds == $0.timeMicroseconds && $0.first("log.bootUUID") == nil })
    #expect(try importLiveIOSLog(directory, sessionID: "audit", phoneArtifactID: "audit-phone").observations == item.observations)
    #expect(sameLogActivity(try #require(item.observations.first), observations: item.observations).isEmpty)
    let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: temp) }
    try FileManager.default.copyItem(at: directory.appendingPathComponent("ios-log-config.json"), to: temp.appendingPathComponent("ios-log-config.json"))
    let raw = try Data(contentsOf: directory.appendingPathComponent("ios-log.ndjson"))
    try (raw + Data("{\"timestamp\":".utf8)).write(to: temp.appendingPathComponent("ios-log.ndjson"))
    #expect(try importLiveIOSLog(temp, sessionID: "audit", phoneArtifactID: "audit-phone").observations.count == item.observations.count)
    #expect(throws: AnalysisError.self) { try importIOSLog(temp, sessionID: "audit", phoneArtifactID: "audit-phone") }
    print("Real iPhone log replay: \(item.observations.count) records, original timestamps preserved, partial live tail deferred and incomplete final file rejected")
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_USB_AUDIT"] != nil))
func physicalUSBDiscovery() throws {
    let directory = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["RVI_USB_AUDIT"]))
    let serials = try parseAppleUSBSerials(Data(contentsOf: directory.appendingPathComponent("usb-registry.plist")))
    let data = try Data(contentsOf: directory.appendingPathComponent("device-readiness-after.json"))
    let devices = try parseCaptureDevices(data, usbSerials: serials)
    #expect(devices.contains { $0.isConnected && $0.connection.contains("tunnel unavailable") })
    #expect(try parseCaptureDevices(data, usbSerials: []).allSatisfy { !$0.isConnected })
    print("Real USB inventory matched a paired physical iPhone despite unavailable developer tunnel; removing USB presence disables readiness")
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_IOS_SESSION_AUDIT"] != nil))
func physicalFourStreamEvidence() throws {
    let directory = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["RVI_IOS_SESSION_AUDIT"]))
    let output = URL(fileURLWithPath: try #require(ProcessInfo.processInfo.environment["RVI_IOS_SESSION_REPORT"]))
    let phone = try importCapture(directory.appendingPathComponent("iphone-rvi.pcapng"), source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(directory.appendingPathComponent("mac-pktap.pcapng"), source: .mac, offsetMicroseconds: 0)
    let log = try importUnifiedLog(directory.appendingPathComponent("unified-log.ndjson"), offsetMicroseconds: 0)
    let ios = try importIOSLog(directory, sessionID: directory.lastPathComponent, phoneArtifactID: phone.artifact.id)
    let settings = CorrelationSettings(windowMilliseconds: 250, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: "")
    let previous = try correlate([phone, mac, log], settings: settings, isDemonstration: false)
    let result = try correlate([phone, mac, log, ios], settings: settings, isDemonstration: false)
    #expect(!ios.observations.isEmpty)
    #expect(previous.correlations.map(\.id) == result.correlations.map(\.id))
    #expect(previous.correlations.map(\.score) == result.correlations.map(\.score))
    #expect(previous.peerReview.flows.map(\.id) == result.peerReview.flows.map(\.id))
    #expect(result.observations.count == previous.observations.count + ios.observations.count)
    struct ContextLink: Encodable { let packet: Int; let logRecords: [Int]; let outsideWindow: Int; let withoutEndpoint: Int }
    let links = phone.observations.compactMap { packet -> ContextLink? in
        let review = iosLogContext(packet, logs: ios.observations, windowMicroseconds: 250_000)
        if review.matches.isEmpty { return nil }
        return ContextLink(packet: packet.record, logRecords: review.matches.map(\.record), outsideWindow: review.outsideWindow, withoutEndpoint: review.withoutEndpoint)
    }
    struct Report: Encodable {
        let counts: [String: Int]
        let sharedCandidates: Int
        let peerFlowPartitions: Int
        let unchangedScores: Bool
        let contextLinks: [ContextLink]
        let interpretation: String
    }
    let report = Report(counts: Dictionary(uniqueKeysWithValues: [phone, mac, log, ios].map { ($0.artifact.source.rawValue, $0.observations.count) }),
        sharedCandidates: result.correlations.count, peerFlowPartitions: result.peerReview.flows.count,
        unchangedScores: previous.correlations.map(\.score) == result.correlations.map(\.score), contextLinks: links,
        interpretation: "Device endpoint mentions are unscored review links, not RVI ownership or cross-device attribution. Clocks remain 0 ms and unverified. The targeted PID excludes other device processes.")
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(report).write(to: output, options: .atomic)
    print("Four-stream replay: \(result.observations.count) observations, \(result.correlations.count) unchanged shared candidates, \(links.count) RVI packets with unscored iPhone endpoint context")
}
