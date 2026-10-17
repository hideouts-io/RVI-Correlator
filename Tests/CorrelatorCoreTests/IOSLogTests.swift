import CryptoKit
import Darwin
import Foundation
import Testing
@testable import CorrelatorCore

private func fabricatedIOSLogDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("fabricated-ios-log-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let config = IOSLogConfiguration(executable: "/usr/bin/true", version: "fabricated-test",
                                     executableSHA256: String(repeating: "a", count: 64), processID: 1234)
    try JSONEncoder().encode(config).write(to: directory.appendingPathComponent("ios-log-config.json"), options: .atomic)
    return directory
}

private func fabricatedIOSLogLine(pid: Int32, timestamp: String, message: String) -> String {
    #"{"timestamp":"\#(timestamp)","pid":\#(pid),"filename":"/FixtureApp","level":"Default","message":"\#(message)","image_name":"FixtureApp","image_offset":0}"# + "\n"
}

private func fabricatedCollectorScript(in directory: URL) throws -> URL {
    let valid = String(fabricatedIOSLogLine(pid: 1234, timestamp: "2026-09-29T03:40:39", message: "fabricated collector").dropLast())
    let script = #"""
    #!/bin/sh
    case "$1" in
      quiet) exit 0 ;;
      complete) printf '%s\n' '\#(valid)' ;;
      partial) printf '%s' '{"timestamp":' ;;
      malformed) printf '%s\n' '{invalid JSON}' ;;
      fail-after-valid) printf '%s\n' '\#(valid)'; exit 7 ;;
      *) exit 64 ;;
    esac
    """#
    let url = directory.appendingPathComponent("fabricated-collector.sh")
    try script.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    return url
}

private func runFabricatedCollector(_ script: URL, mode: String, output: URL) throws -> Int32 {
    try Data().write(to: output, options: .atomic)
    let handle = try FileHandle(forWritingTo: output)
    let process = Process()
    process.executableURL = script
    process.arguments = [mode]
    process.standardOutput = handle
    process.standardError = Pipe()
    defer {
        if process.isRunning {
            process.terminate()
            let cleanupDeadline = Date().addingTimeInterval(1)
            while process.isRunning && Date() < cleanupDeadline { Thread.sleep(forTimeInterval: 0.01) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
        }
        try? handle.close()
    }
    try process.run()
    let deadline = Date().addingTimeInterval(3)
    while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
    guard !process.isRunning else { throw AnalysisError.resourceLimit("Fabricated collector did not exit within three seconds.") }
    process.waitUntilExit()
    return process.terminationStatus
}

@Test func iosTimestampRequiresRecordedUTCConvention() throws {
    #expect(try iosLogEpoch("2026-09-29T03:40:39.000123") == parseEpochMicroseconds("1790653239.000123"))
    #expect(throws: AnalysisError.self) { try iosLogEpoch("2026-09-29T03:40:39-07:00") }
    #expect(throws: AnalysisError.self) { try iosLogEpoch("2026-02-30T03:40:39") }
}

@Test func iosLogCapabilitiesRemainDistinctAndEvidenceConditionsAreExplicit() throws {
    #expect(iosLogCapabilityLabels() == [
        .osLogUnifiedLogging, .syslogCompatibility, .dvtTelemetry,
        .logarchive, .sysdiagnose, .syntheticFixture
    ])
    let status = IOSLogCollectionStatus(source: .osLogUnifiedLogging, state: .partial,
                                        evidence: .incompleteRecord,
                                        redaction: .possible, droppedRecords: .unverified,
                                        synthetic: .notObserved, clockAlignment: .unverified,
                                        detail: "bounded test stream")
    let data = try JSONEncoder().encode(status)
    let decoded = try JSONDecoder().decode(IOSLogCollectionStatus.self, from: data)
    #expect(decoded.source == .osLogUnifiedLogging)
    #expect(decoded.state == .partial)
    #expect(decoded.evidence == .incompleteRecord)
    #expect(decoded.redaction == .possible)
    #expect(decoded.droppedRecords == .unverified)
    #expect(decoded.synthetic == .notObserved)
    #expect(decoded.clockAlignment == .unverified)
}

@Test func iosLogCollectorStateTracksLifecycleOnly() {
    struct Case {
        let phase: String
        let requested: Bool
        let processLaunched: Bool
        let processAlive: Bool
        let expected: IOSLogCollectionState
    }
    let cases: [Case] = [
        Case(phase: "running", requested: false, processLaunched: false, processAlive: false, expected: .unavailable),
        Case(phase: "running", requested: false, processLaunched: true, processAlive: true, expected: .unavailable),
        Case(phase: "starting", requested: true, processLaunched: false, processAlive: false, expected: .starting),
        Case(phase: "running", requested: true, processLaunched: false, processAlive: false, expected: .starting),
        Case(phase: "running", requested: true, processLaunched: true, processAlive: true, expected: .running),
        Case(phase: "running", requested: true, processLaunched: true, processAlive: false, expected: .failed),
        Case(phase: "stopping", requested: true, processLaunched: true, processAlive: true, expected: .stopping),
        Case(phase: "stopped", requested: true, processLaunched: true, processAlive: false, expected: .stopped),
        Case(phase: "failed", requested: true, processLaunched: false, processAlive: false, expected: .failed),
        Case(phase: "failed", requested: true, processLaunched: true, processAlive: false, expected: .failed)
    ]
    for item in cases {
        #expect(iosLogCollectionState(phase: item.phase, requested: item.requested,
                                      processLaunched: item.processLaunched, processAlive: item.processAlive) == item.expected)
    }
}

@Test func iosLogEvidenceStateRequiresObservedBytesAndCompleteLines() {
    struct Case {
        let byteCount: UInt64?
        let lastByte: UInt8?
        let expected: IOSLogEvidenceObservation
    }
    let cases: [Case] = [
        Case(byteCount: nil, lastByte: nil, expected: .unknown),
        Case(byteCount: 0, lastByte: nil, expected: .notObserved),
        Case(byteCount: 5, lastByte: nil, expected: .bytesObserved),
        Case(byteCount: 5, lastByte: 123, expected: .incompleteRecord),
        Case(byteCount: 5, lastByte: 10, expected: .completeLinesObserved)
    ]
    for item in cases {
        #expect(iosLogEvidenceObservation(byteCount: item.byteCount, lastByte: item.lastByte) == item.expected)
    }
}

@Test func iosLogLiveLimitIsStrictlyAboveSixtyMegabytes() {
    #expect(!iosLogLiveLimitReached(bytes: 60_000_000))
    #expect(iosLogLiveLimitReached(bytes: 60_000_001))
}

@Test func iosLogStatusDecodesBeforeAndAfterOptionalCollectionStatus() throws {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let beforeCollection = #"{"phase":"running","startedAt":"2026-09-29T03:40:39Z","updatedAt":"2026-09-29T03:40:40Z"}"#
    let oldStatus = try decoder.decode(LiveCaptureStatus.self, from: Data(beforeCollection.utf8))
    #expect(oldStatus.iosLogStatus == nil)
    #expect(oldStatus.iosLogPID == nil)
    #expect(oldStatus.iosLogBytes == nil)

    let beforeEvidence = #"{"phase":"running","startedAt":"2026-09-29T03:40:39Z","updatedAt":"2026-09-29T03:40:40Z","iosLogPID":4321,"iosLogStatus":{"source":"OSLog / Unified Logging","state":"streaming","redaction":"possible","droppedRecords":"unverified","synthetic":"notObserved","clockAlignment":"unverified","detail":"Legacy status"}}"#
    let legacy = try decoder.decode(LiveCaptureStatus.self, from: Data(beforeEvidence.utf8))
    #expect(legacy.iosLogPID == 4321)
    #expect(legacy.iosLogStatus?.state == .streaming)
    #expect(legacy.iosLogStatus?.evidence == nil)
    #expect(legacy.iosLogStatus?.droppedRecords == .unverified)
    #expect(legacy.iosLogStatus?.clockAlignment == .unverified)
}

@Test func fabricatedIOSLogImportsCompleteRecordsWithOriginalByteProvenance() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("ios-log.ndjson")
    let first = fabricatedIOSLogLine(pid: 1234, timestamp: "2026-09-29T03:40:39.000123", message: "fixture one")
    let second = fabricatedIOSLogLine(pid: 1234, timestamp: "2026-09-29T03:40:40.000123", message: "fixture two")

    for (raw, expectedCount) in [(first, 1), (first + second, 2)] {
        let data = Data(raw.utf8)
        try data.write(to: url, options: .atomic)
        let imported = try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone")
        let expectedHash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #expect(imported.observations.count == expectedCount)
        #expect(imported.artifact.records == expectedCount)
        #expect(imported.artifact.bytes == UInt64(data.count))
        #expect(imported.artifact.sha256 == expectedHash)
        #expect(imported.artifact.path == url.path)
        #expect(imported.artifact.decoder.contains("fabricated-test"))
        #expect(imported.observations.allSatisfy { $0.source == .iosLog && $0.pid == "1234" &&
            $0.originalMicroseconds == $0.timeMicroseconds && $0.first("iosLog.rviArtifactID") == "fixture-phone" })
        #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations == imported.observations)
    }
}

@Test func fabricatedIOSLogDefersLiveTailAndRejectsIncompleteFinalRecord() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("ios-log.ndjson")
    let fragment = Data(#"{"timestamp":"#.utf8)
    try fragment.write(to: url, options: .atomic)
    #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.isEmpty)
    #expect(throws: AnalysisError.self) { try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }

    let complete = Data(fabricatedIOSLogLine(pid: 1234, timestamp: "2026-09-29T03:40:39", message: "fixture one").utf8)
    let partial = complete + fragment
    try partial.write(to: url, options: .atomic)
    let live = try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone")
    #expect(live.observations.count == 1)
    #expect(live.artifact.bytes == UInt64(complete.count))
    #expect(throws: AnalysisError.self) { try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
    #expect(try Data(contentsOf: url) == partial)
}

@Test func fabricatedIOSLogRejectsMalformedAndWrongPIDRecordsWithoutChangingOriginal() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let url = directory.appendingPathComponent("ios-log.ndjson")
    let malformed = Data("{invalid JSON}\n".utf8)
    let wrongPID = Data(fabricatedIOSLogLine(pid: 4321, timestamp: "2026-09-29T03:40:39", message: "fixture wrong PID").utf8)
    for raw in [malformed, wrongPID] {
        try raw.write(to: url, options: .atomic)
        #expect(throws: AnalysisError.self) { try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
        #expect(throws: AnalysisError.self) { try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
        #expect(try Data(contentsOf: url) == raw)
    }
}

@Test func fabricatedCollectorQuietAndCompleteOutputImportSeparately() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let script = try fabricatedCollectorScript(in: directory)
    let output = directory.appendingPathComponent("ios-log.ndjson")

    #expect(try runFabricatedCollector(script, mode: "quiet", output: output) == 0)
    #expect(try Data(contentsOf: output).isEmpty)
    #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.isEmpty)
    #expect(try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.isEmpty)

    #expect(try runFabricatedCollector(script, mode: "complete", output: output) == 0)
    let original = try Data(contentsOf: output)
    #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.count == 1)
    #expect(try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.count == 1)
    #expect(try Data(contentsOf: output) == original)
}

@Test func fabricatedCollectorPartialMalformedAndFailedExitPreserveOutput() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let script = try fabricatedCollectorScript(in: directory)
    let output = directory.appendingPathComponent("ios-log.ndjson")

    #expect(try runFabricatedCollector(script, mode: "partial", output: output) == 0)
    let partial = try Data(contentsOf: output)
    #expect(!partial.isEmpty && partial.last != 10)
    #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.isEmpty)
    #expect(throws: AnalysisError.self) { try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
    #expect(try Data(contentsOf: output) == partial)

    #expect(try runFabricatedCollector(script, mode: "malformed", output: output) == 0)
    let malformed = try Data(contentsOf: output)
    #expect(malformed.last == 10)
    #expect(throws: AnalysisError.self) { try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
    #expect(throws: AnalysisError.self) { try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone") }
    #expect(try Data(contentsOf: output) == malformed)

    #expect(try runFabricatedCollector(script, mode: "fail-after-valid", output: output) == 7)
    let failedOutput = try Data(contentsOf: output)
    #expect(try importLiveIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.count == 1)
    #expect(try importIOSLog(directory, sessionID: "fixture-session", phoneArtifactID: "fixture-phone").observations.count == 1)
    #expect(try Data(contentsOf: output) == failedOutput)
}

@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_IOS_LOG_PERF"] != nil))
func fabricatedIOSLogImportPerformance() throws {
    let directory = try fabricatedIOSLogDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let output = directory.appendingPathComponent("ios-log.ndjson")
    let line = Data(fabricatedIOSLogLine(pid: 1234, timestamp: "2026-09-29T03:40:39",
                                         message: String(repeating: "x", count: 8_192)).utf8)
    for targetBytes in [1_000_000, 10_000_000, 59_000_000] {
        var data = Data()
        data.reserveCapacity(targetBytes)
        while data.count + line.count <= targetBytes { data.append(line) }
        try data.write(to: output, options: .atomic)
        let expectedRecords = data.count / line.count

        let liveStarted = Date()
        let live = try importLiveIOSLog(directory, sessionID: "perf-fixture", phoneArtifactID: "perf-phone")
        let liveSeconds = Date().timeIntervalSince(liveStarted)
        let finalStarted = Date()
        let final = try importIOSLog(directory, sessionID: "perf-fixture", phoneArtifactID: "perf-phone")
        let finalSeconds = Date().timeIntervalSince(finalStarted)
        #expect(live.observations.count == expectedRecords)
        #expect(final.observations.count == expectedRecords)
        print("Fabricated iPhone NDJSON: \(data.count) bytes, \(expectedRecords) records, live import \(liveSeconds) s, final import \(finalSeconds) s")
    }
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
