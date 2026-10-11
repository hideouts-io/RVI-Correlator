import CryptoKit
import Foundation

/// Optional collector contract. Device selection is inherited from the RVI session.
public struct IOSLogConfiguration: Codable, Sendable {
    public let executable: String
    public let version: String
    public let executableSHA256: String
    public let processID: Int32
    public let timeZone: String
    public let service: String

    public init(executable: String, version: String, executableSHA256: String, processID: Int32) {
        self.executable = executable; self.version = version; self.executableSHA256 = executableSHA256
        self.processID = processID; self.timeZone = "UTC"; self.service = "com.apple.os_trace_relay"
    }

    public func validate() throws {
        guard executable.hasPrefix("/"), processID > 0, !version.isEmpty,
              executableSHA256.count == 64, executableSHA256.allSatisfy(\.isHexDigit),
              timeZone == "UTC", service == "com.apple.os_trace_relay" else {
            throw AnalysisError.invalidInput("Invalid iPhone log collector configuration: require an absolute executable, positive device PID, version, SHA-256, UTC, and OS trace relay.")
        }
    }
}

public func readIOSLogConfiguration(_ directory: URL) throws -> IOSLogConfiguration {
    let url = directory.appendingPathComponent("ios-log-config.json")
    let config = try JSONDecoder().decode(IOSLogConfiguration.self, from: Data(contentsOf: url))
    try config.validate()
    return config
}

private struct IOSLogRecord: Decodable {
    struct Label: Decodable { let subsystem: String; let category: String }
    let timestamp: String
    let pid: Int32
    let filename: String
    let level: String
    let message: String
    let label: Label?
    let image_name: String
    let image_offset: UInt64
    let image_uuid: String?
    let process_image_uuid: String?
    let procid: UInt64?
    let thread_id: UInt64?
    let mach_timestamp: UInt64?
}

/// The collector emits a naive host-local rendering of device epoch seconds. TZ=UTC
/// is an explicit collection convention, not a measurement of device clock alignment.
func iosLogEpoch(_ stamp: String) throws -> Int64 {
    guard stamp.range(of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?$"#, options: .regularExpression) != nil else {
        throw AnalysisError.invalidInput("Unexpected iPhone log timestamp: \(stamp). Expected collector ISO text captured with TZ=UTC.")
    }
    let parts = stamp.split(separator: ".")
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = TimeZone(secondsFromGMT: 0)
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
    formatter.isLenient = false
    guard let date = formatter.date(from: String(parts[0])), formatter.string(from: date) == parts[0] else {
        throw AnalysisError.invalidInput("Invalid iPhone log calendar timestamp: \(stamp)")
    }
    return try parseEpochMicroseconds("\(Int64(date.timeIntervalSince1970)).\(parts.count == 2 ? String(parts[1]) : "0")")
}

private func decodeIOSLog(_ data: Data, url: URL, config: IOSLogConfiguration, sessionID: String, phoneArtifactID: String) throws -> ImportedEvidence {
    try config.validate()
    guard let text = String(data: data, encoding: .utf8) else { throw AnalysisError.invalidInput("iPhone log is not UTF-8: \(url.path)") }
    let artifactID = "\(sessionID)-iPhone OS trace"
    let decoder = JSONDecoder()
    let observations: [Observation] = try text.split(separator: "\n", omittingEmptySubsequences: false).enumerated().compactMap { index, line in
        if line.isEmpty { return nil }
        let record: IOSLogRecord
        do { record = try decoder.decode(IOSLogRecord.self, from: Data(line.utf8)) }
        catch { throw AnalysisError.invalidInput("Invalid iPhone OS trace record \(index + 1) in \(url.path): \(error)") }
        guard record.pid == config.processID else { throw AnalysisError.invalidInput("iPhone log record \(index + 1) has PID \(record.pid), outside requested PID \(config.processID).") }
        let epoch = try iosLogEpoch(record.timestamp)
        let fields: [String: [String]] = [
            "log.message": [record.message], "log.pid": [String(record.pid)],
            "log.process": [URL(fileURLWithPath: record.filename).lastPathComponent],
            "log.category": record.label.map { [$0.category] } ?? [],
            "log.subsystem": record.label.map { [$0.subsystem] } ?? [],
            "log.processImageUUID": record.process_image_uuid.map { [$0] } ?? [],
            "iosLog.timestamp": [record.timestamp], "iosLog.level": [record.level],
            "iosLog.filename": [record.filename], "iosLog.image": [record.image_name],
            "iosLog.imageOffset": [String(record.image_offset)],
            "iosLog.imageUUID": record.image_uuid.map { [$0] } ?? [],
            "iosLog.procid": record.procid.map { [String($0)] } ?? [],
            "iosLog.threadID": record.thread_id.map { [String($0)] } ?? [],
            "iosLog.machTimestamp": record.mach_timestamp.map { [String($0)] } ?? [],
            "iosLog.rviArtifactID": [phoneArtifactID],
            "iosLog.timestampConvention": ["Collector TZ=UTC; device epoch rendered to microseconds; offset 0; alignment unverified"]
        ]
        return Observation(id: "\(artifactID):\(index + 1)", source: .iosLog, artifactID: artifactID, record: index + 1,
                           originalMicroseconds: epoch, timeMicroseconds: epoch, protocols: [], fields: fields.filter { !$0.value.isEmpty })
    }
    let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    return ImportedEvidence(artifact: Artifact(id: artifactID, source: .iosLog, path: url.path, sha256: hash,
        bytes: UInt64(data.count), records: observations.count, decoder: "pymobiledevice3 \(config.version) · OS trace relay NDJSON · device PID \(config.processID)", offsetMicroseconds: 0,
        warnings: ["Experimental third-party OS trace relay. Original collector NDJSON is preserved; this is not raw binary transport or a complete logarchive.",
                   "PID-scoped, default/error/fault levels. Redaction, unpersisted messages and transport loss may hide evidence. Loss count unavailable, never zero by assumption.",
                   "UTC rendering is documented collection provenance. Device clock alignment is unverified; boot and activity identifiers are unavailable. PID and image UUID do not establish a process lifetime or RVI packet ownership."]), observations: observations)
}

private func iosLogSnapshot(_ url: URL) throws -> Data {
    let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber
    guard let size, size.int64Value <= 64_000_000 else { throw AnalysisError.resourceLimit("iPhone log exceeds the 64 MB import limit: \(url.path)") }
    let data = try readBoundedFile(url, maximumBytes: 64_000_000)
    guard data.count <= 64_000_000 else { throw AnalysisError.resourceLimit("iPhone log grew beyond the 64 MB import limit: \(url.path)") }
    return data
}

/// Live snapshots consume complete lines only; final import rejects an incomplete tail.
public func importLiveIOSLog(_ directory: URL, sessionID: String, phoneArtifactID: String) throws -> ImportedEvidence {
    let url = directory.appendingPathComponent("ios-log.ndjson")
    let data = try iosLogSnapshot(url)
    let complete = data.lastIndex(of: 10).map { Data(data[...$0]) } ?? Data()
    return try decodeIOSLog(complete, url: url, config: readIOSLogConfiguration(directory), sessionID: sessionID, phoneArtifactID: phoneArtifactID)
}

public func importIOSLog(_ directory: URL, sessionID: String, phoneArtifactID: String) throws -> ImportedEvidence {
    let url = directory.appendingPathComponent("ios-log.ndjson")
    let data = try iosLogSnapshot(url)
    guard data.isEmpty || data.last == 10 else { throw AnalysisError.invalidInput("iPhone log has an incomplete final record: \(url.path). Preserve the file; session finalization is incomplete.") }
    let result = try decodeIOSLog(data, url: url, config: readIOSLogConfiguration(directory), sessionID: sessionID, phoneArtifactID: phoneArtifactID)
    guard try fingerprint(url).0 == result.artifact.sha256 else { throw AnalysisError.evidenceChanged("iPhone log changed during import: \(url.path)") }
    return result
}

public struct IOSLogContext: Sendable {
    public let matches: [Observation]
    public let outsideWindow: Int
    public let withoutEndpoint: Int
}

/// Explicit endpoint mentions are unscored review context, scoped by the coordinated
/// session binding. PIDs, image UUIDs and similar message text are never cross-device joins.
public func iosLogContext(_ packet: Observation, logs: [Observation], windowMicroseconds: Int64) -> IOSLogContext {
    let tokens = Set([packet.sourceIP, packet.destinationIP].compactMap { $0 } + packet.hostnames)
    var matches: [Observation] = []
    var outside = 0
    var without = 0
    guard packet.source == .iphone else { return IOSLogContext(matches: [], outsideWindow: 0, withoutEndpoint: 0) }
    for log in logs where log.source == .iosLog && log.first("iosLog.rviArtifactID") == packet.artifactID {
        guard let message = log.first("log.message"), tokens.contains(where: { messageMentions(message, token: $0) }) else { without += 1; continue }
        if abs(Double(log.timeMicroseconds) - Double(packet.timeMicroseconds)) <= Double(windowMicroseconds) { matches.append(log) }
        else { outside += 1 }
    }
    return IOSLogContext(matches: matches, outsideWindow: outside, withoutEndpoint: without)
}
