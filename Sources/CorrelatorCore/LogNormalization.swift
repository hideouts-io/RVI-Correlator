import Darwin
import Foundation

struct LogNormalizationLimits {
    let lineBytes: Int
    let outputBytes: Int
    let rawBytes: Int
}

public struct LogNormalizationSummary: Sendable {
    public let deferredTailBytes: Int
    public var warnings: [String] {
        deferredTailBytes == 0 ? [] : ["Live Unified Log snapshot deferred \(deferredTailBytes) bytes of a non-LF-terminated record. That tail is absent from this snapshot; final normalization must validate it."]
    }
}

private struct LogCounterSummary: Decodable {
    let count: Int
    let finished: Int
    private struct Key: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: Key.self)
        guard Set(container.allKeys.map(\.stringValue)) == ["count", "finished"],
              let countKey = Key(stringValue: "count"), let finishedKey = Key(stringValue: "finished") else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Unsupported Unified Log summary shape."))
        }
        count = try container.decode(Int.self, forKey: countKey)
        finished = try container.decode(Int.self, forKey: finishedKey)
        guard count >= 0, finished == 0 || finished == 1 else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid Unified Log summary counters."))
        }
    }
}

public func withLogNormalizationWarnings(_ item: ImportedEvidence, summary: LogNormalizationSummary) -> ImportedEvidence {
    let old = item.artifact
    let artifact = Artifact(id: old.id, source: old.source, path: old.path, sha256: old.sha256, bytes: old.bytes,
        records: old.records, decoder: old.decoder, offsetMicroseconds: old.offsetMicroseconds, warnings: old.warnings + summary.warnings)
    return ImportedEvidence(artifact: artifact, observations: item.observations)
}

func readBoundedFile(_ url: URL, maximumBytes: Int) throws -> Data {
    guard maximumBytes >= 0, maximumBytes < Int.max else { throw AnalysisError.invalidInput("Invalid file read budget.") }
    let input = try FileHandle(forReadingFrom: url)
    defer { try? input.close() }
    var data = Data()
    while true {
        let chunk = try input.read(upToCount: min(65_536, maximumBytes - data.count + 1)) ?? Data()
        if chunk.isEmpty { return data }
        guard chunk.count <= maximumBytes - data.count else {
            throw AnalysisError.resourceLimit("File exceeds \(maximumBytes) bytes while reading \(url.path). Use a stable, narrower export.")
        }
        data.append(chunk)
    }
}

/// Encodes only the consumed log schema. Original raw bytes remain a separate artifact.
private func normalizedLogLine(_ data: Data, line: Int, raw: URL, processIDs: Set<Int>, patterns: [NSRegularExpression], timestampParser: UnifiedLogTimestampParser) throws -> Data? {
    guard let text = String(data: data, encoding: .utf8) else {
        throw AnalysisError.invalidInput("Unified Log line \(line) is not UTF-8 at \(raw.path).")
    }
    let trimmed = text.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r"))
    if trimmed.isEmpty || trimmed.hasPrefix("Filtering the log data using ") { return nil }
    if let record = try? JSONDecoder().decode(LogRecord.self, from: data) {
        guard !record.timestamp.isEmpty, !record.eventMessage.isEmpty else {
            throw AnalysisError.invalidInput("Unified Log event \(line) has an empty timestamp or message in \(raw.path).")
        }
        do { _ = try timestampParser.microseconds(record.timestamp) }
        catch let error as AnalysisError {
            throw AnalysisError.invalidInput("Invalid Unified Log timestamp at raw line \(line) in \(raw.path): \(error.localizedDescription)")
        }
        let processName = record.processImagePath.map { URL(fileURLWithPath: $0).lastPathComponent }
        let deviceContext = processName.map { deviceLogProcesses.contains($0) } ?? false
        let endpointContext = record.processID.map { processIDs.contains($0) } == true && messageMatchesTokens(record.eventMessage, patterns: patterns)
        guard deviceContext || endpointContext else { return nil }
        let selection = deviceContext ? "device-service context; not a packet match" : "packet PID and bounded endpoint/name mention; context only"
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(record.annotated(line: line, selection: selection)) + Data([10])
    }
    guard (try? JSONDecoder().decode(LogCounterSummary.self, from: data)) != nil else {
        throw AnalysisError.invalidInput("Unexpected Unified Log JSON at line \(line) in \(raw.path). Inspect the original stream.")
    }
    return nil
}

@discardableResult
public func normalizeLiveLog(_ raw: URL, destination: URL, processIDs: Set<Int>, tokens: Set<String>) throws -> LogNormalizationSummary {
    let tail = try normalizeLog(raw, destination: destination, processIDs: processIDs, tokens: tokens,
        limits: LogNormalizationLimits(lineBytes: 1_000_000, outputBytes: 64_000_000, rawBytes: 1_000_000_000))
    return LogNormalizationSummary(deferredTailBytes: tail)
}

/// Stopped evidence consumes a valid terminal record, including one without LF;
/// malformed/truncated tails fail before publication instead of disappearing.
public func normalizeFinalLog(_ raw: URL, destination: URL, processIDs: Set<Int>, tokens: Set<String>) throws {
    let patterns = try compileLogTokenPatterns(tokens)
    let timestampParser = UnifiedLogTimestampParser()
    _ = try writeNormalizedLog(raw, destination: destination, processIDs: processIDs, patterns: patterns, timestampParser: timestampParser,
        limits: LogNormalizationLimits(lineBytes: 1_000_000, outputBytes: 64_000_000, rawBytes: 1_000_000_000),
        encodeTail: { data, line in try normalizedLogLine(data, line: line, raw: raw, processIDs: processIDs, patterns: patterns, timestampParser: timestampParser) })
}

@discardableResult
func normalizeLog(_ raw: URL, destination: URL, processIDs: Set<Int>, tokens: Set<String>, limits: LogNormalizationLimits) throws -> Int {
    try writeNormalizedLog(raw, destination: destination, processIDs: processIDs, patterns: compileLogTokenPatterns(tokens), timestampParser: UnifiedLogTimestampParser(),
        limits: limits, encodeTail: { _, _ in nil })
}

private func writeNormalizedRecord(_ data: Data, output: FileHandle, bytes: Int, limit: Int) throws -> Int {
    guard data.count <= limit - bytes else { throw AnalysisError.resourceLimit("Selected Unified Log exceeds \(limit) bytes. Stop and review the raw stream.") }
    try output.write(contentsOf: data)
    return bytes + data.count
}

/// Writes one selected record at a time. All byte budgets are enforced before write;
/// publication replaces the destination only after successful normalization and close.
private func writeNormalizedLog(_ raw: URL, destination: URL, processIDs: Set<Int>, patterns: [NSRegularExpression], timestampParser: UnifiedLogTimestampParser, limits: LogNormalizationLimits,
                                encodeTail: (Data, Int) throws -> Data?) throws -> Int {
    guard limits.lineBytes > 0, limits.outputBytes >= 0, limits.rawBytes >= 0 else {
        throw AnalysisError.invalidInput("Invalid Unified Log normalization budgets.")
    }
    let input = try FileHandle(forReadingFrom: raw)
    defer { try? input.close() }
    let temporary = destination.deletingLastPathComponent().appendingPathComponent(".normalized-\(UUID().uuidString)")
    let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
    guard descriptor >= 0 else { throw AnalysisError.invalidInput("Cannot create temporary normalized log (errno \(errno)). Check the destination directory.") }
    let output = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    defer { try? output.close() }
    do {
        var carry = Data()
        var line = 0, inputBytes = 0, outputBytes = 0
        while true {
            let chunk = try input.read(upToCount: 65_536) ?? Data()
            if chunk.isEmpty { break }
            guard chunk.count <= limits.rawBytes - inputBytes else { throw AnalysisError.resourceLimit("Raw Unified Log exceeds \(limits.rawBytes) bytes. Use a shorter stream.") }
            inputBytes += chunk.count
            carry.append(chunk)
            while let newline = carry.firstIndex(of: 10) {
                line += 1
                guard carry.distance(from: carry.startIndex, to: newline) <= limits.lineBytes else {
                    throw AnalysisError.resourceLimit("Unified Log line \(line) exceeds \(limits.lineBytes) bytes at \(raw.path).")
                }
                let data = Data(carry[..<newline])
                carry.removeSubrange(...newline)
                if let encoded = try normalizedLogLine(data, line: line, raw: raw, processIDs: processIDs, patterns: patterns, timestampParser: timestampParser) {
                    outputBytes = try writeNormalizedRecord(encoded, output: output, bytes: outputBytes, limit: limits.outputBytes)
                }
            }
            guard carry.count <= limits.lineBytes else { throw AnalysisError.resourceLimit("Unified Log line exceeds \(limits.lineBytes) bytes at \(raw.path).") }
        }
        if !carry.isEmpty, let encoded = try encodeTail(carry, line + 1) {
            outputBytes = try writeNormalizedRecord(encoded, output: output, bytes: outputBytes, limit: limits.outputBytes)
        }
        try output.close()
        guard rename(temporary.path, destination.path) == 0 else {
            throw AnalysisError.invalidInput("Cannot publish normalized log (errno \(errno)). Original destination remains intact.")
        }
        return carry.count
    } catch {
        let primary = error
        guard unlink(temporary.path) == 0 else {
            throw AnalysisError.invalidInput("\(primary.localizedDescription) Could not clean temporary normalization file (errno \(errno)).")
        }
        throw primary
    }
}
