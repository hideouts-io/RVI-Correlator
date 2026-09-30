import CryptoKit
import Foundation

private let packetFields = [
    "frame.darwin.process_info.pid", "frame.darwin.process_info.pname", "frame.darwin.process_info.epid", "frame.darwin.process_info.epname", "frame.packet_flags_direction",
    "frame.number", "frame.time_epoch", "frame.protocols", "frame.interface_name", "frame.len",
    "eth.src", "eth.dst", "eth.type", "arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4",
    "ip.src", "ip.dst", "ip.proto", "ipv6.src", "ipv6.dst", "ipv6.nxt", "icmp.type", "icmpv6.type",
    "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.srcport", "tcp.dstport", "tcp.flags.syn", "tcp.flags.ack", "tcp.stream", "udp.srcport", "udp.dstport", "udp.stream",
    "dns.flags.response", "dns.flags.rcode", "dns.flags.truncated", "dns.response_to", "dns.qry.name", "dns.resp.name", "dns.resp.ttl", "dns.a", "dns.aaaa", "dns.cname", "dns.id",
    "tls.handshake.type", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str", "x509af.serialNumber", "x509af.notBeforeTime", "x509af.notAfterTime", "x509ce.dNSName", "x509sat.uTF8String", "x509sat.printableString",
    "http.request.method", "http.host", "http.request.uri", "http.response.code", "stun.type", "stun.id",
    "quic.version", "quic.dcid", "quic.scid", "quic.long.packet_type", "quic.long.packet_type_v2", "quic.packet_number", "quic.token_length",
    "pktap.ifname", "pktap.flags", "pktap.pid", "pktap.cmdname", "pktap.epid", "pktap.ecmdname", "pktap.svc_class", "pktap.iftype", "pktap.ifunit", "pktap.dlt"
]

private enum FieldValue: Decodable {
    case text(String), list([String])
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let strings = try? container.decode([String].self) { self = .list(strings); return }
        self = .text(try container.decode(String.self))
    }
    var strings: [String] { switch self { case .text(let value): return [value]; case .list(let values): return values } }
}

private struct TSharkPacket: Decodable {
    let source: Source
    private enum CodingKeys: String, CodingKey { case source = "_source" }
    struct Source: Decodable { let layers: [String: FieldValue] }
}

private struct LogRecord: Decodable {
    let timestamp: String
    let eventMessage: String
    let processImagePath: String?
    let processID: Int?
    let subsystem: String?
    let category: String?
    let rviCaptureLine: Int?
    let rviCaptureSelection: String?
    let bootUUID: String?
    let processImageUUID: String?
    let activityIdentifier: UInt64?
    let parentActivityIdentifier: UInt64?
    let traceID: UInt64?
}

public func parseEpochMicroseconds(_ text: String) throws -> Int64 {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 2, let seconds = Int64(parts[0]), seconds >= 0,
          parts[1].count <= 9, parts[1].allSatisfy(\.isNumber),
          let fraction = Int64(String(parts[1].prefix(6)).padding(toLength: 6, withPad: "0", startingAt: 0)) else {
        throw AnalysisError.invalidInput("Invalid packet epoch timestamp: \(text)")
    }
    let (base, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000)
    guard !overflow else { throw AnalysisError.invalidInput("Packet timestamp is out of range: \(text)") }
    let (timestamp, fractionOverflow) = base.addingReportingOverflow(fraction)
    guard !fractionOverflow else { throw AnalysisError.invalidInput("Packet timestamp is out of range: \(text)") }
    return timestamp
}

private func fingerprint(_ url: URL) throws -> (String, UInt64) {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var hash = SHA256()
    var bytes: UInt64 = 0
    while true {
        let chunk = try handle.read(upToCount: 1_048_576) ?? Data()
        if chunk.isEmpty { break }
        bytes += UInt64(chunk.count)
        hash.update(data: chunk)
    }
    return (hash.finalize().map { String(format: "%02x", $0) }.joined(), bytes)
}

public func tsharkExecutable() throws -> URL {
    let candidates = ["/Applications/Wireshark.app/Contents/MacOS/tshark", "/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"]
    guard let path = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
        throw AnalysisError.invalidInput("TShark is required for PCAP/PCAPNG decoding. Install Wireshark for macOS or Homebrew tshark and retry.")
    }
    return URL(fileURLWithPath: path)
}

private func decodeCapture(_ url: URL) throws -> ([TSharkPacket], String) {
    try decodeGrowingCapture(url, afterRecord: 0)
}

private func decodeGrowingCapture(_ url: URL, afterRecord: Int) throws -> ([TSharkPacket], String) {
    guard afterRecord >= 0 else { throw AnalysisError.invalidInput("Last decoded frame number cannot be negative: \(afterRecord)") }
    var packets: [TSharkPacket] = []
    var diagnostics: [String] = []
    var cursor = afterRecord
    while true {
        let (batch, diagnostic) = try decodePackets(url, selection: ["-c", String(cursor + 50_000), "-Y", "frame.number > \(cursor)"])
        packets.append(contentsOf: batch)
        if !diagnostic.isEmpty { diagnostics.append(diagnostic) }
        if batch.count < 50_000 { break }
        cursor += batch.count
    }
    return (packets, diagnostics.joined(separator: "\n"))
}

private func decodePackets(_ url: URL, selection: [String]) throws -> ([TSharkPacket], String) {
    let (data, errorText) = try runPacketDecoder(url, arguments: selection + ["-T", "json", "--no-duplicate-keys"] + packetFields.flatMap { ["-e", $0] })
    let packets: [TSharkPacket]
    do { packets = try JSONDecoder().decode([TSharkPacket].self, from: data) }
    catch { throw AnalysisError.decoderFailed("Could not decode TShark JSON for \(url.path): \(error)") }
    guard packets.count < 100_001 else {
        throw AnalysisError.resourceLimit("Decoder returned more than 100,000 frames in one pass from \(url.path). Shorten the refresh interval or narrow the capture.")
    }
    return (packets, errorText)
}

func runPacketDecoder(_ url: URL, arguments: [String]) throws -> (Data, String) {
    let executable = try tsharkExecutable()
    let scratch = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-correlator-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: scratch) }
    let outputURL = scratch.appendingPathComponent("packets.json")
    let errorURL = scratch.appendingPathComponent("decoder.stderr")
    FileManager.default.createFile(atPath: outputURL.path, contents: nil)
    FileManager.default.createFile(atPath: errorURL.path, contents: nil)
    let output = try FileHandle(forWritingTo: outputURL)
    let errors = try FileHandle(forWritingTo: errorURL)
    defer { try? output.close(); try? errors.close() }
    let process = Process()
    process.executableURL = executable
    process.arguments = ["-n", "-2", "-r", url.path] + arguments
    process.standardOutput = output
    process.standardError = errors
    try process.run()
    let deadline = Date().addingTimeInterval(120)
    while process.isRunning {
        if Date() > deadline {
            process.terminate()
            process.waitUntilExit()
            throw AnalysisError.resourceLimit("TShark exceeded 120 seconds while decoding \(url.path). Narrow the capture and retry.")
        }
        Thread.sleep(forTimeInterval: 0.05)
    }
    let errorText = (try? String(contentsOf: errorURL, encoding: .utf8)) ?? ""
    guard process.terminationStatus == 0 else {
        throw AnalysisError.decoderFailed("TShark failed for \(url.path) with exit status \(process.terminationStatus): \(errorText.prefix(4_000))")
    }
    let bytes = try FileManager.default.attributesOfItem(atPath: outputURL.path)[.size] as? NSNumber
    guard let bytes, bytes.intValue <= 256_000_000 else {
        throw AnalysisError.resourceLimit("Decoded packet data exceeds 256 MB for \(url.path). Narrow the capture and retry.")
    }
    return (try Data(contentsOf: outputURL), errorText)
}

public func importCapture(_ url: URL, source: EvidenceSource, offsetMicroseconds: Int64) throws -> ImportedEvidence {
    guard source != .log else { throw AnalysisError.invalidInput("A Unified Log export must be imported as log evidence.") }
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Capture does not exist: \(url.path)") }
    let (hashBefore, byteCount) = try fingerprint(url)
    let (packets, diagnostics) = try decodeCapture(url)
    let dnsRecords = try decodeDNSRecords(url, records: packets.compactMap { Int($0.source.layers["frame.number"]?.strings.first ?? "") }, hasDNS: packets.contains { $0.source.layers["dns.flags.response"]?.strings.contains(where: { $0 == "1" || $0 == "True" }) == true })
    let (hashAfter, _) = try fingerprint(url)
    guard hashBefore == hashAfter else { throw AnalysisError.evidenceChanged("Capture changed during decoding: \(url.path). Re-import a stable copy.") }
    let artifactID = String(hashBefore.prefix(16)) + "-" + source.rawValue
    let observations = try packets.enumerated().map { index, packet -> Observation in
        let fields = packet.source.layers.mapValues(\.strings)
        guard let timestamp = fields["frame.time_epoch"]?.first else {
            throw AnalysisError.decoderFailed("Frame \(index + 1) in \(url.path) has no capture timestamp.")
        }
        let epoch = try parseEpochMicroseconds(timestamp)
        let (adjusted, overflow) = epoch.addingReportingOverflow(offsetMicroseconds)
        guard !overflow else { throw AnalysisError.invalidInput("Clock offset overflows frame \(index + 1) in \(url.path).") }
        let record = Int(fields["frame.number"]?.first ?? "") ?? index + 1
        let protocols = fields["frame.protocols"]?.first?.split(separator: ":").map(String.init) ?? []
        return Observation(id: "\(artifactID):\(record)", source: source, artifactID: artifactID, record: record,
                           originalMicroseconds: epoch, timeMicroseconds: adjusted, protocols: protocols, fields: fields, dnsRecords: dnsRecords[record] ?? [])
    }
    if source == .mac && !observations.isEmpty && !observations.contains(where: { $0.hasProcessCaptureMetadata }) {
        throw AnalysisError.invalidInput("Mac capture \(url.path) has neither decoded PKTAP headers nor Apple PCAPNG process metadata. Capture from pktap and import that PCAPNG file.")
    }
    var warnings: [String] = [try captureTimestampDescription(url)]
    if diagnostics.contains("Malformed") { warnings.append("TShark reported malformed packet data. Inspect decoder diagnostics before relying on affected frames.") }
    if source == .mac && observations.contains(where: { $0.pid == nil }) { warnings.append("Some PKTAP frames have no process ID; process attribution is incomplete.") }
    let artifact = Artifact(id: artifactID, source: source, path: url.path, sha256: hashBefore, bytes: byteCount,
                            records: observations.count, decoder: "TShark", offsetMicroseconds: offsetMicroseconds, warnings: warnings)
    return ImportedEvidence(artifact: artifact, observations: observations)
}

public func importLiveCapture(_ url: URL, source: EvidenceSource, sessionID: String, afterRecord: Int) throws -> ImportedEvidence {
    guard source != .log else { throw AnalysisError.invalidInput("A packet capture cannot use the Unified Log source.") }
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Live capture does not exist: \(url.path)") }
    let (packets, diagnostics) = try decodeGrowingCapture(url, afterRecord: afterRecord)
    let dnsRecords = try decodeDNSRecords(url, records: packets.compactMap { Int($0.source.layers["frame.number"]?.strings.first ?? "") }, hasDNS: packets.contains { $0.source.layers["dns.flags.response"]?.strings.contains(where: { $0 == "1" || $0 == "True" }) == true })
    let artifactID = "\(sessionID)-\(source.rawValue)"
    let observations = try packets.enumerated().map { index, packet -> Observation in
        let fields = packet.source.layers.mapValues(\.strings)
        guard let timestamp = fields["frame.time_epoch"]?.first else {
            throw AnalysisError.decoderFailed("Frame \(index + 1) in \(url.path) has no capture timestamp.")
        }
        let epoch = try parseEpochMicroseconds(timestamp)
        let record = Int(fields["frame.number"]?.first ?? "") ?? index + 1
        let protocols = fields["frame.protocols"]?.first?.split(separator: ":").map(String.init) ?? []
        return Observation(id: "\(artifactID):\(record)", source: source, artifactID: artifactID, record: record,
                           originalMicroseconds: epoch, timeMicroseconds: epoch, protocols: protocols, fields: fields, dnsRecords: dnsRecords[record] ?? [])
    }
    if source == .mac && !observations.isEmpty && !observations.contains(where: { $0.hasProcessCaptureMetadata }) {
        throw AnalysisError.invalidInput("Live Mac capture has packets but neither PKTAP headers nor Apple PCAPNG process metadata: \(url.path). Verify tcpdump -i pktap and PCAPNG output.")
    }
    let bytes = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber
    guard let bytes else { throw AnalysisError.invalidInput("Cannot read live capture size: \(url.path)") }
    let warnings = ["Live file is changing. SHA-256 and packet counts are final only after Stop."] +
        (diagnostics.contains("Malformed") ? ["TShark reported malformed packet data in the live snapshot."] : [])
    let artifact = Artifact(id: artifactID, source: source, path: url.path, sha256: "IN PROGRESS", bytes: bytes.uint64Value,
                            records: observations.count, decoder: "TShark live snapshot", offsetMicroseconds: 0, warnings: warnings)
    return ImportedEvidence(artifact: artifact, observations: observations)
}

public func finalizeLiveCapture(_ url: URL, source: EvidenceSource, sessionID: String, existing: [Observation]) throws -> ImportedEvidence {
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Final capture does not exist: \(url.path)") }
    let (hashBefore, byteCount) = try fingerprint(url)
    let lastRecord = existing.map(\.record).max() ?? 0
    let remaining = try importLiveCapture(url, source: source, sessionID: sessionID, afterRecord: lastRecord)
    let (hashAfter, _) = try fingerprint(url)
    guard hashBefore == hashAfter else { throw AnalysisError.evidenceChanged("Capture changed during final decoding: \(url.path). Stop the collector before finalizing.") }
    let observations = existing + remaining.observations
    let artifact = Artifact(id: "\(sessionID)-\(source.rawValue)", source: source, path: url.path,
                            sha256: hashAfter, bytes: byteCount, records: observations.count, decoder: "TShark incremental",
                            offsetMicroseconds: 0, warnings: remaining.artifact.warnings.filter { !$0.contains("Live file is changing") } + [try captureTimestampDescription(url)])
    return ImportedEvidence(artifact: artifact, observations: observations)
}

public func normalizeLiveLog(_ raw: URL, destination: URL, processIDs: Set<Int>, tokens: Set<String>) throws {
    guard FileManager.default.fileExists(atPath: raw.path) else { throw AnalysisError.invalidInput("Live Unified Log stream does not exist: \(raw.path)") }
    let input = try FileHandle(forReadingFrom: raw)
    defer { try? input.close() }
    let decoder = JSONDecoder()
    var lines: [String] = []
    var carry = Data()
    var lineNumber = 0
    let tokenPatterns = try compileLogTokenPatterns(tokens)
    while true {
        let chunk = try input.read(upToCount: 65_536) ?? Data()
        if chunk.isEmpty { break }
        carry.append(chunk)
        while let newline = carry.firstIndex(of: 10) {
            lineNumber += 1
            let lineData = Data(carry[..<newline])
            carry.removeSubrange(...newline)
            guard let first = lineData.first, first == 123 else { continue }
            if let record = try? decoder.decode(LogRecord.self, from: lineData) {
                guard !record.timestamp.isEmpty, !record.eventMessage.isEmpty else {
                    throw AnalysisError.invalidInput("Unified Log event \(lineNumber) has an empty timestamp or message in \(raw.path).")
                }
                let processName = record.processImagePath.map { URL(fileURLWithPath: $0).lastPathComponent }
                let deviceContext = processName.map { deviceLogProcesses.contains($0) } ?? false
                let endpointContext = record.processID.map { processIDs.contains($0) } == true &&
                    messageMatchesTokens(record.eventMessage, patterns: tokenPatterns)
                if deviceContext || endpointContext {
                    guard let line = String(data: lineData, encoding: .utf8) else {
                        throw AnalysisError.invalidInput("Unified Log line \(lineNumber) is not UTF-8: \(raw.path)")
                    }
                    guard line.hasSuffix("}") else {
                        throw AnalysisError.invalidInput("Unified Log line \(lineNumber) is not a JSON object: \(raw.path)")
                    }
                    let selection = deviceContext ? "device-service context; not a packet match" : "packet PID and bounded endpoint/name mention; context only"
                    lines.append(String(line.dropLast()) + ",\"rviCaptureLine\":\(lineNumber),\"rviCaptureSelection\":\"\(selection)\"}")
                }
            } else if lineData.range(of: Data("\"count\"".utf8)) == nil {
                throw AnalysisError.invalidInput("Unexpected Unified Log JSON at line \(lineNumber) in \(raw.path). Inspect the original stream before continuing.")
            }
        }
        guard carry.count <= 1_000_000 else { throw AnalysisError.resourceLimit("Unified Log line exceeds 1 MB at \(raw.path). Inspect the raw stream.") }
    }
    let result = lines.isEmpty ? "" : lines.joined(separator: "\n") + "\n"
    guard result.utf8.count <= 64_000_000 else { throw AnalysisError.resourceLimit("Matched Unified Log events exceed 64 MB in \(raw.path). Stop and review the raw stream.") }
    try result.write(to: destination, atomically: true, encoding: .utf8)
}

public func importUnifiedLog(_ url: URL, offsetMicroseconds: Int64) throws -> ImportedEvidence {
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Unified Log export does not exist: \(url.path)") }
    let (hashBefore, bytes) = try fingerprint(url)
    guard bytes <= 64_000_000 else { throw AnalysisError.resourceLimit("Unified Log JSON exceeds 64 MB: \(url.path). Export a narrower time range.") }
    let data = try Data(contentsOf: url)
    guard let text = String(data: data, encoding: .utf8) else { throw AnalysisError.invalidInput("Unified Log export must be UTF-8 JSON Lines: \(url.path)") }
    let artifactID = String(hashBefore.prefix(16)) + "-Unified Log"
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ssZ"
    formatter.isLenient = false
    let isoFormatter = ISO8601DateFormatter()
    isoFormatter.formatOptions = [.withInternetDateTime]
    let decoder = JSONDecoder()
    var observations: [Observation] = []
    for (index, line) in text.components(separatedBy: .newlines).enumerated() where !line.isEmpty {
        let event: LogRecord
        do { event = try decoder.decode(LogRecord.self, from: Data(line.utf8)) }
        catch { throw AnalysisError.invalidInput("Invalid Unified Log JSON at line \(index + 1) in \(url.path): \(error)") }
        let stamp = event.timestamp
        let baseText: String
        let microseconds: Int64
        if let dot = stamp.firstIndex(of: ".") {
            let remainder = stamp[stamp.index(after: dot)...]
            let digits = String(remainder.prefix(while: { $0.isNumber }))
            guard !digits.isEmpty, digits.count <= 9 else {
                throw AnalysisError.invalidInput("Invalid fractional timestamp at log line \(index + 1) in \(url.path): \(stamp)")
            }
            baseText = String(stamp[..<dot]) + remainder.dropFirst(digits.count)
            guard let micros = Int64(String(digits.prefix(6)).padding(toLength: 6, withPad: "0", startingAt: 0)) else {
                throw AnalysisError.invalidInput("Invalid fractional timestamp at log line \(index + 1) in \(url.path): \(stamp)")
            }
            microseconds = micros
        } else {
            baseText = stamp
            microseconds = 0
        }
        guard let date = formatter.date(from: baseText) ?? isoFormatter.date(from: baseText) else {
            throw AnalysisError.invalidInput("Invalid Unified Log timestamp at line \(index + 1) in \(url.path): \(stamp)")
        }
        let epoch = Int64(date.timeIntervalSince1970) * 1_000_000 + microseconds
        let (adjusted, overflow) = epoch.addingReportingOverflow(offsetMicroseconds)
        guard !overflow else { throw AnalysisError.invalidInput("Clock offset overflows log line \(index + 1) in \(url.path).") }
        let fields: [String: [String]] = [
            "log.captureSelection": event.rviCaptureSelection.map { [$0] } ?? [],
            "log.bootUUID": event.bootUUID.map { [$0] } ?? [],
            "log.processImageUUID": event.processImageUUID.map { [$0] } ?? [],
            "log.activityIdentifier": event.activityIdentifier.map { [String($0)] } ?? [],
            "log.parentActivityIdentifier": event.parentActivityIdentifier.map { [String($0)] } ?? [],
            "log.traceID": event.traceID.map { [String($0)] } ?? [],
            "log.message": [event.eventMessage], "log.process": [URL(fileURLWithPath: event.processImagePath ?? "unknown").lastPathComponent],
            "log.pid": [event.processID.map(String.init) ?? ""], "log.subsystem": [event.subsystem ?? ""], "log.category": [event.category ?? ""]
        ]
        let recordNumber = event.rviCaptureLine ?? index + 1
        observations.append(Observation(id: "\(artifactID):\(recordNumber)", source: .log, artifactID: artifactID,
                                        record: recordNumber, originalMicroseconds: epoch, timeMicroseconds: adjusted,
                                        protocols: [], fields: fields.filter { !$0.value.allSatisfy(\.isEmpty) }))
    }
    let (hashAfter, _) = try fingerprint(url)
    guard hashBefore == hashAfter else { throw AnalysisError.evidenceChanged("Unified Log export changed during import: \(url.path).") }
    let artifact = Artifact(id: artifactID, source: .log, path: url.path, sha256: hashBefore, bytes: bytes,
                            records: observations.count, decoder: "JSON Lines", offsetMicroseconds: offsetMicroseconds,
                            warnings: ["Unified Log messages can contain <private> redactions; hidden content is not evidence of a match."])
    return ImportedEvidence(artifact: artifact, observations: observations)
}
