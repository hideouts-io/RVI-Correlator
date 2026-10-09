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

struct LogRecord: Codable {
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
    func annotated(line: Int, selection: String) -> LogRecord {
        LogRecord(timestamp: timestamp, eventMessage: eventMessage, processImagePath: processImagePath,
            processID: processID, subsystem: subsystem, category: category, rviCaptureLine: line,
            rviCaptureSelection: selection, bootUUID: bootUUID, processImageUUID: processImageUUID,
            activityIdentifier: activityIdentifier, parentActivityIdentifier: parentActivityIdentifier, traceID: traceID)
    }

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

func fingerprint(_ url: URL) throws -> (String, UInt64) {
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
    var budget = PacketBudget(records: 0, bytes: 0)
    var diagnosticBytes = 0
    while true {
        let (end, overflow) = cursor.addingReportingOverflow(50_000)
        guard !overflow else { throw AnalysisError.invalidInput("Frame cursor exceeds the supported range.") }
        let (batch, diagnostic, decodedBytes) = try decodePackets(url, selection: ["-c", String(end), "-Y", "frame.number > \(cursor)"])
        let limit = PacketBudget(records: maximumPacketRecords, bytes: maximumPacketBytes)
        var retained = try addingPacketBudget(PacketBudget(records: 0, bytes: 0), records: batch.count, bytes: 384 * batch.count, limit: limit)
        for packet in batch {
            retained = try addingPacketFields(packet.source.layers.mapValues(\.strings), budget: retained, limit: limit)
        }
        budget = try addingPacketBudget(budget, records: batch.count, bytes: max(decodedBytes, retained.bytes), limit: limit)
        guard diagnostic.utf8.count + 1 <= 1_000_000 - diagnosticBytes else {
            throw AnalysisError.resourceLimit("Aggregate decoder diagnostics exceed 1 MB. Narrow this capture.")
        }
        diagnosticBytes += diagnostic.utf8.count + 1
        packets.append(contentsOf: batch)
        if !diagnostic.isEmpty { diagnostics.append(diagnostic) }
        if batch.count < 50_000 { break }
        cursor = end
    }
    return (packets, diagnostics.joined(separator: "\n"))
}

private func decodePackets(_ url: URL, selection: [String]) throws -> ([TSharkPacket], String, Int) {
    let (data, errorText) = try runPacketDecoder(url, arguments: selection + ["-T", "json", "--no-duplicate-keys"] + packetFields.flatMap { ["-e", $0] })
    let packets: [TSharkPacket]
    do { packets = try JSONDecoder().decode([TSharkPacket].self, from: data) }
    catch { throw AnalysisError.decoderFailed("Could not decode TShark JSON for \(url.path): \(error)") }
    guard packets.count < 100_001 else {
        throw AnalysisError.resourceLimit("Decoder returned more than 100,000 frames in one pass from \(url.path). Shorten the refresh interval or narrow the capture.")
    }
    return (packets, errorText, data.count)
}

func runPacketDecoder(_ url: URL, arguments: [String]) throws -> (Data, String) {
    let (data, diagnostic) = try runBoundedProcess(tsharkExecutable(), arguments: ["-n", "-2", "-r", url.path] + arguments,
        limits: ProcessOutputLimits(stdoutBytes: maximumPacketBytes, stderrBytes: 1_000_000, seconds: 120))
    return (data, String(decoding: diagnostic, as: UTF8.self))
}

public func importCapture(_ url: URL, source: EvidenceSource, offsetMicroseconds: Int64) throws -> ImportedEvidence {
    guard source == .iphone || source == .mac else { throw AnalysisError.invalidInput("A log export must be imported as log evidence.") }
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
    var warnings: [String] = [try captureTimestampDescription(url)] + packetLayerWarnings(observations)
    if diagnostics.contains("Malformed") { warnings.append("TShark reported malformed packet data. Inspect decoder diagnostics before relying on affected frames.") }
    if source == .mac && observations.contains(where: { $0.pid == nil }) { warnings.append("Some PKTAP frames have no process ID; process attribution is incomplete.") }
    let artifact = Artifact(id: artifactID, source: source, path: url.path, sha256: hashBefore, bytes: byteCount,
                            records: observations.count, decoder: "TShark", offsetMicroseconds: offsetMicroseconds, warnings: warnings)
    return ImportedEvidence(artifact: artifact, observations: try appendPacketObservations([], incoming: observations))
}

public func importLiveCapture(_ url: URL, source: EvidenceSource, sessionID: String, afterRecord: Int) throws -> ImportedEvidence {
    guard source == .iphone || source == .mac else { throw AnalysisError.invalidInput("A packet capture cannot use a log source.") }
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
        (diagnostics.contains("Malformed") ? ["TShark reported malformed packet data in the live snapshot."] : []) + packetLayerWarnings(observations)
    let artifact = Artifact(id: artifactID, source: source, path: url.path, sha256: "IN PROGRESS", bytes: bytes.uint64Value,
                            records: observations.count, decoder: "TShark live snapshot", offsetMicroseconds: 0, warnings: warnings)
    return ImportedEvidence(artifact: artifact, observations: try appendPacketObservations([], incoming: observations))
}

/// Merge a refresh into the same capture, retaining ambiguity diagnostics across clean tails.
public func mergeLiveCapture(_ previous: ImportedEvidence, update: ImportedEvidence) throws -> ImportedEvidence {
    let old = update.artifact
    guard old.source == .iphone || old.source == .mac,
          previous.artifact.id == old.id, previous.artifact.source == old.source else {
        throw AnalysisError.invalidInput("Live packet refresh must belong to the same source and session artifact.")
    }
    let observations = try appendPacketObservations(previous.observations, incoming: update.observations)
    let warnings = old.warnings + packetLayerWarnings(observations).filter { !old.warnings.contains($0) }
    let artifact = Artifact(id: old.id, source: old.source, path: old.path, sha256: old.sha256, bytes: old.bytes,
        records: observations.count, decoder: old.decoder, offsetMicroseconds: old.offsetMicroseconds, warnings: warnings)
    return ImportedEvidence(artifact: artifact, observations: observations)
}

public func finalizeLiveCapture(_ url: URL, source: EvidenceSource, sessionID: String, existing: [Observation]) throws -> ImportedEvidence {
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Final capture does not exist: \(url.path)") }
    let (hashBefore, byteCount) = try fingerprint(url)
    let lastRecord = existing.map(\.record).max() ?? 0
    let remaining = try importLiveCapture(url, source: source, sessionID: sessionID, afterRecord: lastRecord)
    let (hashAfter, _) = try fingerprint(url)
    guard hashBefore == hashAfter else { throw AnalysisError.evidenceChanged("Capture changed during final decoding: \(url.path). Stop the collector before finalizing.") }
    let observations = try appendPacketObservations(existing, incoming: remaining.observations)
    let artifact = Artifact(id: "\(sessionID)-\(source.rawValue)", source: source, path: url.path,
                            sha256: hashAfter, bytes: byteCount, records: observations.count, decoder: "TShark incremental",
                            offsetMicroseconds: 0, warnings: remaining.artifact.warnings.filter { !$0.contains("Live file is changing") } + [try captureTimestampDescription(url)] + packetLayerWarnings(observations).filter { !remaining.artifact.warnings.contains($0) })
    return ImportedEvidence(artifact: artifact, observations: observations)
}

public func importUnifiedLog(_ url: URL, offsetMicroseconds: Int64) throws -> ImportedEvidence {
    guard FileManager.default.fileExists(atPath: url.path) else { throw AnalysisError.invalidInput("Unified Log export does not exist: \(url.path)") }
    let (hashBefore, bytes) = try fingerprint(url)
    guard bytes <= 64_000_000 else { throw AnalysisError.resourceLimit("Unified Log JSON exceeds 64 MB: \(url.path). Export a narrower time range.") }
    let data = try readBoundedFile(url, maximumBytes: 64_000_000)
    guard String(data: data, encoding: .utf8) != nil else { throw AnalysisError.invalidInput("Unified Log export must be UTF-8 JSON Lines: \(url.path)") }
    let artifactID = String(hashBefore.prefix(16)) + "-Unified Log"
    let timestampParser = UnifiedLogTimestampParser()
    let decoder = JSONDecoder()
    var observations: [Observation] = []
    for (index, line) in data.split(separator: 10, omittingEmptySubsequences: false).enumerated() where !line.isEmpty {
        if line.allSatisfy({ $0 == 9 || $0 == 13 || $0 == 32 }) { continue }
        let event: LogRecord
        do { event = try decoder.decode(LogRecord.self, from: Data(line)) }
        catch { throw AnalysisError.invalidInput("Invalid Unified Log JSON at line \(index + 1) in \(url.path): \(error)") }
        guard event.rviCaptureLine.map({ $0 > 0 }) != false else {
            throw AnalysisError.invalidInput("Unified Log source line metadata must be positive at export line \(index + 1).")
        }
        let epoch: Int64
        do { epoch = try timestampParser.microseconds(event.timestamp) }
        catch let error as AnalysisError {
            throw AnalysisError.invalidInput("Invalid Unified Log timestamp at line \(index + 1) in \(url.path): \(error.localizedDescription)")
        }
        let (adjusted, overflow) = epoch.addingReportingOverflow(offsetMicroseconds)
        guard !overflow else { throw AnalysisError.invalidInput("Clock offset overflows log line \(index + 1) in \(url.path).") }
        let fields: [String: [String]] = [
            "log.captureLine": event.rviCaptureLine.map { [String($0)] } ?? [],
            "log.captureSelection": event.rviCaptureSelection.map { [$0] } ?? [],
            "log.bootUUID": event.bootUUID.map { [$0] } ?? [],
            "log.processImageUUID": event.processImageUUID.map { [$0] } ?? [],
            "log.activityIdentifier": event.activityIdentifier.map { [String($0)] } ?? [],
            "log.parentActivityIdentifier": event.parentActivityIdentifier.map { [String($0)] } ?? [],
            "log.traceID": event.traceID.map { [String($0)] } ?? [],
            "log.message": [event.eventMessage], "log.process": [URL(fileURLWithPath: event.processImagePath ?? "unknown").lastPathComponent],
            "log.pid": [event.processID.map(String.init) ?? ""], "log.subsystem": [event.subsystem ?? ""], "log.category": [event.category ?? ""]
        ]
        let recordNumber = index + 1
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
