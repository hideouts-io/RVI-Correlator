import Foundation

public enum EvidenceSource: String, Codable, CaseIterable, Sendable {
    case iphone = "iPhone RVI"
    case mac = "Mac PKTAP"
    case log = "Unified Log"
    case iosLog = "iPhone OS trace"
}

public enum Direction: String, Codable, Sendable {
    case inbound, outbound, unknown
}

public struct Observation: Identifiable, Codable, Sendable, Hashable {
    public let id: String
    public let source: EvidenceSource
    public let artifactID: String
    public let record: Int
    public let originalMicroseconds: Int64
    public let timeMicroseconds: Int64
    public let protocols: [String]
    public let fields: [String: [String]]
    public let dnsRecords: [DNSResourceRecord]

    public init(id: String, source: EvidenceSource, artifactID: String, record: Int, originalMicroseconds: Int64, timeMicroseconds: Int64, protocols: [String], fields: [String: [String]]) {
        self.init(id: id, source: source, artifactID: artifactID, record: record, originalMicroseconds: originalMicroseconds, timeMicroseconds: timeMicroseconds, protocols: protocols, fields: fields, dnsRecords: [])
    }

    public init(id: String, source: EvidenceSource, artifactID: String, record: Int, originalMicroseconds: Int64, timeMicroseconds: Int64, protocols: [String], fields: [String: [String]], dnsRecords: [DNSResourceRecord]) {
        self.dnsRecords = dnsRecords
        self.id = id; self.source = source; self.artifactID = artifactID; self.record = record
        self.originalMicroseconds = originalMicroseconds; self.timeMicroseconds = timeMicroseconds
        self.protocols = protocols; self.fields = fields
    }

    public func values(_ key: String) -> [String] { fields[key] ?? [] }
    public func first(_ key: String) -> String? { fields[key]?.first }
    public var process: String? { first("pktap.cmdname") ?? first("frame.darwin.process_info.pname") ?? first("log.process") }
    public var pid: String? { validPID(first("pktap.pid") ?? first("frame.darwin.process_info.pid") ?? first("log.pid")) }
    public var effectivePID: String? { validPID(first("pktap.epid") ?? first("frame.darwin.process_info.epid")) }
    public var effectiveProcess: String? { first("pktap.ecmdname") ?? first("frame.darwin.process_info.epname") }
    public var processIdentity: String { [artifactID, pid ?? "unknown", process ?? "unknown", effectivePID ?? "unknown", effectiveProcess ?? "unknown"].joined(separator: "|") }
    public func flag(_ key: String) -> Bool { values(key).contains { $0 == "1" || $0.lowercased() == "true" } }
    public var interface: String? { first("pktap.ifname") ?? first("frame.interface_name") }
    public var hasProcessCaptureMetadata: Bool {
        first("pktap.ifname") != nil || first("frame.darwin.process_info.pid") != nil
    }
    public var direction: Direction {
        if first("pktap.flags") == nil, let raw = first("frame.packet_flags_direction") {
            let value = raw.hasPrefix("0x") ? UInt32(raw.dropFirst(2), radix: 16) : UInt32(raw)
            switch value { case 1: return .inbound; case 2: return .outbound; default: return .unknown }
        }
        guard let raw = first("pktap.flags") else { return .unknown }
        let flags = raw.hasPrefix("0x") ? UInt32(raw.dropFirst(2), radix: 16) : UInt32(raw)
        guard let flags else { return .unknown }
        switch flags & 3 { case 1: return .inbound; case 2: return .outbound; default: return .unknown }
    }
    public var remoteIP: String? { direction == .inbound ? sourceIP : destinationIP }
    public var remotePort: String? { direction == .inbound ? sourcePort : destinationPort }
    public var isInitiation: Bool { direction != .inbound && hasInitiationSignature }
    public var hasInitiationSignature: Bool {
        if !dnsNames.isEmpty { return !flag("dns.flags.response") }
        if values("tls.handshake.type").contains("1") { return true }
        if protocols.contains("quic") {
            return values("quic.long.packet_type").contains("0") || values("quic.long.packet_type_v2").contains("1")
        }
        return flag("tcp.flags.syn") && !flag("tcp.flags.ack")
    }
    public var sni: [String] { values("tls.handshake.extensions_server_name").map(normalizeHostname) }
    public var dnsNames: [String] { values("dns.qry.name").map(normalizeHostname) }
    public var hostnames: [String] { Array(Set(sni + dnsNames + values("http.host").map(normalizeHostname))).sorted() }
    public var summary: String {
        if source == .log || source == .iosLog { return first("log.message") ?? "Log event" }
        if first("dns.flags.response") == "1" || first("dns.flags.response") == "True" {
            let names = dnsNames.joined(separator: ", ")
            let aliases = values("dns.cname").joined(separator: ", ")
            let addresses = (values("dns.a") + values("dns.aaaa")).joined(separator: ", ")
            let answer = [aliases.isEmpty ? nil : "CNAME \(aliases)", addresses.isEmpty ? nil : addresses].compactMap { $0 }.joined(separator: "; ")
            return answer.isEmpty ? names : "\(names) → \(answer)"
        }
        let names = hostnames.joined(separator: ", ")
        if !names.isEmpty { return names }
        if let destinationIP { return destinationIP + (destinationPort.map { ":\($0)" } ?? "") }
        return first("_ws.col.Info") ?? protocols.joined(separator: " / ")
    }
    public var kind: String {
        if source == .log || source == .iosLog { return first("log.category") ?? "Log event" }
        if !values("dns.qry.name").isEmpty { return first("dns.flags.response") == "1" || first("dns.flags.response") == "True" ? "DNS response" : "DNS query" }
        if protocols.contains("quic") { return sni.isEmpty ? "QUIC" : "QUIC ClientHello" }
        if values("tls.handshake.type").contains("1") { return "TLS ClientHello" }
        return protocols.last?.uppercased() ?? "Packet"
    }
    public var streamIdentity: String {
        let stream = hasAmbiguousPacketLayers ? nil : first("tcp.stream") ?? first("udp.stream")
        return [artifactID, transport ?? "other", stream ?? "frame-\(record)", processIdentity, interface ?? "no-interface"].joined(separator: ":")
    }
}

private func validPID(_ text: String?) -> String? {
    guard let text, let number = Int(text), number > 0, number <= Int(Int32.max) else { return nil }
    return String(number)
}

public func normalizeHostname(_ name: String) -> String {
    name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
}

public struct Artifact: Identifiable, Codable, Sendable {
    public let id: String
    public let source: EvidenceSource
    public let path: String
    public let sha256: String
    public let bytes: UInt64
    public let records: Int
    public let decoder: String
    public let offsetMicroseconds: Int64
    public let warnings: [String]
    public init(id: String, source: EvidenceSource, path: String, sha256: String, bytes: UInt64, records: Int, decoder: String, offsetMicroseconds: Int64, warnings: [String]) {
        self.id = id; self.source = source; self.path = path; self.sha256 = sha256; self.bytes = bytes
        self.records = records; self.decoder = decoder; self.offsetMicroseconds = offsetMicroseconds; self.warnings = warnings
    }
}

public struct ImportedEvidence: Sendable {
    public let artifact: Artifact
    public let observations: [Observation]
    public init(artifact: Artifact, observations: [Observation]) {
        self.artifact = artifact; self.observations = observations
    }
}

public struct CorrelationSettings: Codable, Sendable {
    public let windowMilliseconds: Double
    public let uncertaintyMilliseconds: Double
    public let clocksVerified: Bool
    public let alignmentMethod: String
    public let calibrations: [ClockCalibration]
    public init(windowMilliseconds: Double, uncertaintyMilliseconds: Double, clocksVerified: Bool, alignmentMethod: String) {
        self.init(windowMilliseconds: windowMilliseconds, uncertaintyMilliseconds: uncertaintyMilliseconds, clocksVerified: clocksVerified, alignmentMethod: alignmentMethod, calibrations: [])
    }
    public init(windowMilliseconds: Double, uncertaintyMilliseconds: Double, clocksVerified: Bool, alignmentMethod: String, calibrations: [ClockCalibration]) {
        self.calibrations = calibrations
        self.windowMilliseconds = windowMilliseconds
        self.uncertaintyMilliseconds = uncertaintyMilliseconds
        self.clocksVerified = clocksVerified
        self.alignmentMethod = alignmentMethod
    }
    public func validate() throws {
        guard windowMilliseconds.isFinite, windowMilliseconds > 0, windowMilliseconds <= 60_000 else {
            throw AnalysisError.invalidInput("Correlation window must be greater than 0 and at most 60,000 ms.")
        }
        guard uncertaintyMilliseconds.isFinite, uncertaintyMilliseconds >= 0, uncertaintyMilliseconds <= 60_000 else {
            throw AnalysisError.invalidInput("Clock uncertainty must be between 0 and 60,000 ms.")
        }
        if clocksVerified && alignmentMethod.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw AnalysisError.invalidInput("Describe the evidence for clock alignment before marking clocks verified.")
        }
    }
}

public enum Confidence: String, Codable, Sendable, CaseIterable {
    case high = "High", moderate = "Moderate", low = "Low"
}

public struct EvidenceReason: Codable, Sendable, Hashable {
    public let title: String
    public let detail: String
    public let points: Int
    public let observationIDs: [String]
}

public struct Correlation: Identifiable, Codable, Sendable {
    public let id: String
    public let iphoneID: String
    public let macID: String
    public let logIDs: [String]
    public let deltaMilliseconds: Double
    public let score: Int
    public let confidence: Confidence
    public let reasons: [EvidenceReason]
    public let limitations: [String]
    public let alternativeProcesses: Int
}

public struct Investigation: Codable, Sendable {
    public let schemaVersion: Int
    public let generatedAt: Date
    public let isDemonstration: Bool
    public let settings: CorrelationSettings
    public let artifacts: [Artifact]
    public let observations: [Observation]
    public let sessions: [PacketSession]
    public let correlations: [Correlation]
    public let interpretation: String
    public let diagnostics: CorrelationDiagnostics
    public let peerReview: PeerReview
    public let hostnameEvidence: [String: [HostnameEvidence]]
}

public let interpretationNotice = "Temporal correlation does not prove causation. A PKTAP process label describes Mac-side traffic; it does not identify the process responsible for iPhone traffic. Confidence is a transparent evidence-strength rubric, not a calibrated probability or proof of attribution."

public enum AnalysisError: LocalizedError, Sendable {
    case invalidInput(String)
    case decoderFailed(String)
    case resourceLimit(String)
    case evidenceChanged(String)
    public var errorDescription: String? {
        switch self { case .invalidInput(let text), .decoderFailed(let text), .resourceLimit(let text), .evidenceChanged(let text): return text }
    }
}
