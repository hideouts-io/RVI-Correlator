import Foundation

public struct PacketByteRange: Identifiable, Sendable {
    public let field: String
    public let offset: Int
    public let length: Int
    public var id: String { "\(field):\(offset):\(length)" }
}

public struct RawPacketEvidence: Sendable {
    public let bytes: [UInt8]
    public let ranges: [PacketByteRange]
    public let unmappedFields: [String]
}

private indirect enum RawJSON: Decodable {
    case object([String: RawJSON]), array([RawJSON]), string(String), integer(Int), null

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer()
        if value.decodeNil() { self = .null }
        else if let object = try? value.decode([String: RawJSON].self) { self = .object(object) }
        else if let array = try? value.decode([RawJSON].self) { self = .array(array) }
        else if let string = try? value.decode(String.self) { self = .string(string) }
        else { self = .integer(try value.decode(Int.self)) }
    }

    var object: [String: RawJSON]? { if case .object(let result) = self { return result }; return nil }
    var array: [RawJSON]? { if case .array(let result) = self { return result }; return nil }
    var string: String? { if case .string(let result) = self { return result }; return nil }
    var integer: Int? { if case .integer(let result) = self { return result }; return nil }
}

private func hexBytes(_ hex: String) -> [UInt8]? {
    guard hex.utf8.count.isMultiple(of: 2) else { return nil }
    let characters = Array(hex.utf8)
    var bytes: [UInt8] = []
    bytes.reserveCapacity(characters.count / 2)
    for offset in stride(from: 0, to: characters.count, by: 2) {
        guard let value = UInt8(String(decoding: characters[offset..<(offset + 2)], as: UTF8.self), radix: 16) else { return nil }
        bytes.append(value)
    }
    return bytes
}

private func collectRanges(_ node: RawJSON, fields: Set<String>, bytes: [UInt8]) -> [PacketByteRange] {
    guard let object = node.object else { return [] }
    return object.flatMap { key, value -> [PacketByteRange] in
        if key.hasSuffix("_raw"), fields.contains(String(key.dropLast(4))),
           let parts = value.array, parts.count == 6,
           let hex = parts[0].string, let offset = parts[1].integer, let length = parts[2].integer,
           parts[3].integer == 0, parts[5].integer == 0,
           offset >= 0, length > 0, length <= 262_144, offset <= bytes.count - length,
           let encoded = hexBytes(hex), encoded.count == length,
           Array(bytes[offset..<(offset + length)]) == encoded {
            return [PacketByteRange(field: String(key.dropLast(4)), offset: offset, length: length)]
        }
        return collectRanges(value, fields: fields, bytes: bytes)
    }
}

/// Reads one original frame and accepts only byte ranges whose TShark raw hex exactly matches that frame.
public func inspectRawPacket(_ observation: Observation, artifact: Artifact) throws -> RawPacketEvidence {
    guard observation.source == .iphone || observation.source == .mac, observation.artifactID == artifact.id else {
        throw AnalysisError.invalidInput("Raw packet inspection requires a packet and its matching capture artifact.")
    }
    guard artifact.sha256 != "IN PROGRESS" else {
        throw AnalysisError.invalidInput("Finish this live capture before inspecting original packet bytes and verifying its saved artifact hash.")
    }
    let url = URL(fileURLWithPath: artifact.path)
    guard FileManager.default.fileExists(atPath: url.path) else {
        throw AnalysisError.invalidInput("Original capture is missing at \(url.path). Restore that file or reimport the saved capture before inspecting frame \(observation.record).")
    }
    let (before, _) = try fingerprint(url)
    guard before == artifact.sha256 else {
        throw AnalysisError.evidenceChanged("Capture changed or is missing at \(artifact.path). Expected SHA-256 \(artifact.sha256); found \(before). Reimport the original evidence.")
    }
    let (data, _) = try runPacketDecoder(url, arguments: ["-Y", "frame.number == \(observation.record)", "-T", "jsonraw", "-J", "frame eth arp ip ipv6 icmp icmpv6 tcp udp dns tls http stun quic pktap"])
    let (after, _) = try fingerprint(url)
    guard after == before else { throw AnalysisError.evidenceChanged("Capture changed while inspecting frame \(observation.record) at \(artifact.path).") }
    let root: RawJSON
    do { root = try JSONDecoder().decode(RawJSON.self, from: data) }
    catch { throw AnalysisError.decoderFailed("TShark returned invalid raw JSON for frame \(observation.record) in \(artifact.path): \(error)") }
    guard let packets = root.array, packets.count == 1,
          let layers = packets[0].object?["_source"]?.object?["layers"]?.object,
          let frame = layers["frame_raw"]?.array, frame.count == 6,
          let frameHex = frame[0].string, let bytes = hexBytes(frameHex),
          frame[1].integer == 0, frame[2].integer == bytes.count else {
        throw AnalysisError.decoderFailed("TShark did not return exactly one complete raw frame for record \(observation.record) in \(artifact.path).")
    }
    guard bytes.count <= 262_144 else {
        throw AnalysisError.resourceLimit("Frame \(observation.record) has \(bytes.count) captured bytes; raw inspection is limited to 262,144 bytes per frame.")
    }
    let fields = Set(observation.fields.keys)
    let candidates = collectRanges(.object(layers), fields: fields, bytes: bytes)
    let byID = Dictionary(candidates.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    let verified = byID.values.sorted { ($0.offset, $0.field) < ($1.offset, $1.field) }
    return RawPacketEvidence(bytes: bytes, ranges: verified,
                             unmappedFields: fields.subtracting(verified.map(\.field)).sorted())
}
