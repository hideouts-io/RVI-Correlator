import Foundation

/// An individual answer RR: owner, value and TTL remain paired, including CNAME edges.
public struct DNSResourceRecord: Codable, Hashable, Sendable {
    public let owner: String
    public let type: Int
    public let value: String
    public let ttlSeconds: UInt32
    public init(owner: String, type: Int, value: String, ttlSeconds: UInt32) {
        self.owner = normalizeHostname(owner); self.type = type
        self.value = type == 5 ? normalizeHostname(value) : value
        self.ttlSeconds = ttlSeconds
    }
}

private struct OneOrMany<Value: Decodable>: Decodable {
    let values: [Value]
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let list = try? container.decode([Value].self) { values = list }
        else { values = [try container.decode(Value.self)] }
    }
}

private struct DNSWirePacket: Decodable {
    let source: Source
    enum CodingKeys: String, CodingKey { case source = "_source" }
    struct Source: Decodable { let layers: Layers }
    struct Layers: Decodable {
        let frame: Frame
        let dns: OneOrMany<Message>?
        let mdns: OneOrMany<Message>?
        let llmnr: OneOrMany<Message>?
    }
    struct Frame: Decodable {
        let number: String
        enum CodingKeys: String, CodingKey { case number = "frame.number" }
    }
    struct Message: Decodable {
        let answers: [String: OneOrMany<Record> ]?
        enum CodingKeys: String, CodingKey { case answers = "Answers" }
    }
    struct Record: Decodable {
        let owner: String?
        let type: OneOrMany<String>
        let ttl: String?
        let address: String?
        let address6: String?
        let alias: String?
        enum CodingKeys: String, CodingKey {
            case owner = "dns.resp.name", type = "dns.resp.type", ttl = "dns.resp.ttl"
            case address = "dns.a", address6 = "dns.aaaa", alias = "dns.cname"
        }
    }
}

/// Decode only DNS answer subtrees; flattened field arrays cannot safely pair owners and RDATA.
func decodeDNSRecords(_ url: URL, records: [Int], hasDNS: Bool) throws -> [Int: [DNSResourceRecord]] {
    guard hasDNS, let first = records.min(), let last = records.max() else { return [:] }
    let (data, _) = try runPacketDecoder(url, arguments: ["-c", String(last), "-Y", "dns.flags.response == 1 && frame.number >= \(first)", "-T", "json", "--no-duplicate-keys", "-J", "frame dns mdns llmnr"])
    let packets: [DNSWirePacket]
    do { packets = try JSONDecoder().decode([DNSWirePacket].self, from: data) }
    catch { throw AnalysisError.decoderFailed("Cannot decode structured DNS answers in \(url.path): \(error)") }
    var result: [Int: [DNSResourceRecord]] = [:]
    for packet in packets {
        guard let number = Int(packet.source.layers.frame.number) else { throw AnalysisError.decoderFailed("DNS packet has an invalid frame number in \(url.path).") }
        let layers = packet.source.layers
        let messages = [layers.dns, layers.mdns, layers.llmnr].compactMap { $0 }.flatMap(\.values)
        guard !messages.isEmpty else { throw AnalysisError.decoderFailed("DNS response frame \(number) has no supported DNS, mDNS or LLMNR subtree in \(url.path).") }
        var answers: [DNSResourceRecord] = []
        for message in messages {
            for group in (message.answers ?? [:]).values {
                for record in group.values {
                    guard let firstType = record.type.values.first, let type = Int(firstType) else {
                        throw AnalysisError.decoderFailed("DNS frame \(number) has invalid RR type in \(url.path).")
                    }
                    guard [1, 5, 28].contains(type) else { continue }
                    guard record.type.values.count == 1, let ttlText = record.ttl, let ttl = UInt32(ttlText) else {
                        throw AnalysisError.decoderFailed("DNS frame \(number) has ambiguous RR type or invalid TTL in \(url.path).")
                    }
                    let value = type == 1 ? record.address : type == 28 ? record.address6 : record.alias
                    guard let value, let owner = record.owner, !value.isEmpty, !owner.isEmpty else {
                        throw AnalysisError.decoderFailed("DNS frame \(number) has missing RDATA or owner for type \(type) in \(url.path).")
                    }
                    answers.append(DNSResourceRecord(owner: owner, type: type, value: value, ttlSeconds: ttl))
                }
            }
        }
        result[number] = answers.sorted { ($0.owner, $0.type, $0.value) < ($1.owner, $1.type, $1.value) }
    }
    return result
}
