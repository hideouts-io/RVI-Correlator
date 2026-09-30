import Foundation

public struct PeerPacketPair: Codable, Sendable, Hashable {
    public let iphoneID: String
    public let macID: String
    public let deltaMilliseconds: Double
}

public struct PeerFlow: Identifiable, Codable, Sendable {
    public let id: String
    public let pairs: [PeerPacketPair]
    public let bidirectional: Bool
    public let logIDs: [String]
    public let limitations: [String]
}

public struct PeerReview: Codable, Sendable {
    public let eligiblePhonePackets: Int
    public let ambiguousPhonePackets: Int
    public let unmatchedPhonePackets: Int
    public let insufficientFlowPackets: Int
    public let flows: [PeerFlow]
}

private struct TCPFingerprint: Hashable {
    let source: String
    let destination: String
    let sourcePort: String
    let destinationPort: String
    let sequence: String
    let acknowledgment: String
    let length: String
    let flags: String
}

private func peerFingerprint(_ packet: Observation) -> TCPFingerprint? {
    let sources = packet.values("ip.src") + packet.values("ipv6.src")
    let destinations = packet.values("ip.dst") + packet.values("ipv6.dst")
    let uniqueFields = ["tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "tcp.flags", "tcp.stream"]
    guard sources.count == 1, destinations.count == 1,
          uniqueFields.allSatisfy({ packet.values($0).count == 1 }),
          packet.transport == "TCP", packet.direction != .unknown,
          let source = packet.sourceIP, let destination = packet.destinationIP,
          let sourcePort = packet.sourcePort, let destinationPort = packet.destinationPort,
          let sequence = packet.first("tcp.seq_raw"), let acknowledgment = packet.first("tcp.ack_raw"),
          let length = packet.first("tcp.len"), let flags = packet.first("tcp.flags"),
          packet.first("tcp.stream") != nil, packet.interface != nil else { return nil }
    return TCPFingerprint(source: source, destination: destination, sourcePort: sourcePort,
        destinationPort: destinationPort, sequence: sequence, acknowledgment: acknowledgment, length: length, flags: flags)
}

private func peerLowerBound(_ packets: [Observation], time: Int64) -> Int {
    var lower = 0, upper = packets.count
    while lower < upper {
        let middle = lower + (upper - lower) / 2
        if packets[middle].timeMicroseconds < time { lower = middle + 1 } else { upper = middle }
    }
    return lower
}

/// Reviews possible two-sided TCP observations separately from shared-service correlations.
/// Requires opposite directions, identical wire endpoints and raw TCP header fingerprints,
/// unique pairing in the unchanged search window, and multiple distinct fingerprints per flow.
/// Header equality is not payload equality, causal attribution, or clock calibration.
public func reviewPeerEvidence(_ observations: [Observation], settings: CorrelationSettings) throws -> PeerReview {
    try settings.validate()
    let window = Int64((settings.windowMilliseconds * 1_000).rounded())
    let phones = observations.filter { $0.source == .iphone && peerFingerprint($0) != nil }
    let macs = observations.filter { $0.source == .mac && peerFingerprint($0) != nil && !($0.interface ?? "").hasPrefix("rvi") }
    let indexed = Dictionary(grouping: macs, by: { peerFingerprint($0)! }).mapValues {
        $0.sorted { $0.timeMicroseconds == $1.timeMicroseconds ? $0.id < $1.id : $0.timeMicroseconds < $1.timeMicroseconds }
    }
    let logIndex = Dictionary(grouping: observations.filter { $0.source == .log && $0.pid != nil }, by: { $0.pid ?? "" }).mapValues { $0.sorted { $0.timeMicroseconds < $1.timeMicroseconds } }
    var pairs: [(Observation, Observation)] = []
    var ambiguous = 0, unmatched = 0
    for phone in phones {
        let packets = indexed[peerFingerprint(phone)!] ?? []
        var index = peerLowerBound(packets, time: phone.timeMicroseconds - window)
        var matches: [Observation] = []
        while index < packets.count && packets[index].timeMicroseconds <= phone.timeMicroseconds + window {
            if packets[index].direction != phone.direction { matches.append(packets[index]) }
            index += 1
        }
        if matches.count > 1 { ambiguous += 1 }
        else if let mac = matches.first { pairs.append((phone, mac)) }
        else { unmatched += 1 }
        guard pairs.count <= 20_000 else { throw AnalysisError.resourceLimit("Direct-peer review exceeds 20,000 packet pairs. Narrow the capture before reviewing peer evidence.") }
    }
    let uses = Dictionary(grouping: pairs, by: { $0.1.id })
    let unique = pairs.filter { uses[$0.1.id]?.count == 1 }
    ambiguous += pairs.count - unique.count
    let grouped = Dictionary(grouping: unique, by: { $0.0.streamIdentity + "↔" + $0.1.streamIdentity })
    var flows: [PeerFlow] = []
    var insufficient = 0
    for (key, items) in grouped {
        let signatures = Set(items.compactMap { peerFingerprint($0.0) })
        guard signatures.count >= 2, items.contains(where: { ($0.0.first("tcp.len").flatMap(Int.init) ?? 0) > 0 || $0.0.flag("tcp.flags.syn") }) else {
            insufficient += items.count; continue
        }
        let ordered = items.sorted { $0.0.timeMicroseconds == $1.0.timeMicroseconds ? $0.0.id < $1.0.id : $0.0.timeMicroseconds < $1.0.timeMicroseconds }
        let both = Set(ordered.map { $0.0.direction.rawValue }).count == 2
        let related = Set(ordered.flatMap { relatedLogEvidence($0.0, $0.1, logIndex, window).map(\.id) }).sorted()
        flows.append(PeerFlow(id: key, pairs: ordered.map { PeerPacketPair(iphoneID: $0.0.id, macID: $0.1.id, deltaMilliseconds: Double(abs($0.0.timeMicroseconds - $0.1.timeMicroseconds)) / 1_000) }, bidirectional: both, logIDs: related, limitations: [
            "Inferred two-sided TCP relationship from identical wire endpoints, raw sequence/acknowledgment numbers, payload lengths and flags, with opposite reported capture directions. Header fingerprints are not payload hashes.",
            "Repeated or retransmitted headers can create ambiguous pairings and are not disambiguated by choosing the nearest timestamp. Segmentation/offload can change packet boundaries; no byte-stream reconstruction or payload identity is claimed. Multiple IP layers or repeated fingerprint fields are excluded.",
            "RVI Mac interfaces are excluded. Other forwarding or mirroring paths cannot be ruled out; these observations do not prove physical topology or application causation.",
            "Flow partitions use capture-local stream, interface and process labels. Missing lifecycle evidence, truncated names and PID reuse can split or obscure identity. Labels remain scoped to their own capture.",
            both ? "Both iPhone traffic directions have paired evidence." : "Only one iPhone traffic direction has paired evidence; the reverse path remains unverified.",
            "The configured \(settings.windowMilliseconds) ms window is a search tolerance. No clock correction or latency estimate is derived from these matches; existing clock uncertainty still applies.",
            "Related logs require the same Mac PID/name and a bounded endpoint or hostname mention. They are context only, not independent proof of the paired packet or iPhone process."
        ]))
    }
    return PeerReview(eligiblePhonePackets: phones.count, ambiguousPhonePackets: ambiguous, unmatchedPhonePackets: unmatched,
        insufficientFlowPackets: insufficient, flows: flows.sorted { $0.id < $1.id })
}
