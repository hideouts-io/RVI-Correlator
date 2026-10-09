import Foundation

public struct PacketEndpoint: Codable, Hashable, Sendable, Comparable {
    public let address: String
    public let port: UInt16

    public static func < (left: Self, right: Self) -> Bool {
        if left.address != right.address { return left.address < right.address }
        return left.port < right.port
    }
}

public struct PacketSession: Codable, Identifiable, Sendable {
    public let id: String
    public let source: EvidenceSource
    public let artifactID: String
    public let interface: String?
    public let transport: String
    public let firstEndpoint: PacketEndpoint
    public let secondEndpoint: PacketEndpoint
    public let stream: String
    public let firstMicroseconds: Int64
    public let lastMicroseconds: Int64
    public let packetIDs: [String]
    public let hostnameEvidence: [HostnameEvidence]
    public let processLabels: [String]
    public let correlationIDs: [String]
    public let peerFlowIDs: [String]
    public let logIDs: [String]
}

private struct SessionKey: Hashable {
    let source: EvidenceSource
    let artifactID: String
    let interface: String?
    let transport: String
    let firstEndpoint: PacketEndpoint
    let secondEndpoint: PacketEndpoint
    let stream: String
    let processIdentity: String
}

private func sessionKey(_ packet: Observation) -> SessionKey? {
    guard packet.source == .iphone || packet.source == .mac,
          let sourceIP = packet.sourceIP, let destinationIP = packet.destinationIP,
          let sourcePort = packet.sourcePort.flatMap(UInt16.init),
          let destinationPort = packet.destinationPort.flatMap(UInt16.init),
          let transport = packet.transport,
          let stream = packet.first(transport == "TCP" ? "tcp.stream" : "udp.stream"),
          !stream.isEmpty else { return nil }
    let source = PacketEndpoint(address: sourceIP, port: sourcePort)
    let destination = PacketEndpoint(address: destinationIP, port: destinationPort)
    return SessionKey(source: packet.source, artifactID: packet.artifactID, interface: packet.interface,
                      transport: transport, firstEndpoint: min(source, destination), secondEndpoint: max(source, destination),
                      stream: stream, processIdentity: packet.processIdentity)
}

/// Groups observed packets inside one capture stream; cross-source candidates remain separate inferred links.
public func packetSessions(_ observations: [Observation], hostnameEvidence: [String: [HostnameEvidence]], correlations: [Correlation], peerReview: PeerReview) -> [PacketSession] {
    let links = Dictionary(grouping: correlations.flatMap { correlation in
        [(correlation.iphoneID, correlation), (correlation.macID, correlation)]
    }, by: \.0)
    let peerLinks = Dictionary(grouping: peerReview.flows.flatMap { flow in
        flow.pairs.flatMap { [($0.iphoneID, flow), ($0.macID, flow)] }
    }, by: \.0)
    let grouped = Dictionary(grouping: observations.compactMap { packet -> (SessionKey, Observation)? in
        sessionKey(packet).map { ($0, packet) }
    }, by: \.0)
    return grouped.compactMap { key, members -> PacketSession? in
        let packets = members.map(\.1).sorted { ($0.timeMicroseconds, $0.record) < ($1.timeMicroseconds, $1.record) }
        guard let first = packets.first, let last = packets.last else { return nil }
        let candidates = packets.flatMap { links[$0.id]?.map(\.1) ?? [] }
        let peers = packets.flatMap { peerLinks[$0.id]?.map(\.1) ?? [] }
        let hostnames = Array(Set(packets.flatMap { hostnameEvidence[$0.id] ?? [] })).sorted {
            ($0.name, $0.origin.rawValue, $0.observationIDs.joined()) < ($1.name, $1.origin.rawValue, $1.observationIDs.joined())
        }
        let labels = Set(packets.map { "\($0.process ?? "Unknown process") · PID \($0.pid ?? "unknown")" })
        return PacketSession(id: "\(first.id):session", source: key.source, artifactID: key.artifactID,
                             interface: key.interface, transport: key.transport, firstEndpoint: key.firstEndpoint,
                             secondEndpoint: key.secondEndpoint, stream: key.stream,
                             firstMicroseconds: first.timeMicroseconds, lastMicroseconds: last.timeMicroseconds,
                             packetIDs: packets.map(\.id), hostnameEvidence: hostnames,
                             processLabels: key.source == .mac ? labels.sorted() : [],
                             correlationIDs: Array(Set(candidates.map(\.id))).sorted(),
                             peerFlowIDs: Array(Set(peers.map(\.id))).sorted(),
                             logIDs: Array(Set(candidates.flatMap(\.logIDs) + peers.flatMap(\.logIDs))).sorted())
    }.sorted { ($0.firstMicroseconds, $0.id) < ($1.firstMicroseconds, $1.id) }
}
