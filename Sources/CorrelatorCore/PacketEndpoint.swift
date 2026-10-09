import Foundation

private struct PacketNetworkHeader {
    let source: String
    let destination: String
}

private struct PacketTransportHeader {
    let source: UInt16
    let destination: UInt16
    let name: String
}

extension Observation {
    /// Flattened decoder fields do not bind ports to a particular encapsulated header.
    /// Repeated values remain ambiguous even when equal; raw arrays are never discarded.
    public var hasAmbiguousPacketLayers: Bool {
        let addresses = ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]
        let transport = ["tcp.srcport", "tcp.dstport", "tcp.stream", "udp.srcport", "udp.dstport", "udp.stream"]
        if (addresses + transport).contains(where: { values($0).count > 1 }) { return true }
        let ipv4 = !values("ip.src").isEmpty || !values("ip.dst").isEmpty
        let ipv6 = !values("ipv6.src").isEmpty || !values("ipv6.dst").isEmpty
        let tcp = protocols.contains("tcp") || transport.prefix(3).contains(where: { !values($0).isEmpty })
        let udp = protocols.contains("udp") || transport.suffix(3).contains(where: { !values($0).isEmpty })
        return (ipv4 && ipv6) || (tcp && udp) ||
            protocols.filter { $0 == "ip" || $0 == "ipv6" }.count > 1 ||
            protocols.filter { $0 == "tcp" || $0 == "udp" }.count > 1
    }

    private var networkHeader: PacketNetworkHeader? {
        guard !hasAmbiguousPacketLayers else { return nil }
        for family in ["ip", "ipv6"] {
            let sources = values("\(family).src"), destinations = values("\(family).dst")
            if sources.count == 1, destinations.count == 1 {
                return PacketNetworkHeader(source: sources[0], destination: destinations[0])
            }
        }
        return nil
    }

    private var transportHeader: PacketTransportHeader? {
        guard networkHeader != nil else { return nil }
        for family in ["tcp", "udp"] {
            let sources = values("\(family).srcport"), destinations = values("\(family).dstport")
            if sources.count == 1, destinations.count == 1,
               let source = UInt16(sources[0]), let destination = UInt16(destinations[0]) {
                return PacketTransportHeader(source: source, destination: destination, name: family.uppercased())
            }
        }
        return nil
    }

    public var sourceIP: String? { networkHeader?.source }
    public var destinationIP: String? { networkHeader?.destination }
    public var sourcePort: String? { transportHeader.map { String($0.source) } }
    public var destinationPort: String? { transportHeader.map { String($0.destination) } }
    public var transport: String? { transportHeader?.name }
}

func packetLayerWarnings(_ observations: [Observation]) -> [String] {
    observations.contains(where: \.hasAmbiguousPacketLayers)
        ? ["Packets with repeated or mixed IP/transport layers retain their raw fields but are excluded from derived endpoint scoring and session grouping. Inspect the original packet layers."] : []
}
