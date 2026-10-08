import Foundation
import Testing
@testable import CorrelatorCore

private func little32(_ value: UInt32) -> Data {
    Data([UInt8(value & 255), UInt8((value >> 8) & 255), UInt8((value >> 16) & 255), UInt8(value >> 24)])
}

private func ethernetCapture(_ payload: Data, etherType: UInt16) -> Data {
    let frame = Data([2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, UInt8(etherType >> 8), UInt8(etherType & 255)]) + payload
    let header = Data([0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 1, 0, 0, 0])
    return header + little32(1_790_500_383) + little32(414_421) + little32(UInt32(frame.count)) + little32(UInt32(frame.count)) + frame
}

private func tcpSYNBytes() -> Data {
    Data([0xc7, 0x38, 1, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 2, 255, 255, 0, 0, 0, 0])
}

private func ipv6Header() -> Data {
    Data([0x60, 0, 0, 0, 0, 20, 6, 64,
          0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
          0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5])
}

private func nestedIPv4IPv6() -> Data {
    let outer = Data([0x45, 0, 0, 0x50, 0, 1, 0, 0, 64, 0x29, 0x13, 0xe3, 198, 51, 100, 10, 203, 0, 113, 99])
    return ethernetCapture(outer + ipv6Header() + tcpSYNBytes(), etherType: 0x0800)
}

private func nestedIPv4IPv4() -> Data {
    let outer = Data([0x45, 0, 0, 0x3c, 0, 1, 0, 0, 64, 4, 0x14, 0x1c, 198, 51, 100, 10, 203, 0, 113, 99])
    let inner = Data([0x45, 0, 0, 0x28, 0, 1, 0, 0, 64, 6, 0xf6, 0xbf, 192, 0, 2, 10, 192, 0, 2, 5])
    return ethernetCapture(outer + inner + tcpSYNBytes(), etherType: 0x0800)
}

@Test func realNestedPacketsRetainRawFieldsWithoutScoredEndpoints() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-endpoint-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    for (index, data) in [nestedIPv4IPv6(), nestedIPv4IPv4()].enumerated() {
        let url = directory.appendingPathComponent("nested-\(index).pcap")
        try data.write(to: url)
        let imported = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
        let phone = try #require(imported.observations.first)
        #expect(phone.first("ip.dst") == "203.0.113.99")
        #expect(phone.first("tcp.dstport") == "443")
        #expect(phone.hasAmbiguousPacketLayers && phone.remoteIP == nil && phone.remotePort == nil)
        #expect(imported.artifact.warnings.contains { $0.contains("mixed IP") })
        let first = try importLiveCapture(url, source: .iphone, sessionID: "warning", afterRecord: 0)
        let clean = try importLiveCapture(url, source: .iphone, sessionID: "warning", afterRecord: 1)
        #expect(clean.observations.isEmpty)
        let refreshed = try mergeLiveCapture(first, update: clean)
        #expect(refreshed.observations.count == 1)
        #expect(refreshed.artifact.warnings.contains { $0.contains("mixed IP") })
        let raw = try inspectRawPacket(phone, artifact: imported.artifact)
        #expect(raw.bytes.count == (index == 0 ? 94 : 74))
        let mac = Observation(id: "mac:1", source: .mac, artifactID: "mac", record: 1,
            originalMicroseconds: phone.originalMicroseconds, timeMicroseconds: phone.timeMicroseconds,
            protocols: ["ip", "tcp"], fields: ["ip.src": ["192.0.2.20"], "ip.dst": ["203.0.113.99"],
                "tcp.srcport": ["51001"], "tcp.dstport": ["443"], "tcp.stream": ["0"],
                "pktap.pid": ["123"], "pktap.cmdname": ["apsd"], "pktap.flags": ["2"], "pktap.ifname": ["en0"]])
        let artifact = Artifact(id: "mac", source: .mac, path: "synthetic endpoint control", sha256: "synthetic", bytes: 0,
            records: 1, decoder: "synthetic", offsetMicroseconds: 0, warnings: [])
        let result = try correlate([imported, ImportedEvidence(artifact: artifact, observations: [mac])],
            settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 0, clocksVerified: false, alignmentMethod: ""), isDemonstration: true)
        #expect(result.correlations.isEmpty)
        #expect(result.sessions.allSatisfy { $0.source != .iphone })
        #expect(result.diagnostics.rejections.first?.reason.contains("Ambiguous") == true)
    }
}

@Test func singleIPv6ExtensionAndRepeatedApplicationFieldsRemainEligible() throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-ipv6-\(UUID().uuidString).pcap")
    defer { try? FileManager.default.removeItem(at: url) }
    var header = ipv6Header()
    header[5] = 28; header[6] = 0
    try ethernetCapture(header + Data([6, 0, 1, 4, 0, 0, 0, 0]) + tcpSYNBytes(), etherType: 0x86dd).write(to: url)
    let packet = try #require(importCapture(url, source: .iphone, offsetMicroseconds: 0).observations.first)
    #expect(!packet.hasAmbiguousPacketLayers)
    #expect(packet.destinationIP == "2001:db8::5" && packet.destinationPort == "443")
    let fields = packet.fields.merging(["dns.qry.name": ["one.example", "two.example"], "tls.handshake.type": ["1", "2"]]) { _, new in new }
    let application = Observation(id: packet.id, source: packet.source, artifactID: packet.artifactID, record: packet.record,
        originalMicroseconds: packet.originalMicroseconds, timeMicroseconds: packet.timeMicroseconds, protocols: packet.protocols, fields: fields)
    #expect(!application.hasAmbiguousPacketLayers && application.destinationPort == "443")
}

@Test func equalRepeatedLayersAndMixedTransportsCannotFormEndpoints() {
    let base: [String: [String]] = ["ip.src": ["192.0.2.10"], "ip.dst": ["203.0.113.5"], "tcp.srcport": ["51000"], "tcp.dstport": ["443"], "tcp.stream": ["0"]]
    for additional in [["ip.dst": ["203.0.113.5", "203.0.113.5"]], ["tcp.stream": ["0", "0"]],
                       ["udp.srcport": ["51000"], "udp.dstport": ["443"]]] {
        let packet = Observation(id: "p:1", source: .iphone, artifactID: "p", record: 1,
            originalMicroseconds: 1, timeMicroseconds: 1, protocols: ["ip", "tcp"], fields: base.merging(additional) { _, new in new })
        #expect(packet.hasAmbiguousPacketLayers && packet.destinationIP == nil && packet.destinationPort == nil)
    }
    let fragment = Observation(id: "p:2", source: .iphone, artifactID: "p", record: 2,
        originalMicroseconds: 1, timeMicroseconds: 1, protocols: ["ip"], fields: ["ip.src": ["192.0.2.10"], "ip.dst": ["203.0.113.5"]])
    #expect(!fragment.hasAmbiguousPacketLayers && fragment.destinationIP == "203.0.113.5" && fragment.destinationPort == nil)
}
