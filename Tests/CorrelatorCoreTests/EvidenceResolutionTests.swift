import Foundation
import Testing
@testable import CorrelatorCore

@Test(.enabled(if: ProcessInfo.processInfo.environment["RVI_MDNS_CAPTURE"] != nil))
func importsPhysicalMulticastDNSInSavedAndLivePaths() throws {
    let path = try #require(ProcessInfo.processInfo.environment["RVI_MDNS_CAPTURE"])
    let url = URL(fileURLWithPath: path)
    let saved = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
    let mdns = saved.observations.filter { $0.protocols.contains("mdns") && $0.flag("dns.flags.response") }
    #expect(!mdns.isEmpty)
    let live = try importLiveCapture(url, source: .iphone, sessionID: "physical-mdns-test", afterRecord: 0)
    #expect(live.observations.map(\.dnsRecords) == saved.observations.map(\.dnsRecords))
}

private func packet(_ id: String, source: EvidenceSource, time: Int64, fields: [String: [String]]) -> Observation {
    Observation(id: id, source: source, artifactID: source.rawValue, record: Int(id.split(separator: ":").last ?? "0") ?? 0,
        originalMicroseconds: time, timeMicroseconds: time, protocols: ["ip", "tcp"], fields: fields)
}
private func evidence(_ source: EvidenceSource, packets: [Observation]) -> ImportedEvidence {
    ImportedEvidence(artifact: Artifact(id: source.rawValue, source: source, path: "synthetic adversarial case", sha256: "synthetic", bytes: 0,
        records: packets.count, decoder: "test", offsetMicroseconds: 0, warnings: []), observations: packets)
}

@Test func capturedDNSChainsAreScopedAndExpire() throws {
    let url = try #require(Bundle.module.url(forResource: "iphone-dns-response", withExtension: "pcap", subdirectory: "Fixtures"))
    let imported = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
    let response = imported.observations[1]
    #expect(response.dnsRecords.count == 2)
    #expect(response.dnsRecords.contains { $0.owner == "example.apple.com" && $0.value == "edge.example.net" && $0.ttlSeconds == 60 })
    let client = try #require(response.destinationIP)
    func connection(_ record: Int, source: EvidenceSource, time: Int64, address: String) -> Observation {
        Observation(id: "\(source.rawValue):\(record)", source: source, artifactID: source == .iphone ? response.artifactID : "another-source", record: record,
            originalMicroseconds: time, timeMicroseconds: time, protocols: ["ip", "tcp"],
            fields: ["ip.src": [address], "ip.dst": ["17.0.0.1"], "tcp.srcport": ["51000"], "tcp.dstport": ["443"], "tcp.stream": [String(record)]])
    }
    let valid = connection(10, source: .iphone, time: response.timeMicroseconds + 1_000, address: client)
    let expired = connection(11, source: .iphone, time: response.timeMicroseconds + 60_000_000, address: client)
    let mac = connection(12, source: .mac, time: valid.timeMicroseconds, address: client)
    let otherClient = connection(13, source: .iphone, time: valid.timeMicroseconds, address: "192.0.2.100")
    let names = try resolveHostnames(imported.observations + [valid, expired, mac, otherClient])
    #expect(Set((names[valid.id] ?? []).map(\.name)) == Set(["example.apple.com", "edge.example.net"]))
    #expect(names[valid.id]?.allSatisfy { $0.inferred && $0.origin == .dns && $0.observationIDs.contains(response.id) } == true)
    #expect(names[expired.id] == nil)
    #expect(names[mac.id] == nil)
    #expect(names[otherClient.id] == nil)
    #expect(imported.artifact.warnings.contains { $0.contains("microsecond storage resolution") })
}

@Test func booleanSYNAndBidirectionalMacEvidenceAreExplained() throws {
    let phone = packet("p:1", source: .iphone, time: 1_000_000, fields: ["ip.src": ["192.0.2.10"], "ip.dst": ["203.0.113.5"], "tcp.srcport": ["50000"], "tcp.dstport": ["443"], "tcp.flags.syn": ["True"], "tcp.flags.ack": ["False"]])
    let mac = packet("m:1", source: .mac, time: 1_001_000, fields: ["ip.src": ["203.0.113.5"], "ip.dst": ["192.0.2.20"], "tcp.srcport": ["443"], "tcp.dstport": ["51000"], "pktap.flags": ["0x1"], "pktap.pid": ["321"], "pktap.cmdname": ["apsd"], "pktap.epid": ["500"], "pktap.ecmdname": ["delegate"], "pktap.ifname": ["en0"]])
    #expect(phone.isInitiation)
    #expect(mac.direction == .inbound)
    #expect(mac.effectivePID == "500")
    let result = try correlate([evidence(.iphone, packets: [phone]), evidence(.mac, packets: [mac])], settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: ""), isDemonstration: true)
    let candidate = try #require(result.correlations.first)
    #expect(candidate.confidence == .low)
    #expect(candidate.limitations.contains { $0.contains("inbound response") })
    #expect(result.diagnostics.matchedInitiations == 1)
    #expect(candidate.reasons.first { $0.title == "Time proximity" }?.points == 0)
}

@Test func rejectionDiagnosticsAndPIDReuseDoNotInventMatches() throws {
    let phone = packet("p:1", source: .iphone, time: 1_000_000, fields: ["ip.dst": ["203.0.113.5"], "tcp.srcport": ["50000"], "tcp.dstport": ["443"], "tcp.flags.syn": ["1"], "tcp.flags.ack": ["0"]])
    let mac = packet("m:1", source: .mac, time: 2_000_000, fields: ["ip.dst": ["203.0.113.5"], "tcp.srcport": ["51000"], "tcp.dstport": ["443"], "pktap.flags": ["0x2"], "pktap.pid": ["321"], "pktap.cmdname": ["apsd"], "pktap.ifname": ["en0"]])
    let log = packet("l:1", source: .log, time: 2_000_000, fields: ["log.pid": ["321"], "log.process": ["another-process"], "log.message": ["203.0.113.5"]])
    let inputs = [evidence(.iphone, packets: [phone]), evidence(.mac, packets: [mac]), evidence(.log, packets: [log])]
    let narrow = try correlate(inputs, settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: ""), isDemonstration: true)
    #expect(narrow.correlations.isEmpty)
    #expect(narrow.diagnostics.outsideWindow == 1)
    #expect(narrow.diagnostics.rejections.first?.nearestMilliseconds == 1000)
    let wide = try correlate(inputs, settings: CorrelationSettings(windowMilliseconds: 2000, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: ""), isDemonstration: true)
    #expect(wide.correlations.first?.logIDs.isEmpty == true)
    let sentinel = packet("m:2", source: .mac, time: 2_000_000, fields: ["pktap.pid": ["4294967295"], "pktap.epid": ["0"]])
    #expect(sentinel.pid == nil && sentinel.effectivePID == nil)
}

@Test func calibrationPreservesOriginalsAndReportsResidualDrift() throws {
    let observations = [packet("p:1", source: .iphone, time: 1_000_000, fields: [:]), packet("p:2", source: .iphone, time: 11_000_000, fields: [:]),
        packet("m:1", source: .mac, time: 1_080_000, fields: [:]), packet("m:2", source: .mac, time: 11_082_000, fields: [:])]
    let markers = [ClockMarker(sourceID: "p:1", referenceID: "m:1", identity: "independent marker A"), ClockMarker(sourceID: "p:2", referenceID: "m:2", identity: "independent marker B")]
    let result = try calibrateClock(source: .iphone, markers: markers, observations: observations, measurementUncertaintyMilliseconds: 1, method: "Independent test reference")
    #expect(result.offsetMicroseconds == 81_000)
    #expect(result.residualMilliseconds == 1)
    #expect(result.uncertaintyMilliseconds == 2)
    #expect(result.driftPPM == 200)
    #expect(observations[0].originalMicroseconds == 1_000_000)
    #expect(throws: AnalysisError.self) { try calibrateClock(source: .iphone, markers: [markers[0], markers[0]], observations: observations, measurementUncertaintyMilliseconds: 1, method: "test") }
}

@Test func cnameAcrossResponsesUsesEachTTLAndSupersedingAnswers() throws {
    func response(_ record: Int, time: Int64, records: [DNSResourceRecord]) -> Observation {
        Observation(id: "phone:\(record)", source: .iphone, artifactID: "iPhone RVI", record: record, originalMicroseconds: time, timeMicroseconds: time, protocols: ["dns"],
            fields: ["ip.src": ["192.0.2.53"], "ip.dst": ["192.0.2.10"], "dns.flags.response": ["1"], "dns.flags.rcode": ["0"], "dns.qry.name": [records[0].owner]], dnsRecords: records)
    }
    let alias = response(1, time: 1_000_000, records: [DNSResourceRecord(owner: "alias.example", type: 5, value: "edge.example", ttlSeconds: 2)])
    let address = response(2, time: 2_000_000, records: [DNSResourceRecord(owner: "edge.example", type: 1, value: "203.0.113.5", ttlSeconds: 30)])
    let connectionFields = ["ip.src": ["192.0.2.10"], "ip.dst": ["203.0.113.5"], "tcp.srcport": ["51000"], "tcp.dstport": ["443"]]
    let before = packet("p:3", source: .iphone, time: 2_500_000, fields: connectionFields)
    let after = packet("p:4", source: .iphone, time: 3_000_000, fields: connectionFields)
    let result = try resolveHostnames([alias, address, before, after])
    #expect(Set((result[before.id] ?? []).map(\.name)) == Set(["alias.example", "edge.example"]))
    #expect(result[before.id]?.first { $0.name == "alias.example" }?.observationIDs == [alias.id, address.id])
    #expect((result[after.id] ?? []).map(\.name) == ["edge.example"])
    let expiredUpdate = response(5, time: 2_100_000, records: [DNSResourceRecord(owner: "edge.example", type: 1, value: "203.0.113.5", ttlSeconds: 0)])
    let updated = try resolveHostnames([alias, address, expiredUpdate, before])
    #expect(updated[before.id] == nil)
}

@Test func conflictingHostnamesCapConfidenceAndUnknownProcessesStayUnknown() throws {
    let common = ["ip.dst": ["203.0.113.5"], "tcp.srcport": ["51000"], "tcp.dstport": ["443"], "tls.handshake.type": ["1"], "tcp.stream": ["1"]]
    let phone = packet("p:1", source: .iphone, time: 1_000_000, fields: common.merging(["tls.handshake.extensions_server_name": ["first.example"]]) { _, new in new })
    let mac = packet("m:1", source: .mac, time: 1_001_000, fields: common.merging(["tls.handshake.extensions_server_name": ["other.example"], "pktap.pid": ["321"], "pktap.cmdname": ["apsd"], "pktap.flags": ["2"]]) { _, new in new })
    let result = try correlate([evidence(.iphone, packets: [phone]), evidence(.mac, packets: [mac])], settings: CorrelationSettings(windowMilliseconds: 250, uncertaintyMilliseconds: 1, clocksVerified: true, alignmentMethod: "Independent reference"), isDemonstration: true)
    let candidate = try #require(result.correlations.first)
    #expect(candidate.confidence == .low)
    #expect(candidate.limitations.contains { $0.contains("Conflicting observed hostnames") })
}
