import Foundation
import Testing
@testable import CorrelatorCore

@Test func filtersSimulatorsAndRequiresUSBForLiveCapture() throws {
    let json = """
    {"result":{"devices":[
      {"hardwareProperties":{"udid":"simulator","reality":"simulated","deviceType":"iPhone","platform":"iOS"},"deviceProperties":{"name":"Simulator"},"connectionProperties":{"pairingState":"paired","tunnelState":"connected","transportType":"sameMachine"}},
      {"hardwareProperties":{"udid":"wifi-phone","reality":"physical","deviceType":"iPhone","platform":"iOS"},"deviceProperties":{"name":"Wi-Fi iPhone"},"connectionProperties":{"pairingState":"paired","tunnelState":"connected","transportType":"localNetwork"}},
      {"hardwareProperties":{"udid":"usb-phone","reality":"physical","deviceType":"iPhone","platform":"iOS"},"deviceProperties":{"name":"USB iPhone"},"connectionProperties":{"pairingState":"paired","tunnelState":"connected","transportType":"wired"}}
    ]}}
    """
    let devices = try parseCaptureDevices(Data(json.utf8), usbSerials: ["usb-phone"])
    #expect(devices.map(\.id) == ["wifi-phone", "usb-phone"])
    #expect(devices[0].isConnected == false)
    #expect(devices[0].connection.contains("Wi-Fi"))
    #expect(devices[1].isConnected == true)
    #expect(devices[1].connection.contains("USB"))
    let tunnelUnavailable = json.replacingOccurrences(of: "\"tunnelState\":\"connected\"", with: "\"tunnelState\":\"unavailable\"")
    #expect(try parseCaptureDevices(Data(tunnelUnavailable.utf8), usbSerials: ["usbphone"])[1].isConnected)
    #expect(try parseCaptureDevices(Data(json.utf8), usbSerials: []).allSatisfy { !$0.isConnected })
}

@Test func importsDecodedPKTAPAndCorrelatesWithoutCausalClaim() throws {
    let phoneURL = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let macURL = try #require(Bundle.module.url(forResource: "mac-pktap", withExtension: "pcap", subdirectory: "Fixtures"))
    let phone = try importCapture(phoneURL, source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(macURL, source: .mac, offsetMicroseconds: 0)
    #expect(mac.observations.first?.process == "apsd")
    #expect(mac.observations.first?.direction == .outbound)
    #expect(phone.observations.first?.dnsNames == ["example.apple.com"])
    let investigation = try correlate([phone, mac], settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 1, clocksVerified: false, alignmentMethod: ""), isDemonstration: false)
    #expect(investigation.correlations.count == 1)
    #expect(investigation.correlations[0].confidence == .moderate)
    #expect(investigation.correlations[0].reasons.contains { $0.title == "DNS query match" })
    #expect(investigation.correlations[0].limitations.contains { $0.contains("does not prove causation") })
}

@Test func rejectsTimestampOnlyAndUnverifiedHighConfidence() throws {
    let first = Observation(id: "p:1", source: .iphone, artifactID: "p", record: 1, originalMicroseconds: 1_000_000, timeMicroseconds: 1_000_000,
                            protocols: ["ip", "tcp", "tls"], fields: ["ip.dst": ["203.0.113.5"], "tcp.srcport": ["50000"], "tcp.dstport": ["443"], "tls.handshake.type": ["1"], "tls.handshake.extensions_server_name": ["example.apple.com"], "tcp.stream": ["1"]])
    let mac = Observation(id: "m:1", source: .mac, artifactID: "m", record: 1, originalMicroseconds: 1_005_000, timeMicroseconds: 1_005_000,
                          protocols: ["pktap", "ip", "tcp", "tls"], fields: ["ip.dst": ["203.0.113.6"], "tcp.srcport": ["50001"], "tcp.dstport": ["443"], "tls.handshake.type": ["1"], "tls.handshake.extensions_server_name": ["example.apple.com"], "pktap.pid": ["423"], "pktap.cmdname": ["apsd"], "pktap.ifname": ["en0"], "pktap.flags": ["0x2"], "tcp.stream": ["2"]])
    let pa = Artifact(id: "p", source: .iphone, path: "fixture", sha256: "synthetic", bytes: 0, records: 1, decoder: "fixture", offsetMicroseconds: 0, warnings: [])
    let ma = Artifact(id: "m", source: .mac, path: "fixture", sha256: "synthetic", bytes: 0, records: 1, decoder: "fixture", offsetMicroseconds: 0, warnings: [])
    let a = ImportedEvidence(artifact: pa, observations: [first])
    let b = ImportedEvidence(artifact: ma, observations: [mac])
    let result = try correlate([a, b], settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 1, clocksVerified: true, alignmentMethod: "Measured against shared UTC reference"), isDemonstration: true)
    #expect(result.correlations.isEmpty)
    let matchedMac = Observation(id: "m:2", source: .mac, artifactID: "m", record: 2, originalMicroseconds: 1_005_000, timeMicroseconds: 1_005_000,
                                 protocols: mac.protocols, fields: mac.fields.merging(["ip.dst": ["203.0.113.5"]]) { _, new in new })
    let matched = try correlate([a, ImportedEvidence(artifact: ma, observations: [matchedMac])], settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 1, clocksVerified: false, alignmentMethod: ""), isDemonstration: true)
    #expect(matched.correlations.count == 1)
    #expect(matched.correlations[0].confidence != .high)
}

@Test func tlsSNIAndALPNCanSupportHighOnlyWithVerifiedClocks() throws {
    let phoneURL = try #require(Bundle.module.url(forResource: "iphone-tls", withExtension: "pcap", subdirectory: "Fixtures"))
    let macURL = try #require(Bundle.module.url(forResource: "mac-tls-pktap", withExtension: "pcap", subdirectory: "Fixtures"))
    let phone = try importCapture(phoneURL, source: .iphone, offsetMicroseconds: 0)
    let mac = try importCapture(macURL, source: .mac, offsetMicroseconds: 0)
    #expect(phone.observations[0].sni == ["example.apple.com"])
    #expect(phone.observations[0].first("tls.handshake.extensions_alpn_str") == "h2")
    #expect(phone.observations[0].first("tls.handshake.extensions.supported_version") == "0x0304")
    let result = try correlate([phone, mac], settings: CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 10, clocksVerified: true, alignmentMethod: "Measured against shared UTC reference"), isDemonstration: true)
    #expect(result.correlations.count == 1)
    #expect(result.correlations[0].confidence == .high)
    #expect(result.correlations[0].reasons.contains { $0.title == "Direct TLS SNI match" })
}

@Test func importsAppleUnifiedLogTimestamp() throws {
    let path = FileManager.default.temporaryDirectory.appendingPathComponent("correlator-log-\(UUID().uuidString).ndjson")
    defer { try? FileManager.default.removeItem(at: path) }
    let line = "{\"timestamp\":\"2026-09-27 09:13:03.414421+0000\",\"eventMessage\":\"test endpoint 203.0.113.5\",\"processImagePath\":\"/usr/libexec/apsd\",\"processID\":423,\"subsystem\":\"test\",\"category\":\"Network\"}\n"
    try line.write(to: path, atomically: true, encoding: .utf8)
    let evidence = try importUnifiedLog(path, offsetMicroseconds: 0)
    #expect(evidence.observations.count == 1)
    #expect(evidence.observations[0].process == "apsd")
    #expect(evidence.observations[0].pid == "423")
    #expect(evidence.observations[0].originalMicroseconds == 1_790_500_383_414_421)
}

@Test func dnsResponseRetainsAnswerAndAlias() throws {
    let url = try #require(Bundle.module.url(forResource: "iphone-dns-response", withExtension: "pcap", subdirectory: "Fixtures"))
    let evidence = try importCapture(url, source: .iphone, offsetMicroseconds: 0)
    #expect(evidence.observations.count == 3)
    let response = evidence.observations[1]
    #expect(response.kind == "DNS response")
    #expect(response.values("dns.cname") == ["edge.example.net"])
    #expect(response.values("dns.a") == ["17.0.0.1"])
    #expect(response.summary.contains("17.0.0.1"))
}

@Test func verifiedClockNeedsRecordedMethod() throws {
    #expect(throws: AnalysisError.self) {
        try CorrelationSettings(windowMilliseconds: 100, uncertaintyMilliseconds: 10, clocksVerified: true, alignmentMethod: " ").validate()
    }
}

@Test func liveSnapshotKeepsStableFrameIdentityAndExplicitCoverage() throws {
    let phoneURL = try #require(Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Fixtures"))
    let macURL = try #require(Bundle.module.url(forResource: "mac-pktap", withExtension: "pcap", subdirectory: "Fixtures"))
    let phone = try importLiveCapture(phoneURL, source: .iphone, sessionID: "session-test", afterRecord: 0)
    let mac = try importLiveCapture(macURL, source: .mac, sessionID: "session-test", afterRecord: 0)
    #expect(phone.observations.first?.id == "session-test-iPhone RVI:1")
    #expect(mac.observations.first?.process == "apsd")
    #expect(phone.artifact.sha256 == "IN PROGRESS")
    let multiPacketURL = try #require(Bundle.module.url(forResource: "iphone-dns-response", withExtension: "pcap", subdirectory: "Fixtures"))
    let tail = try importLiveCapture(multiPacketURL, source: .iphone, sessionID: "session-test", afterRecord: 1)
    #expect(tail.observations.map(\.record) == [2, 3])
    let next = try importLiveCapture(phoneURL, source: .iphone, sessionID: "session-test", afterRecord: phone.observations.last?.record ?? 0)
    #expect(next.observations.isEmpty)
    let final = try finalizeLiveCapture(phoneURL, source: .iphone, sessionID: "session-test", existing: phone.observations)
    #expect(final.observations.count == phone.observations.count)
    #expect(final.artifact.sha256.count == 64)
    #expect(iphoneInterfaceCoverage(phone.observations).contains { $0.id == "Loopback" && $0.status.lowercased().contains("unverified") })
}

@Test func normalizesRealUnifiedLogLinesByObservedProcessAndEndpoint() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("correlator-live-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let raw = directory.appendingPathComponent("raw.ndjson")
    let normalized = directory.appendingPathComponent("matched.ndjson")
    let header = "Filtering the log data using a network predicate\n"
    let matching = "{\"timestamp\":\"2026-09-27 09:13:03.414421+0000\",\"eventMessage\":\"connection to 203.0.113.5\",\"processImagePath\":\"/usr/libexec/apsd\",\"processID\":423}\n"
    let other = "{\"timestamp\":\"2026-09-27 09:13:03.414422+0000\",\"eventMessage\":\"connection to 203.0.113.5\",\"processImagePath\":\"/usr/libexec/other\",\"processID\":99}\n"
    try (header + matching + other + "{\"count\":2,\"finished\":1}\n").write(to: raw, atomically: true, encoding: .utf8)
    try normalizeLiveLog(raw, destination: normalized, processIDs: [423], tokens: ["203.0.113.5"])
    let evidence = try importUnifiedLog(normalized, offsetMicroseconds: 0)
    #expect(evidence.observations.count == 1)
    #expect(evidence.observations[0].pid == "423")
}

@Test func importsApplePCAPNGProcessOptions() throws {
    let url = try #require(Bundle.module.url(forResource: "mac-apple", withExtension: "pcapng", subdirectory: "Fixtures"))
    let imported = try importCapture(url, source: .mac, offsetMicroseconds: 0)
    let packet = try #require(imported.observations.first)
    #expect(packet.process == "apsd")
    #expect(packet.pid == "123")
    #expect(packet.interface == "en0")
    #expect(packet.direction == .outbound)
    #expect(packet.first("pktap.ifname") == nil)
    let live = try importLiveCapture(url, source: .mac, sessionID: "apple-options", afterRecord: 0)
    #expect(live.observations.first?.process == "apsd")
}

@Test func parsesAppleLiveAndFinalCounters() {
    let live = parseTcpdumpCounters("tcpdump: 1180 packets captured, 1193 packets received by filter, 4 packets dropped by kernel\n")
    #expect(live == CaptureCounters(captured: 1180, dropped: 4))
    let final = parseTcpdumpCounters("tcpdump: 1180 packets captured, 1193 packets received by filter, 4 packets dropped by kernel\n1200 packets captured\n1213 packets received by filter\n5 packets dropped by kernel\n")
    #expect(final == CaptureCounters(captured: 1200, dropped: 5))
}
