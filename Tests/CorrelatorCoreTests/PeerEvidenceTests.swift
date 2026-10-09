import Foundation
import Testing
@testable import CorrelatorCore

private func peerPacket(_ id: String, source: EvidenceSource, time: Int64, sequence: String, direction: String, interface: String) -> Observation {
    Observation(id: id, source: source, artifactID: source.rawValue, record: Int(id.split(separator: ":").last!)!, originalMicroseconds: time, timeMicroseconds: time,
        protocols: ["ip", "tcp"], fields: ["ip.src": ["192.0.2.1"], "ip.dst": ["192.0.2.2"], "tcp.srcport": ["50000"], "tcp.dstport": ["62078"],
            "tcp.seq_raw": [sequence], "tcp.ack_raw": ["99"], "tcp.len": ["20"], "tcp.flags": ["0x0018"], "tcp.stream": ["0"],
            "pktap.flags": [direction], "pktap.ifname": [interface], "pktap.pid": [source == .mac ? "100" : "200"], "pktap.cmdname": [source == .mac ? "mac-process" : "phone-process"]])
}

@Test func peerReviewRequiresDistinctUniqueOppositeDirectionPackets() throws {
    let settings = CorrelationSettings(windowMilliseconds: 250, uncertaintyMilliseconds: 1000, clocksVerified: false, alignmentMethod: "")
    let phone1 = peerPacket("p:1", source: .iphone, time: 1_000_000, sequence: "123", direction: "1", interface: "utun6")
    let phone2 = peerPacket("p:2", source: .iphone, time: 1_100_000, sequence: "143", direction: "1", interface: "utun6")
    let mac1 = peerPacket("m:1", source: .mac, time: 999_000, sequence: "123", direction: "2", interface: "utun4")
    let mac2 = peerPacket("m:2", source: .mac, time: 1_099_000, sequence: "143", direction: "2", interface: "utun4")
    let result = try reviewPeerEvidence([phone1, phone2, mac1, mac2], settings: settings)
    #expect(result.flows.count == 1)
    #expect(result.flows[0].pairs.count == 2)
    #expect(!result.flows[0].bidirectional)
    #expect(result.flows[0].pairs[0].deltaMilliseconds == 1)
    #expect(phone1.originalMicroseconds == phone1.timeMicroseconds)
    let sessions = packetSessions([phone1, phone2, mac1, mac2], hostnameEvidence: [:], correlations: [], peerReview: result)
    #expect(sessions.count == 2)
    #expect(sessions.allSatisfy { $0.peerFlowIDs == [result.flows[0].id] })
    #expect(sessions.allSatisfy { session in
        session.packetIDs.allSatisfy { id in session.source == .iphone ? id.hasPrefix("p:") : id.hasPrefix("m:") }
    })
    let mirror = peerPacket("m:3", source: .mac, time: 999_000, sequence: "123", direction: "2", interface: "rvi0")
    #expect(try reviewPeerEvidence([phone1, phone2, mirror, mac2], settings: settings).flows.isEmpty)
    let duplicate = peerPacket("m:4", source: .mac, time: 999_500, sequence: "123", direction: "2", interface: "utun4")
    let ambiguous = try reviewPeerEvidence([phone1, phone2, mac1, mac2, duplicate], settings: settings)
    #expect(ambiguous.ambiguousPhonePackets == 1 && ambiguous.flows.isEmpty)
    let repeatPhone = peerPacket("p:3", source: .iphone, time: 1_001_000, sequence: "123", direction: "1", interface: "utun6")
    #expect(try reviewPeerEvidence([phone1, repeatPhone, mac1], settings: settings).ambiguousPhonePackets == 2)
    let sameDirection = peerPacket("m:5", source: .mac, time: 999_000, sequence: "123", direction: "1", interface: "utun4")
    #expect(try reviewPeerEvidence([phone1, sameDirection], settings: settings).unmatchedPhonePackets == 1)
    let late = peerPacket("m:6", source: .mac, time: 9_000_000, sequence: "123", direction: "2", interface: "utun4")
    #expect(try reviewPeerEvidence([phone1, late], settings: settings).unmatchedPhonePackets == 1)
    for extraFields in [["ipv6.src": ["2001:db8::1"]], ["tcp.seq_raw": ["123", "456"]]] {
        let layered = Observation(id: phone1.id, source: phone1.source, artifactID: phone1.artifactID,
            record: phone1.record, originalMicroseconds: phone1.originalMicroseconds, timeMicroseconds: phone1.timeMicroseconds,
            protocols: phone1.protocols, fields: phone1.fields.merging(extraFields) { _, replacement in replacement })
        let excluded = try reviewPeerEvidence([layered, phone2, mac1, mac2], settings: settings)
        #expect(excluded.eligiblePhonePackets == 1 && excluded.flows.isEmpty)
    }
}

@Test func logsRequireBoundedTokensAndScopedNonzeroActivity() throws {
    #expect(messageMentions("remote=203.0.113.5:443", token: "203.0.113.5"))
    #expect(!messageMentions("remote=203.0.113.50:443", token: "203.0.113.5"))
    #expect(!messageMentions("https://not-example.apple.com/path", token: "example.apple.com"))
    #expect(messageMentions("https://example.apple.com/path", token: "example.apple.com"))
    #expect(!messageMentions("[2001:db8::12]", token: "2001:db8::1"))
    func log(_ record: Int, pid: String, boot: String, activity: String) -> Observation {
        Observation(id: "l:\(record)", source: .log, artifactID: "logs", record: record, originalMicroseconds: Int64(record), timeMicroseconds: Int64(record), protocols: [],
            fields: ["log.pid": [pid], "log.process": ["example"], "log.bootUUID": [boot], "log.processImageUUID": ["image"], "log.activityIdentifier": [activity]])
    }
    let first = log(1, pid: "12", boot: "boot-A", activity: "55")
    let second = log(2, pid: "12", boot: "boot-A", activity: "55")
    let otherPID = log(3, pid: "13", boot: "boot-A", activity: "55")
    let otherBoot = log(4, pid: "12", boot: "boot-B", activity: "55")
    #expect(sameLogActivity(first, observations: [otherBoot, second, first, otherPID]).map(\.id) == [first.id, second.id])
    let missingBoot = log(6, pid: "12", boot: "", activity: "55")
    #expect(sameLogActivity(missingBoot, observations: [missingBoot]).isEmpty)
    let zero = log(5, pid: "12", boot: "boot-A", activity: "0")
    #expect(sameLogActivity(zero, observations: [zero]).isEmpty)
}
