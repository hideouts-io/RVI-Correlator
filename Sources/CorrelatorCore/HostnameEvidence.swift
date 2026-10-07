import Foundation

public enum HostnameOrigin: String, Codable, Sendable {
    case tls = "TLS SNI", quic = "QUIC ClientHello", http = "HTTP Host", dns = "Captured DNS answer", query = "Captured DNS question"
}

public struct HostnameEvidence: Codable, Hashable, Sendable {
    public let name: String
    public let origin: HostnameOrigin
    public let observationIDs: [String]
    public let inferred: Bool
    public let detail: String
}

private struct DNSBinding {
    let name: String
    let ip: String
    let start: Int64
    let end: Int64
    let scope: String
    let observationIDs: [String]
    let addressType: Int
    let chain: [String]
    let records: [TimedDNSRecord]
}

private func dnsScope(_ packet: Observation, client: String) -> String {
    [packet.artifactID, packet.source.rawValue, client].joined(separator: "|")
}

private struct TimedDNSRecord {
    let record: DNSResourceRecord
    let start: Int64
    let end: Int64
    let scope: String
    let observationIDs: [String]
}

private func bindings(_ observations: [Observation], byRecord: [String: Observation]) throws -> [DNSBinding] {
    var records: [TimedDNSRecord] = []
    for response in observations where response.flag("dns.flags.response") && !response.flag("dns.flags.truncated") && response.first("dns.flags.rcode") == "0" {
        guard let client = response.destinationIP else { continue }
        let query = response.first("dns.response_to").flatMap { byRecord["\(response.artifactID):\($0)"] }
        let queryID = query.flatMap { query in
            query.sourceIP == client && query.destinationIP == response.sourceIP && query.first("dns.id") == response.first("dns.id") && query.dnsNames == response.dnsNames && query.timeMicroseconds <= response.timeMicroseconds ? query.id : nil
        }
        for record in response.dnsRecords where record.ttlSeconds > 0 {
            let (end, overflow) = response.timeMicroseconds.addingReportingOverflow(Int64(record.ttlSeconds) * 1_000_000)
            guard !overflow else { throw AnalysisError.invalidInput("DNS TTL overflows timestamp in \(response.id).") }
            records.append(TimedDNSRecord(record: record, start: response.timeMicroseconds, end: end, scope: dnsScope(response, client: client), observationIDs: [queryID, response.id].compactMap { $0 }))
        }
    }
    let aliases = Dictionary(grouping: records.filter { $0.record.type == 5 }, by: { "\($0.scope)|\($0.record.value)" })
    var result: [DNSBinding] = []
    for address in records where address.record.type == 1 || address.record.type == 28 {
        var queue = [DNSBinding(name: address.record.owner, ip: address.record.value, start: address.start, end: address.end,
            scope: address.scope, observationIDs: address.observationIDs, addressType: address.record.type, chain: [address.record.owner], records: [address])]
        var index = 0
        while index < queue.count {
            let binding = queue[index]; index += 1; result.append(binding)
            guard result.count <= 100_000 else { throw AnalysisError.resourceLimit("More than 100,000 DNS associations. Narrow this capture before resolving hostname chains.") }
            for alias in aliases["\(binding.scope)|\(binding.name)"] ?? [] {
                guard !binding.chain.contains(alias.record.owner) else { continue }
                let start = max(binding.start, alias.start), end = min(binding.end, alias.end)
                guard start < end else { continue }
                queue.append(DNSBinding(name: alias.record.owner, ip: binding.ip, start: start, end: end, scope: binding.scope,
                    observationIDs: Array(Set(binding.observationIDs + alias.observationIDs)).sorted(), addressType: binding.addressType, chain: [alias.record.owner] + binding.chain, records: binding.records + [alias]))
            }
        }
    }
    return result
}

/// Passive associations are scoped to the source artifact and client IP. No network lookup occurs.
public func resolveHostnames(_ observations: [Observation]) throws -> [String: [HostnameEvidence]] {
    let byRecord = Dictionary(uniqueKeysWithValues: observations.map { ("\($0.artifactID):\($0.record)", $0) })
    let dns = Dictionary(grouping: try bindings(observations, byRecord: byRecord), by: { "\($0.scope)|\($0.ip)" })
    var responsesByName: [String: [Observation]] = [:]
    for response in observations where response.flag("dns.flags.response") {
        guard let client = response.destinationIP else { continue }
        for name in Set(response.dnsNames + response.dnsRecords.map(\.owner)) {
            responsesByName["\(dnsScope(response, client: client))|\(name)", default: []].append(response)
        }
    }
    let handshakes = Dictionary(grouping: observations.filter { !$0.sni.isEmpty || !$0.values("http.host").isEmpty }, by: \.streamIdentity)
    var result: [String: [HostnameEvidence]] = [:]
    for packet in observations where packet.source == .iphone || packet.source == .mac {
        var evidence = packet.dnsNames.map { name in
            HostnameEvidence(name: name, origin: .query, observationIDs: [packet.id], inferred: false,
                detail: "Observed DNS question name. A question alone does not associate an address with a later connection.")
        }
        for frame in handshakes[packet.streamIdentity] ?? [] {
            // A captured stream can span requests; only inherit earlier observations within five minutes.
            let age = packet.timeMicroseconds - frame.timeMicroseconds
            guard age >= 0, age <= 300_000_000 else { continue }
            let origin: HostnameOrigin = frame.protocols.contains("quic") ? .quic : .tls
            for name in frame.sni {
                evidence.append(HostnameEvidence(name: name, origin: origin, observationIDs: [frame.id], inferred: frame.id != packet.id,
                    detail: frame.id == packet.id ? "Directly observed ClientHello name." : "Earlier name on the same capture, transport stream, interface and process identity; flow association is inferred."))
            }
            for name in frame.values("http.host").map(normalizeHostname) {
                evidence.append(HostnameEvidence(name: name, origin: .http, observationIDs: [frame.id], inferred: frame.id != packet.id,
                    detail: frame.id == packet.id ? "Direct HTTP Host header." : "Earlier HTTP Host on this transport stream; multiplexing or connection reuse can make the association ambiguous."))
            }
        }
        let client = packet.direction == .inbound ? packet.destinationIP : packet.sourceIP
        if let client, let remote = packet.remoteIP {
            let candidates = dns["\(dnsScope(packet, client: client))|\(remote)"] ?? []
            for binding in candidates where packet.timeMicroseconds >= binding.start && packet.timeMicroseconds < binding.end {
                // A later answer for the same name supersedes an older address, even if its TTL is not exhausted.
                let replaced = binding.records.contains { dependency in
                    (responsesByName["\(binding.scope)|\(dependency.record.owner)"] ?? []).contains { response in
                        guard response.timeMicroseconds > dependency.start, response.timeMicroseconds <= packet.timeMicroseconds,
                              !response.flag("dns.flags.truncated") else { return false }
                        if response.first("dns.flags.rcode") == "3" { return true }
                        return response.dnsRecords.contains { $0.owner == dependency.record.owner && $0.type == dependency.record.type }
                    }
                }
                if replaced { continue }
                evidence.append(HostnameEvidence(name: binding.name, origin: .dns,
                    observationIDs: binding.observationIDs, inferred: true,
                    detail: "\(binding.chain.joined(separator: " → ")) → \(remote). Valid until epoch µs \(binding.end), using the intersection of each record’s validity interval. Supporting IDs include linked queries where captured. Address-to-connection association is inferred; shared IPs are ambiguous."))
            }
        }
        if !evidence.isEmpty {
            result[packet.id] = Array(Set(evidence)).sorted { ($0.name, $0.origin.rawValue, $0.observationIDs.joined()) < ($1.name, $1.origin.rawValue, $1.observationIDs.joined()) }
        }
    }
    return result
}
