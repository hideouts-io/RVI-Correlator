import CorrelatorCore
import Darwin
import Foundation

struct ActiveDNSAnswer: Codable, Sendable, Hashable {
    let owner: String
    let ttl: Int
    let type: String
    let value: String
}

struct ActiveDNSResult: Codable, Sendable, Identifiable {
    let id: UUID
    let requestedAt: Date
    let completedAt: Date
    let query: String
    let observationID: String
    let answers: [ActiveDNSAnswer]
    let status: String
    let warnings: [String]
}

/// Explicit user action only. Results are separate present-day enrichment and never enter scoring.
enum ActiveDNSLookup {
    static func lookup(_ query: String, observationID: String) throws -> ActiveDNSResult {
        let target = query.trimmingCharacters(in: .whitespacesAndNewlines)
        var ipv4 = in_addr(), ipv6 = in6_addr()
        let isIP = inet_pton(AF_INET, target, &ipv4) == 1 || inet_pton(AF_INET6, target, &ipv6) == 1
        guard isIP || (target.utf8.count <= 253 && !target.isEmpty && target.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 63 && $0.first != "-" && $0.last != "-" && $0.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }) else { throw AnalysisError.invalidInput("Enter a valid IPv4/IPv6 address or ASCII DNS name; Unicode names require their punycode form.") }
        let started = Date()
        var answers: [ActiveDNSAnswer] = [], statuses: [String] = [], warnings: [String] = []
        for type in isIP ? ["PTR"] : ["A", "AAAA"] {
            var completed = false
            for attempt in 1...2 {
                do {
                    let result = try request(target, type: type)
                    answers += result.0; statuses.append("\(type): \(result.1)"); completed = true
                    break
                } catch {
                    if attempt == 2 { throw error }
                    warnings.append("\(type) first attempt failed: \(error.localizedDescription). Retried once.")
                }
            }
            guard completed else { throw AnalysisError.decoderFailed("DNS lookup did not complete for \(target) / \(type).") }
        }
        return ActiveDNSResult(id: UUID(), requestedAt: started, completedAt: Date(), query: target,
            observationID: observationID, answers: answers, status: statuses.joined(separator: "; "), warnings: warnings)
    }

    private static func request(_ target: String, type: String) throws -> ([ActiveDNSAnswer], String) {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/dig")
        process.arguments = ["+time=2", "+tries=1", "+noall", "+answer", "+comments"] + (type == "PTR" ? ["-x", target] : [target, type])
        process.standardOutput = pipe; process.standardError = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard let text = String(data: data, encoding: .utf8) else { throw AnalysisError.decoderFailed("DNS lookup response was not UTF-8 for \(target) / \(type).") }
        guard process.terminationStatus == 0, let header = text.split(separator: "\n").first(where: { $0.contains("status:") }),
              let status = header.components(separatedBy: "status: ").last?.components(separatedBy: ",").first,
              ["NOERROR", "NXDOMAIN"].contains(status) else {
            throw AnalysisError.decoderFailed("DNS lookup failed for \(target) / \(type), exit \(process.terminationStatus): \(text.prefix(2000))")
        }
        let answers = try text.split(separator: "\n").filter { !$0.hasPrefix(";") }.map { line -> ActiveDNSAnswer in
            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard fields.count >= 5, let ttl = Int(fields[1]), ttl >= 0, fields[2] == "IN" else { throw AnalysisError.decoderFailed("Unexpected DNS answer for \(target) / \(type): \(line)") }
            return ActiveDNSAnswer(owner: fields[0], ttl: ttl, type: fields[3], value: fields[4...].joined(separator: " "))
        }
        return (answers, status)
    }
}
