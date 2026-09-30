import Foundation

/// Matches a whole address/name token, never a substring of a longer hostname or address.
func messageMentions(_ message: String, token: String) -> Bool {
    guard token.count >= 5 else { return false }
    let characters = token.contains(":") ? "A-Za-z0-9_.:\\-" : "A-Za-z0-9_.\\-"
    let pattern = "(?<![\(characters)])" + NSRegularExpression.escapedPattern(for: token) + "(?![\(characters)])"
    return message.range(of: pattern, options: [.regularExpression, .caseInsensitive]) != nil
}

/// Contextual log support stays on the Mac identity and does not score activity identifiers.
func relatedLogEvidence(_ phone: Observation, _ mac: Observation, _ logIndex: [String: [Observation]], _ windowMicroseconds: Int64) -> [Observation] {
    guard let pid = mac.pid, let process = mac.process, !process.isEmpty, let logs = logIndex[pid] else { return [] }
    let tokens = Array(Set([phone.remoteIP, mac.remoteIP].compactMap { $0 } + phone.hostnames + mac.hostnames))
    var lower = 0, upper = logs.count
    while lower < upper {
        let middle = lower + (upper - lower) / 2
        if logs[middle].timeMicroseconds < mac.timeMicroseconds - windowMicroseconds { lower = middle + 1 } else { upper = middle }
    }
    var matches: [Observation] = []
    var index = lower
    while index < logs.count && logs[index].timeMicroseconds <= mac.timeMicroseconds + windowMicroseconds {
        let log = logs[index]
        if log.process == process, let message = log.first("log.message"), tokens.contains(where: { messageMentions(message, token: $0) }) { matches.append(log) }
        index += 1
    }
    return matches
}

/// Same-activity navigation is confined to one artifact, boot and observed process/image label.
/// It is a log-context group, not a verified process lifetime or cross-device operation join.
public func sameLogActivity(_ selected: Observation, observations: [Observation]) -> [Observation] {
    guard selected.source == .log, selected.pid != nil,
          let boot = selected.first("log.bootUUID"), !boot.isEmpty,
          let image = selected.first("log.processImageUUID"), !image.isEmpty,
          let activity = selected.first("log.activityIdentifier"), let value = UInt64(activity), value > 0 else { return [] }
    return observations.filter {
        $0.source == .log && $0.artifactID == selected.artifactID && $0.processIdentity == selected.processIdentity &&
        $0.first("log.bootUUID") == boot && $0.first("log.processImageUUID") == image && $0.first("log.activityIdentifier") == activity
    }.sorted { $0.timeMicroseconds == $1.timeMicroseconds ? $0.id < $1.id : $0.timeMicroseconds < $1.timeMicroseconds }
}

/// Compiles bounded alternatives once per normalization pass, rather than once per
/// token per log record. IPv6 needs a colon boundary; hostname/IPv4 tokens allow :port.
func compileLogTokenPatterns(_ tokens: Set<String>) throws -> [NSRegularExpression] {
    let groups = Dictionary(grouping: tokens.filter { $0.count >= 5 }, by: { $0.contains(":") })
    return try groups.map { ipv6, values in
        let characters = ipv6 ? "A-Za-z0-9_.:\\-" : "A-Za-z0-9_.\\-"
        let alternatives = values.sorted().map(NSRegularExpression.escapedPattern(for:)).joined(separator: "|")
        let pattern = "(?<![\(characters)])(?:\(alternatives))(?![\(characters)])"
        do { return try NSRegularExpression(pattern: pattern, options: .caseInsensitive) }
        catch { throw AnalysisError.invalidInput("Could not compile bounded log token matcher for \(values.count) escaped tokens: \(error)") }
    }
}

func messageMatchesTokens(_ message: String, patterns: [NSRegularExpression]) -> Bool {
    let range = NSRange(message.startIndex..<message.endIndex, in: message)
    return patterns.contains { $0.firstMatch(in: message, range: range) != nil }
}
