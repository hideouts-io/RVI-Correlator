import Foundation

private func lowerBound(_ observations: [Observation], _ timestamp: Int64) -> Int {
    var low = 0
    var high = observations.count
    while low < high {
        let middle = low + (high - low) / 2
        if observations[middle].timeMicroseconds < timestamp { low = middle + 1 } else { high = middle }
    }
    return low
}

private func endpointKey(_ packet: Observation) -> String? {
    guard let ip = packet.remoteIP, let port = packet.remotePort, let transport = packet.transport else { return nil }
    return "\(transport)|\(ip)|\(port)"
}


private func score(_ phone: Observation, _ mac: Observation, _ logs: [Observation], _ hostContext: [String: [HostnameEvidence]], _ settings: CorrelationSettings, _ alternativeProcesses: Int) -> Correlation {
    let delta = Double(abs(phone.timeMicroseconds - mac.timeMicroseconds)) / 1_000
    var reasons: [EvidenceReason] = [
        EvidenceReason(title: "Remote IP match", detail: "Both packet headers identify remote endpoint \(phone.remoteIP ?? ""). Direction determines which endpoint is remote.", points: 25, observationIDs: [phone.id, mac.id]),
        EvidenceReason(title: "Remote port match", detail: "Both packets use remote port \(phone.remotePort ?? "") using \(phone.transport ?? "the same transport").", points: 10, observationIDs: [phone.id, mac.id])
    ]
    let phoneHosts = (hostContext[phone.id] ?? []).filter { $0.origin != .dns && $0.origin != .query }
    let macHosts = (hostContext[mac.id] ?? []).filter { $0.origin != .dns && $0.origin != .query }
    let shared = phoneHosts.first { left in macHosts.contains(where: { $0.name == left.name }) }
    if let shared, let other = macHosts.first(where: { $0.name == shared.name }) {
        let direct = !shared.inferred && !other.inferred && shared.origin == .tls && other.origin == .tls
        reasons.append(EvidenceReason(title: direct ? "Direct TLS SNI match" : "Hostname match within flows",
                                      detail: "\(shared.name) appears as \(shared.origin.rawValue) in iPhone records \(shared.observationIDs.joined(separator: ", ")) and \(other.origin.rawValue) in Mac records \(other.observationIDs.joined(separator: ", ")). \(direct ? "Both names are directly observed in these frames." : "Flow inheritance is an inference.")",
                                      points: direct ? 25 : 17, observationIDs: shared.observationIDs + other.observationIDs))
    }
    if let query = phone.dnsNames.first, mac.dnsNames.contains(query) {
        reasons.append(EvidenceReason(title: "DNS query match", detail: "Both packets query \(query). A shared resolver can carry independent clients' queries.", points: 12, observationIDs: [phone.id, mac.id]))
    }
    let phoneDNS = (hostContext[phone.id] ?? []).filter { $0.origin == .dns }
    let macDNS = (hostContext[mac.id] ?? []).filter { $0.origin == .dns }
    if let left = phoneDNS.first(where: { name in macDNS.contains { $0.name == name.name } }), let right = macDNS.first(where: { $0.name == left.name }) {
        reasons.append(EvidenceReason(title: "DNS answer support", detail: "Separate source-scoped, time-valid DNS chains support \(left.name) at the remote IP. This is inferred hostname context, not process attribution.", points: shared == nil ? 7 : 0, observationIDs: left.observationIDs + right.observationIDs))
    }
    if let phoneVersion = phone.first("quic.version"), let macVersion = mac.first("quic.version"), phoneVersion == macVersion {
        reasons.append(EvidenceReason(title: "QUIC version match", detail: "Both packets advertise QUIC version \(phoneVersion). This version is common across unrelated connections.", points: 3, observationIDs: [phone.id, mac.id]))
    }
    if let phoneALPN = phone.first("tls.handshake.extensions_alpn_str"), mac.values("tls.handshake.extensions_alpn_str").contains(phoneALPN) {
        reasons.append(EvidenceReason(title: "ALPN match", detail: "Both handshakes advertise \(phoneALPN).", points: 3, observationIDs: [phone.id, mac.id]))
    }
    if mac.pid != nil && mac.process != nil {
        reasons.append(EvidenceReason(title: "PKTAP process observed", detail: "The Mac packet carries process \(mac.process ?? "") (PID \(mac.pid ?? "")). This labels Mac traffic only.", points: 8, observationIDs: [mac.id]))
    }
    if mac.interface != nil && mac.direction == .outbound {
        reasons.append(EvidenceReason(title: "Mac interface and direction", detail: "PKTAP reports outbound traffic on \(mac.interface ?? "").", points: 4, observationIDs: [mac.id]))
    }
    let calibrationCoversPhone = settings.calibrations.isEmpty || settings.calibrations.contains {
        $0.source == .iphone && phone.originalMicroseconds >= $0.startMicroseconds && phone.originalMicroseconds <= $0.endMicroseconds &&
        phone.timeMicroseconds - phone.originalMicroseconds == $0.offsetMicroseconds
    }
    let aligned = settings.clocksVerified && calibrationCoversPhone && settings.uncertaintyMilliseconds <= settings.windowMilliseconds
    let timePoints = aligned ? (delta <= 50 ? 15 : delta <= 250 ? 10 : delta <= 1_000 ? 5 : 2) : 0
    reasons.append(EvidenceReason(title: "Time proximity", detail: "Capture timestamps differ by \(String(format: "%.1f", delta)) ms. \(aligned ? "Clock alignment is documented." : "Time adds no points until alignment is documented and uncertainty is within the match window.")", points: timePoints, observationIDs: [phone.id, mac.id]))
    let logAlignmentCovered = settings.calibrations.isEmpty || logs.allSatisfy { log in
        settings.calibrations.contains { $0.source == .log && log.originalMicroseconds >= $0.startMicroseconds && log.originalMicroseconds <= $0.endMicroseconds && log.timeMicroseconds - log.originalMicroseconds == $0.offsetMicroseconds }
    }
    if !logs.isEmpty {
        reasons.append(EvidenceReason(title: "Related Unified Log message", detail: "A nearby log entry shares the Mac PID and process name and explicitly mentions an observed endpoint or hostname. This supports Mac activity, not iPhone causation. It adds points only when clock alignment covers the evidence.", points: aligned && logAlignmentCovered ? 8 : 0, observationIDs: logs.map(\.id)))
    }
    var limitations = [interpretationNotice]
    if !calibrationCoversPhone { limitations.append("This event falls outside the measured clock calibration interval or its applied offset differs. Time adds no points and High is disabled.") }
    if !logs.isEmpty && !logAlignmentCovered { limitations.append("Unified Log alignment is not measured for these events; log support adds no points.") }
    if !settings.clocksVerified { limitations.append("Clock alignment has not been verified. High confidence is disabled.") }
    if settings.uncertaintyMilliseconds > delta { limitations.append("Stated clock uncertainty exceeds this time difference; event ordering is uncertain.") }
    if shared == nil { limitations.append("No matching hostname was observed in both transport flows.") }
    if mac.pid == nil || mac.process == nil { limitations.append("PKTAP has no complete process label for this frame.") }
    if alternativeProcesses > 0 { limitations.append("\(alternativeProcesses) other Mac process(es) also match this iPhone activity within the time window.") }
    if mac.direction == .unknown { limitations.append("PKTAP direction is unknown for this frame.") }
    let phoneNames = Set(phoneHosts.map(\.name)), macNames = Set(macHosts.map(\.name))
    let conflict = !phoneNames.isEmpty && !macNames.isEmpty && phoneNames.isDisjoint(with: macNames)
    let ambiguous = phoneNames.count > 1 || macNames.count > 1
    if conflict { limitations.append("Conflicting observed hostnames: the flows name different hosts. Shared infrastructure is not shared activity.") }
    if ambiguous { limitations.append("Multiple observed hostnames occur in a flow; connection reuse or multiplexing makes this match ambiguous.") }
    if mac.direction == .inbound { limitations.append("Mac evidence is an inbound response. It does not establish that this process initiated a connection; confidence is capped at Low.") }
    if mac.effectivePID != nil || mac.effectiveProcess != nil { limitations.append("Effective Mac identity: \(mac.effectiveProcess ?? "unknown") / PID \(mac.effectivePID ?? "unknown"). It is distinct from the original process label.") }
    limitations.append("PID and process name are packet-time labels, not process lifetime identifiers. PID reuse cannot be ruled out without independent lifecycle evidence; log support also requires the same name.")
    if phoneDNS.count > 1 || macDNS.count > 1 { limitations.append("Several captured DNS names map to this IP. DNS association does not select a unique hostname.") }
    let total = min(100, reasons.reduce(0) { $0 + $1.points })
    let highEligible = aligned && settings.uncertaintyMilliseconds <= 50 && shared != nil && mac.pid != nil && mac.direction == .outbound && alternativeProcesses == 0 && !conflict && !ambiguous && mac.process != nil && total >= 75
    let confidence: Confidence = conflict || mac.direction == .inbound ? .low : highEligible ? .high : total >= 50 && alternativeProcesses <= 2 ? .moderate : .low
    return Correlation(id: "\(phone.id)|\(mac.id)", iphoneID: phone.id, macID: mac.id, logIDs: logs.map(\.id),
                       deltaMilliseconds: delta, score: total, confidence: confidence, reasons: reasons,
                       limitations: limitations, alternativeProcesses: alternativeProcesses)
}

public func correlate(_ imports: [ImportedEvidence], settings: CorrelationSettings, isDemonstration: Bool) throws -> Investigation {
    try settings.validate()
    let sources = Set(imports.map { $0.artifact.source })
    guard sources.contains(.iphone), sources.contains(.mac) else {
        throw AnalysisError.invalidInput("Import both an iPhone RVI capture and a Mac PKTAP capture before correlating.")
    }
    let observations = imports.flatMap(\.observations).sorted { $0.timeMicroseconds < $1.timeMicroseconds }
    let phones = observations.filter { $0.source == .iphone }
    let macs = observations.filter { $0.source == .mac }.sorted { $0.timeMicroseconds < $1.timeMicroseconds }
    let logIndex = Dictionary(grouping: observations.filter { $0.source == .log && $0.pid != nil }, by: { $0.pid ?? "" })
    let macIndex = Dictionary(grouping: macs, by: { endpointKey($0) ?? "unaddressed" })
    let hosts = try resolveHostnames(observations)
    let window = Int64((settings.windowMilliseconds * 1_000).rounded())
    var results: [Correlation] = []
    var rejections: [CandidateRejection] = []
    var noEndpoint = 0, excluded = 0, outside = 0, matched = 0
    let initiations = phones.filter(\.isInitiation)
    for phone in initiations {
        guard let key = endpointKey(phone), let endpointPackets = macIndex[key] else {
            noEndpoint += 1
            rejections.append(CandidateRejection(observationID: phone.id, reason: "No Mac packet shares the observed remote IP, port and transport.", nearestMilliseconds: nil))
            continue
        }
        let eligible = endpointPackets.filter { !(($0.interface ?? "").hasPrefix("rvi")) }
        guard !eligible.isEmpty else {
            excluded += 1
            rejections.append(CandidateRejection(observationID: phone.id, reason: "Only Mac RVI mirror packets share this endpoint; excluded to avoid self-correlation.", nearestMilliseconds: nil))
            continue
        }
        var candidates: [Observation] = []
        var index = lowerBound(eligible, phone.timeMicroseconds - window)
        while index < eligible.count && eligible[index].timeMicroseconds <= phone.timeMicroseconds + window {
            candidates.append(eligible[index]); index += 1
        }
        if candidates.isEmpty {
            outside += 1
            let insertion = lowerBound(eligible, phone.timeMicroseconds)
            let neighbors = [insertion - 1, insertion].filter { eligible.indices.contains($0) }
            let nearest = neighbors.map { Double(abs(eligible[$0].timeMicroseconds - phone.timeMicroseconds)) / 1_000 }.min()
            rejections.append(CandidateRejection(observationID: phone.id, reason: "Matching Mac endpoint exists, but no packet is inside the configured time window. No automatic clock shift was applied.", nearestMilliseconds: nearest))
            continue
        }
        matched += 1
        let processes = Set(candidates.map(\.processIdentity))
        for mac in candidates {
            let alternativeProcesses = max(0, processes.count - 1)
            let relatedLogs = relatedLogEvidence(phone, mac, logIndex, window)
            results.append(score(phone, mac, relatedLogs, hosts, settings, alternativeProcesses))
            if results.count > 20_000 { throw AnalysisError.resourceLimit("More than 20,000 candidate correlations. Narrow the captures or the time window.") }
        }
    }
    let diagnostics = CorrelationDiagnostics(phonePackets: phones.count, inboundInitiationSignatures: phones.filter { $0.hasInitiationSignature && $0.direction == .inbound }.count, initiationPackets: initiations.count,
        noEndpointMatch: noEndpoint, excludedInterfaceOnly: excluded, outsideWindow: outside, matchedInitiations: matched,
        rejections: rejections, notes: [
            "Candidates require an iPhone DNS query, ClientHello, QUIC Initial or SYN without ACK. Midstream data and inbound responses are not treated as iPhone initiation evidence.",
            "Decoding completed for the imported artifacts; zero candidates is distinct from a decode error. Missing traffic or handshake metadata can still limit coverage.",
            settings.clocksVerified ? "The configured clock method is recorded; its evidence must be independently assessed." : "Offsets are investigator-supplied; clock alignment is unverified. Timing adds no confidence points. Uncertainty does not silently expand the matching window.",
            "Encrypted DNS, ECH, TLS encryption and a capture starting after a handshake can hide names. Missing names do not prove that DNS or TLS was absent."
        ])
    let macByID = Dictionary(uniqueKeysWithValues: macs.map { ($0.id, $0) })
    let best = Dictionary(grouping: results, by: { result in
        result.iphoneID + "|" + (macByID[result.macID]?.streamIdentity ?? result.macID)
    }).compactMap { $0.value.max(by: { $0.score < $1.score }) }
    return Investigation(schemaVersion: 3, generatedAt: Date(), isDemonstration: isDemonstration, settings: settings,
                         artifacts: imports.map(\.artifact), observations: observations,
                         correlations: best.sorted {
                             if $0.score != $1.score { return $0.score > $1.score }
                             if $0.deltaMilliseconds != $1.deltaMilliseconds { return $0.deltaMilliseconds < $1.deltaMilliseconds }
                             return $0.id < $1.id
                         },
                         interpretation: interpretationNotice, diagnostics: diagnostics, peerReview: try reviewPeerEvidence(observations, settings: settings), hostnameEvidence: hosts)
}
