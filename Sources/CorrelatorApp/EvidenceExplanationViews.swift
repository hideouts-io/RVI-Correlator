import CorrelatorCore
import SwiftUI

extension ContentView {
    func timelineSummary(_ packet: Observation) -> String {
        guard packet.hostnames.isEmpty, let name = investigation?.hostnameEvidence[packet.id]?.first else { return packet.summary }
        return "\(packet.summary) · inferred \(name.name) [\(name.origin.rawValue)]"
    }

    func diagnosticsCard(_ result: Investigation) -> some View {
        card {
            VStack(alignment: .leading, spacing: 10) {
                sectionTitle("Shared-service candidate audit", detail: "Every iPhone initiation packet has an outcome. These counts explain filtering, not network causality.")
                let audit = result.diagnostics
                Text("\(audit.phonePackets) iPhone packets → \(audit.initiationPackets) initiation packets → \(audit.matchedInitiations) with candidate evidence").font(.subheadline.bold())
                Text("\(audit.inboundInitiationSignatures) inbound initiation signatures excluded by the client-initiation policy. Direct-peer TCP evidence is reviewed separately on the Correlations page.").font(.caption).foregroundStyle(.secondary)
                Text("\(audit.noEndpointMatch) without a matching Mac endpoint · \(audit.excludedInterfaceOnly) with only excluded RVI mirrors · \(audit.outsideWindow) outside the time window").font(.caption)
                ForEach(audit.notes, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                DisclosureGroup("Rejected initiation records (first \(min(20, audit.rejections.count)) of \(audit.rejections.count); all included in export)") {
                    ForEach(Array(audit.rejections.prefix(20))) { rejection in
                        Button {
                            selectedObservationID = rejection.observationID; selectedCorrelationID = nil; selectedTab = .timeline
                        } label: {
                            VStack(alignment: .leading) {
                                Text(rejection.observationID).font(.caption.monospaced())
                                Text(rejection.reason).font(.caption)
                                if let distance = rejection.nearestMilliseconds { Text("Nearest endpoint evidence: \(String(format: "%.3f", distance)) ms").font(.caption) }
                            }
                        }.buttonStyle(.plain).accessibilityIdentifier("diagnostics.rejection.\(rejection.id)")
                    }
                }.font(.caption)
            }
        }.accessibilityElement(children: .contain).accessibilityIdentifier("diagnostics.summary")
    }

    func hostnameDetails(_ packet: Observation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("HOSTNAME EVIDENCE").font(.caption.bold())
            let names = investigation?.hostnameEvidence[packet.id] ?? []
            if names.isEmpty {
                explanation("No hostname established", "Encrypted DNS, ECH, encrypted payloads or a capture starting after the handshake can hide names. Absence of a decoded name does not establish which cause applies.")
            }
            ForEach(names, id: \.self) { name in
                explanation("\(name.name) · \(name.origin.rawValue) · \(name.inferred ? "inferred association" : "observed")", name.detail)
                Text(name.observationIDs.joined(separator: " · ")).font(.caption2.monospaced()).textSelection(.enabled)
            }
            if Set(names.map(\.name)).count > 1 {
                Label("Multiple names remain plausible. Shared IPs and reused connections do not identify a unique hostname.", systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            }
            ForEach(packet.dnsRecords, id: \.self) { record in
                detailLine("DNS answer · TTL \(record.ttlSeconds) s", "\(record.owner) → \(record.value) (type \(record.type))")
            }
            DisclosureGroup("Optional current DNS lookup") {
                Text("Sends this query to the Mac's configured DNS resolver now. It cannot establish the hostname used during capture. Results never affect correlation scores.").font(.caption)
                TextField("Hostname or IP", text: $activeDNSQuery).textFieldStyle(.roundedBorder).accessibilityIdentifier("dns.active.query")
                Button("Look up now") { runActiveLookup(packet.id) }.disabled(activeDNSBusy || activeDNSQuery.isEmpty).accessibilityIdentifier("dns.active.run")
                if activeDNSBusy { ProgressView() }
                if let activeDNSError { Text(activeDNSError).font(.caption).foregroundStyle(.red) }
                ForEach(activeDNSResults.filter { $0.observationID == packet.id }) { result in
                    explanation("Current lookup: \(result.query)", "\(result.completedAt.formatted()) · \(result.status). Present-day enrichment only.")
                    ForEach(result.answers, id: \.self) { answer in Text("\(answer.owner) \(answer.type) \(answer.value) · TTL \(answer.ttl) s").font(.caption).textSelection(.enabled) }
                    if result.answers.isEmpty { Text("No answer records returned.").font(.caption) }
                    ForEach(result.warnings, id: \.self) { Text($0).font(.caption).foregroundStyle(.orange) }
                }
            }.font(.caption).accessibilityElement(children: .contain).accessibilityIdentifier("dns.active.disclosure")
        }
    }

    func runActiveLookup(_ observationID: String) {
        let query = activeDNSQuery
        activeDNSBusy = true; activeDNSError = nil
        Task {
            do {
                let result = try await Task.detached { try ActiveDNSLookup.lookup(query, observationID: observationID) }.value
                activeDNSResults.append(result)
            } catch { activeDNSError = error.localizedDescription }
            activeDNSBusy = false
        }
    }
}
