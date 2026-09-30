import CorrelatorCore
import SwiftUI

extension ContentView {
    func peerEvidenceCard(_ result: Investigation) -> some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("Possible direct-peer traffic", detail: "A separate review of matching TCP packets seen from opposite capture directions. These are inferred relationships, not shared-service scores.")
                let review = result.peerReview
                Text("\(review.flows.count) flow partitions · \(review.flows.reduce(0) { $0 + $1.pairs.count }) paired observations").font(.headline)
                Text("\(review.eligiblePhonePackets) eligible TCP packets · \(review.unmatchedPhonePackets) unmatched · \(review.ambiguousPhonePackets) ambiguous · \(review.insufficientFlowPackets) without sufficient distinct flow evidence").font(.caption).foregroundStyle(.secondary)
                Text(result.settings.clocksVerified ? "Clock method is recorded; assess its evidence and uncertainty separately. Peer relationships remain unscored." : "Clock alignment is unverified. Timing is only a search constraint; peer relationships remain unscored.").font(.caption).foregroundStyle(.orange)
                Text("Requires both wire endpoints, raw TCP sequence/acknowledgment numbers, length and flags to match; known opposite directions; a non-RVI Mac interface; unique pairing in the existing time window; and multiple distinct fingerprints per flow. UDP/QUIC peer matching and address translation are not evaluated.").font(.caption).foregroundStyle(.secondary)
                if review.flows.isEmpty { Text("No direct-peer flow met these criteria. Missing direction, stream or TCP fields can prevent review.").font(.caption) }
                ForEach(review.flows) { flow in
                    Button {
                        if expandedPeerFlowIDs.contains(flow.id) { expandedPeerFlowIDs.remove(flow.id) }
                        else { expandedPeerFlowIDs.insert(flow.id) }
                    } label: {
                        VStack(alignment: .leading, spacing: 3) {
                            Label(peerFlowTitle(flow), systemImage: expandedPeerFlowIDs.contains(flow.id) ? "chevron.down" : "chevron.right").font(.subheadline.bold())
                            Text("\(flow.pairs.count) packet pairs · \(flow.bidirectional ? "both directions" : "one direction") · inferred / unscored").font(.caption).foregroundStyle(.secondary)
                        }
                    }.buttonStyle(.plain).id(flow.id).accessibilityIdentifier("peer.flow.\(flow.id)")
                    if expandedPeerFlowIDs.contains(flow.id) { peerFlowDetails(flow) }
                }
            }
        }.accessibilityElement(children: .contain).accessibilityIdentifier("peer.review")
    }

    func peerFlowTitle(_ flow: PeerFlow) -> String {
        guard let pair = flow.pairs.first, let phone = observation(pair.iphoneID), let mac = observation(pair.macID) else { return flow.id }
        return "iPhone: \(phone.process ?? "unknown") · \(phone.interface ?? "?") ↔ Mac: \(mac.process ?? "unknown") · \(mac.interface ?? "?")"
    }

    func peerFlowDetails(_ flow: PeerFlow) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(flow.limitations, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
            Text("First \(min(8, flow.pairs.count)) packet pairs; all pairs are included in the investigation export. Each link opens the original record.").font(.caption)
            ForEach(Array(flow.pairs.prefix(8)), id: \.iphoneID) { pair in
                HStack(alignment: .top, spacing: 16) {
                    evidenceRecordButton(pair.iphoneID, peerID: flow.id)
                    Text("↔ \(String(format: "%.3f", pair.deltaMilliseconds)) ms").font(.caption.monospacedDigit())
                    evidenceRecordButton(pair.macID, peerID: flow.id)
                }
            }
            Text("\(flow.logIDs.count) contextual Mac log records; first \(min(8, flow.logIDs.count)) shown. Log context is not independent confirmation of packet identity.").font(.caption)
            ForEach(Array(flow.logIDs.prefix(8)), id: \.self) { evidenceRecordButton($0, peerID: flow.id) }
        }.padding(.vertical, 8)
    }

    func evidenceRecordButton(_ id: String) -> some View { evidenceRecordButton(id, peerID: nil) }

    func evidenceRecordButton(_ id: String, peerID: String?) -> some View {
        Button {
            if let peerID { focusedPeerID = peerID; peerReturnID = peerID }
            focusedCorrelationID = nil; selectedCorrelationID = nil; selectedObservationID = id; selectedTab = .timeline
        } label: {
            if let record = observation(id) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(record.source.rawValue) #\(record.record) · \(timeLabel(record.timeMicroseconds))").font(.caption.monospaced())
                    Text("\(record.process ?? "unknown process") · \(record.kind)").font(.caption)
                }
            } else { Text(id).font(.caption) }
        }.buttonStyle(.link).accessibilityIdentifier("evidence.record.\(id)")
    }

    func logActivityDetails(_ packet: Observation) -> some View {
        let records = sameLogActivity(packet, observations: displayedObservations)
        return VStack(alignment: .leading, spacing: 8) {
            Text("SAME-PROCESS LOG ACTIVITY").font(.caption.bold())
            if packet.first("log.bootUUID")?.isEmpty != false {
                Text("Activity grouping unavailable: this log record has no boot UUID. An activity ID alone cannot establish the required identity scope.").font(.caption).foregroundStyle(.orange)
            }
            Text("\(records.count) loaded records share artifact, boot UUID, process/image labels and a nonzero activity ID. This navigation context does not establish a cross-device operation or eliminate PID reuse. Missing or zero activity IDs are not grouped.").font(.caption).foregroundStyle(.secondary)
            ForEach(Array(records.prefix(12)), id: \.id) { evidenceRecordButton($0.id) }
            if records.count > 12 { Text("First 12 shown; all original records and activity fields remain in the timeline/export.").font(.caption) }
        }
    }
}
