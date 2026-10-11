import AppKit
import CorrelatorCore
import SwiftUI

extension ContentView {
    func clearSessionSelection() {
        selectedSessionID = nil
        focusedSessionID = nil
        rawPacketID = nil
        rawPacket = nil
        rawPacketError = nil
        selectedByteRangeID = nil
    }

    var sessionsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            notice
            card {
                VStack(alignment: .leading, spacing: 9) {
                    sectionTitle("Packet sessions", detail: "A session groups a direction-independent TCP or UDP five-tuple only within one capture artifact, interface, process label, and TShark stream. Packets without enough fields remain on the timeline.")
                    Text("Links to the other device and to logs are separate inferred evidence. Shared endpoints, names, and timing never merge captures or establish causation.")
                        .font(.caption).foregroundStyle(.secondary)
                    TextField("Filter by endpoint, process, hostname, or source", text: $sessionSearch)
                        .textFieldStyle(.roundedBorder).accessibilityIdentifier("session.search")
                }
            }
            if let investigation {
                let matched = investigation.sessions.filter { session in
                    sessionSearch.isEmpty ||
                    "\(session.firstEndpoint.address):\(session.firstEndpoint.port) \(session.secondEndpoint.address):\(session.secondEndpoint.port)".localizedCaseInsensitiveContains(sessionSearch) ||
                    session.source.rawValue.localizedCaseInsensitiveContains(sessionSearch) ||
                    session.processLabels.contains { $0.localizedCaseInsensitiveContains(sessionSearch) } ||
                    session.hostnameEvidence.contains { $0.name.localizedCaseInsensitiveContains(sessionSearch) }
                }
                Text("\(matched.count) sessions · packets without a complete five-tuple or transport stream remain on the timeline")
                    .font(.caption).foregroundStyle(.secondary)
                if matched.isEmpty { card { emptyMessage("No packet sessions match this filter. Try the full timeline for packets without a transport stream or five-tuple.") } }
                LazyVStack(spacing: 8) {
                    ForEach(matched) { session in
                        Button {
                            selectedSessionID = session.id
                            selectedObservationID = nil
                            selectedCorrelationID = nil
                        } label: {
                            HStack(alignment: .top, spacing: 12) {
                                Circle().fill(color(session.source)).frame(width: 9, height: 9).padding(.top, 5)
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("\(session.firstEndpoint.address):\(String(session.firstEndpoint.port)) ↔ \(session.secondEndpoint.address):\(String(session.secondEndpoint.port))")
                                        .font(.subheadline.weight(.semibold)).monospaced().lineLimit(2)
                                    Text("\(session.source.rawValue) · \(session.transport) stream \(session.stream) · \(session.interface ?? "interface unknown") · \(session.packetIDs.count) \(session.packetIDs.count == 1 ? "packet" : "packets")")
                                        .font(.caption).foregroundStyle(.secondary)
                                    if !session.hostnameEvidence.isEmpty {
                                        Text(Array(Set(session.hostnameEvidence.map(\.name))).sorted().prefix(3).joined(separator: ", "))
                                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                    }
                                }
                                Spacer()
                                Text(timeLabel(session.firstMicroseconds)).font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                            }
                            .foregroundStyle(ink).padding(14)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(selectedSessionID == session.id ? Color.blue.opacity(0.12) : .white, in: RoundedRectangle(cornerRadius: 12))
                        }.buttonStyle(.plain).accessibilityIdentifier("session.row.\(session.id)")
                    }
                }
            } else { card { emptyMessage("Import iPhone and Mac captures, or open a saved session, to explore packet sessions.") } }
        }
    }

    func sessionDetail(_ session: PacketSession) -> some View {
        VStack(alignment: .leading, spacing: 13) {
            Text("\(session.transport) stream \(session.stream)").font(.title3.bold())
            Text("Observed packet group · \(session.source.rawValue)").font(.caption.weight(.medium)).foregroundStyle(color(session.source))
            Text("\(session.firstEndpoint.address):\(String(session.firstEndpoint.port)) ↔ \(session.secondEndpoint.address):\(String(session.secondEndpoint.port))")
                .font(.caption.monospaced()).textSelection(.enabled)
            detailLine("First observed", timeLabel(session.firstMicroseconds))
            detailLine("Last observed", timeLabel(session.lastMicroseconds))
            detailLine("Interface", session.interface ?? "unknown")
            detailLine("Packets", "\(session.packetIDs.count)")
            if let artifact = investigation?.artifacts.first(where: { $0.id == session.artifactID }) {
                detailLine("Original capture", artifact.path)
                detailLine("SHA-256", artifact.sha256)
                Button("Reveal original capture") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: artifact.path)]) }
                    .accessibilityIdentifier("session.revealArtifact")
            }
            if !session.processLabels.isEmpty {
                Divider()
                Text("OBSERVED MAC LABELS").font(.caption.bold()).tracking(1.3)
                ForEach(session.processLabels, id: \.self) { Text($0).font(.caption) }
                Text("These labels describe Mac packets only. PID reuse and incomplete process lifetimes remain possible.").font(.caption).foregroundStyle(.secondary)
            }
            if !session.hostnameEvidence.isEmpty {
                Divider()
                Text("HOSTNAME PROVENANCE").font(.caption.bold()).tracking(1.3)
                ForEach(session.hostnameEvidence, id: \.self) { evidence in
                    explanation("\(evidence.name) · \(evidence.origin.rawValue)\(evidence.inferred ? " · inferred" : " · observed")", evidence.detail)
                }
            }
            Divider()
            Button("View session and linked records on timeline") {
                focusedPeerID = nil; focusedCorrelationID = nil; focusedSessionID = session.id
                selectedObservationID = nil; selectedTab = .timeline
            }.buttonStyle(.borderedProminent).accessibilityIdentifier("session.viewEvidence")
            Text("LINKED INVESTIGATIVE LEADS").font(.caption.bold()).tracking(1.3)
            Text("\(session.correlationIDs.count) shared-service candidates · \(session.peerFlowIDs.count) direct-peer partitions · \(session.logIDs.count) linked logs. These links are inferred, and zero is a valid result.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(session.correlationIDs.prefix(8), id: \.self) { id in
                Button("Review shared-service candidate") {
                    selectedSessionID = nil; selectedCorrelationID = id; selectedTab = .correlations
                }.buttonStyle(.link).accessibilityIdentifier("session.correlation.\(id)")
            }
            ForEach(session.peerFlowIDs.prefix(8), id: \.self) { id in
                Button("Review direct-peer partition") {
                    selectedSessionID = nil; peerReturnID = id; selectedTab = .correlations
                }.buttonStyle(.link).accessibilityIdentifier("session.peer.\(id)")
            }
            if !session.logIDs.isEmpty {
                Text("LINKED LOG RECORDS").font(.caption.bold()).tracking(1.3)
                ForEach(session.logIDs.prefix(8), id: \.self) { id in sessionRecordButton(id, sessionID: session.id) }
            }
            Divider()
            Text("OBSERVED PACKETS").font(.caption.bold()).tracking(1.3)
            ForEach(session.packetIDs.prefix(12), id: \.self) { id in sessionRecordButton(id, sessionID: session.id) }
            if session.packetIDs.count > 12 { Text("First 12 shown here; open the focused timeline for all packets.").font(.caption).foregroundStyle(.secondary) }
        }
    }

    func sessionRecordButton(_ id: String, sessionID: String) -> some View {
        Button {
            focusedSessionID = sessionID; focusedPeerID = nil; focusedCorrelationID = nil
            selectedObservationID = id; selectedTab = .timeline
        } label: {
            if let record = observation(id) {
                Text("\(record.source.rawValue) #\(record.record) · \(record.kind)").font(.caption.monospaced()).lineLimit(2)
            } else { Text(id).font(.caption.monospaced()) }
        }.buttonStyle(.link).accessibilityIdentifier("session.record.\(id)")
    }
}
