import AppKit
import CorrelatorCore
import SwiftUI
import UniformTypeIdentifiers

extension ContentView {
    var overview: some View {
        VStack(alignment: .leading, spacing: 22) {
            notice
            liveCaptureCard
            HStack(spacing: 12) {
                metric("OBSERVATIONS", displayedObservations.count, "Captured frames and log entries", "waveform.path")
                metric("SHARED-SERVICE CANDIDATES", investigation?.correlations.count ?? 0, "Potential related activity", "link")
                metric("ARTIFACTS", imports.count, liveStatus?.phase == "running" ? "Saved streams; hashes after Stop" : "Hashed local evidence files", "externaldrive")
            }
            card {
                VStack(alignment: .leading, spacing: 17) {
                    sectionTitle("Start an investigation", detail: "Import an existing RVI-Sentinel PCAP or PCAPNG, a Mac PKTAP trace, and optionally a Unified Log JSON export.")
                    HStack(spacing: 10) {
                        importButton(.iphone, "Import iPhone RVI", "iphone.gen3")
                        importButton(.mac, "Import Mac PKTAP", "desktopcomputer")
                        importButton(.log, "Add Unified Log", "list.bullet.rectangle")
                    }
                    Button("Open saved session…") { openSavedSession() }
                        .buttonStyle(.bordered)
                        .disabled(busy || liveStarting || liveStatus?.phase == "running")
                        .accessibilityIdentifier("evidence.openSession")
                    if let savedSessionDirectory {
                        HStack(spacing: 10) {
                            Text("Manifest hashes matched: \(savedSessionDirectory.lastPathComponent)")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Reveal in Finder") {
                                if !NSWorkspace.shared.open(savedSessionDirectory) {
                                    error = "Finder could not open \(savedSessionDirectory.path)."
                                }
                            }.buttonStyle(.link)
                        }
                    }
                    Divider()
                    Button("Explore a synthetic example") { loadDemo() }
                        .accessibilityIdentifier("evidence.loadDemo")
                        .buttonStyle(.link).disabled(busy)
                }
            }
            card {
                VStack(alignment: .leading, spacing: 17) {
                    sectionTitle("Time alignment", detail: "Start with 0 ms offsets and unverified clocks. Offset = reference time − source time. A positive value moves the source later. A matching window is a search tolerance, not clock accuracy.")
                    HStack(spacing: 14) {
                        offsetField("iPhone offset, ms", text: $phoneOffsetText)
                        offsetField("Mac offset, ms", text: $macOffsetText)
                        offsetField("Log offset, ms", text: $logOffsetText)
                    }.disabled(liveStatus?.phase == "running")
                    HStack(spacing: 14) {
                        offsetField("Match window, ms", text: $windowText)
                        offsetField("Clock uncertainty, ms", text: $uncertaintyText)
                        Toggle("Clock alignment verified", isOn: $clocksVerified).toggleStyle(.checkbox)
                    }
                    Text("The initial 1,000 ms uncertainty is a placeholder, not a measurement. Keep alignment unverified until calibrated. Never tune offsets just to obtain matches.").font(.caption).foregroundStyle(.secondary)
                    TextField("How was clock alignment verified?", text: $alignmentMethod)
                        .textFieldStyle(.roundedBorder)
                    HStack {
                        Button("Apply and recalculate") { rebuild() }.disabled(busy || liveStatus?.phase == "running" || imports[.iphone] == nil || imports[.mac] == nil)
                            .buttonStyle(.borderedProminent)
                        Text("High requires verified clocks with ≤50 ms uncertainty, matching host evidence, an outbound PKTAP process, and no competing process.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            calibrationCard
            if let investigation {
                diagnosticsCard(investigation)
                Button("Review collection and host provenance") { selectedTab = .sources }
                    .accessibilityIdentifier("context.review")
                Button("Review \(investigation.peerReview.flows.count) possible direct-peer flow partitions") {
                    selectedCorrelationID = nil; selectedObservationID = nil; selectedTab = .correlations
                }.accessibilityIdentifier("peer.openReview")
                card {
                    VStack(alignment: .leading, spacing: 13) {
                        sectionTitle("Strongest shared-service candidates", detail: "Select a relationship to inspect its observed evidence and score.")
                        ForEach(investigation.correlations.prefix(5)) { correlation in
                            Button { focusedPeerID = nil; selectedCorrelationID = correlation.id; selectedObservationID = nil; selectedTab = .correlations } label: {
                                correlationRow(correlation)
                            }.buttonStyle(.plain)
                        }
                        if investigation.correlations.isEmpty { emptyMessage("No candidate matched an observed destination IP, port, and time window.") }
                    }
                }
            }
        }
    }

    var notice: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "info.circle.fill").foregroundStyle(accent).font(.title3)
            VStack(alignment: .leading, spacing: 5) {
                Text("Correlation is an investigative lead").font(.headline).foregroundStyle(ink)
                Text(interpretationNotice).font(.subheadline).foregroundStyle(ink.opacity(0.78)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(17)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(red: 0.88, green: 0.94, blue: 0.99), in: RoundedRectangle(cornerRadius: 16))
    }

    var correlationsView: some View {
        VStack(alignment: .leading, spacing: 14) {
            notice
            if let investigation {
                peerEvidenceCard(investigation)
                diagnosticsCard(investigation)
                if investigation.correlations.isEmpty { card { emptyMessage("No shared-service candidates meet the destination, transport, and time requirements. Review coverage and clock alignment.") } }
                ForEach(investigation.correlations) { correlation in
                    Button { focusedPeerID = nil; selectedCorrelationID = correlation.id; selectedObservationID = nil } label: { correlationRow(correlation) }
                        .buttonStyle(.plain).accessibilityIdentifier("correlation.row.\(correlation.id)")
                }
            } else { card { emptyMessage("Import iPhone and Mac captures to calculate candidate relationships.") } }
        }
    }

    var timelineView: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let focusedSession {
                HStack {
                    Text("Session evidence: \(focusedSession.packetIDs.count) observed packets; linked candidates and their logs are inferred context. Other filters are suspended.").font(.caption)
                    Button("Return to session") { focusedSessionID = nil; selectedObservationID = nil; selectedTab = .sessions }
                        .accessibilityIdentifier("session.return")
                    Button("Show all events") { focusedSessionID = nil }.accessibilityIdentifier("session.clearFocus")
                }
            }
            if focusedPeerID != nil && focusedPeer == nil {
                Text("The focused peer relationship is no longer present in this investigation.").font(.caption).foregroundStyle(.orange)
                Button("Clear unavailable peer focus") { focusedPeerID = nil }.accessibilityIdentifier("peer.clearUnavailable")
            }
            if let focusedPeer {
                HStack {
                    Text("Peer evidence: \(focusedPeer.pairs.count) packet pairs and \(focusedPeer.logIDs.count) contextual logs. Other filters are suspended.").font(.caption)
                    Button("Return to relationship") {
                        peerReturnID = focusedPeer.id; focusedPeerID = nil
                        selectedObservationID = nil; selectedCorrelationID = nil; selectedTab = .correlations
                    }.accessibilityIdentifier("peer.return")
                    Button("Show all events") { focusedPeerID = nil }.accessibilityIdentifier("peer.clearFocus")
                }
            }
            if focusedCorrelationID != nil {
                HStack(spacing: 12) {
                    Image(systemName: "scope").foregroundStyle(accent)
                    Text(focusedCorrelation == nil ? "The focused candidate is no longer in this investigation." : "Showing records cited by this possible correlation.")
                        .font(.subheadline.weight(.medium))
                    Spacer()
                    Button("Show all events") { focusedCorrelationID = nil }
                        .buttonStyle(.bordered).accessibilityIdentifier("timeline.clearFocus")
                }.padding(12).background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
            }
            HStack {
                TextField("Search hostname, process, protocol, or IP", text: $search).accessibilityIdentifier("timeline.search")
                    .textFieldStyle(.roundedBorder)
                Picker("Source", selection: $sourceFilter) {
                    Text("All sources").tag(nil as EvidenceSource?)
                    ForEach(EvidenceSource.allCases, id: \.self) { source in Text(source.rawValue).tag(source as EvidenceSource?) }
                }.frame(width: 190)
                Text("\(filteredObservations.count) shown").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }.disabled(focusedPeerID != nil || focusedSessionID != nil)
            if filteredObservations.isEmpty { card { emptyMessage(imports.isEmpty ? "Import evidence to view a normalized timeline." : "No observations match this filter.") } }
            else {
                LazyVStack(spacing: 1) {
                    ForEach(filteredObservations) { observation in
                        Button { selectedObservationID = observation.id; selectedCorrelationID = nil } label: {
                            HStack(alignment: .top, spacing: 14) {
                                Text(timeLabel(observation.timeMicroseconds)).font(.system(.caption2, design: .monospaced)).frame(width: 170, alignment: .leading)
                                Circle().fill(color(observation.source)).frame(width: 8, height: 8).padding(.top, 4)
                                Text(observation.source.rawValue).font(.caption.weight(.medium)).frame(width: 100, alignment: .leading)
                                Text(observation.kind).font(.caption.weight(.semibold)).frame(width: 118, alignment: .leading)
                                Text(timelineSummary(observation)).font(.caption).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                                Text(observation.process ?? "").font(.caption).foregroundStyle(.secondary).frame(width: 90, alignment: .trailing)
                            }
                            .foregroundStyle(ink)
                            .padding(.horizontal, 14).padding(.vertical, 11)
                            .background(selectedObservationID == observation.id ? Color.blue.opacity(0.12) : .white,
                                        in: RoundedRectangle(cornerRadius: 9))
                        }.buttonStyle(.plain).accessibilityIdentifier("timeline.record.\(observation.id)")
                    }
                }
            }
        }
    }

    var sourcesView: some View {
        VStack(alignment: .leading, spacing: 16) {
            if liveSession != nil || imports[.iphone] != nil { liveCoverageCard }
            ForEach(EvidenceSource.allCases, id: \.self) { source in
                card {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack {
                            Label(source.rawValue, systemImage: source == .iphone ? "iphone.gen3" : source == .mac ? "desktopcomputer" : "list.bullet.rectangle")
                                .font(.headline)
                            Spacer()
                            if imports[source] != nil { Text("IMPORTED").font(.caption.bold()).foregroundStyle(.green) }
                        }
                        if let artifact = imports[source]?.artifact {
                            detailLine("File", artifact.path)
                            detailLine("SHA-256", artifact.sha256)
                            detailLine("Records", "\(artifact.records)")
                            detailLine("Decoder", artifact.decoder)
                            detailLine("Clock offset", "\(Double(artifact.offsetMicroseconds) / 1_000) ms")
                            ForEach(artifact.warnings, id: \.self) { warning in
                                Label(warning, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
                            }
                        } else {
                            Text("No artifact loaded.").foregroundStyle(.secondary)
                            if source == .iosLog {
                                Text("Enable process logs before a live session, or open a finalized session containing their collection provenance. Standalone naive timestamps are not imported without that provenance.").font(.caption).foregroundStyle(.secondary)
                            } else { importButton(source, "Import \(source.rawValue)", "plus") }
                        }
                    }
                }
            }
            card {
                VStack(alignment: .leading, spacing: 10) {
                    sectionTitle("Protocol coverage", detail: "Fields are directly decoded from saved captures by TShark. Empty fields mean unavailable in that frame, not absent on the network.")
                    Text("Ethernet · ARP · IPv4 · IPv6 · ICMP · TCP · UDP · DNS · TLS · HTTP/1 · STUN · QUIC")
                        .font(.subheadline).foregroundStyle(ink)
                    Text("QUIC Initial SNI and ALPN appear only where the decoder can recover the ClientHello. Encrypted payloads, ECH inner names, and TLS 1.3 encrypted certificates remain unavailable without separate key material.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if let investigation {
                card {
                    VStack(alignment: .leading, spacing: 8) {
                        sectionTitle("Clock provenance", detail: "These settings are included in the exported investigation.")
                        if let sessionContext {
                            explanation("Host session context (separate artifact)", sessionContext.context.summary)
                            detailLine("Context SHA-256", sessionContext.sha256)
                            detailLine("Context artifact", sessionContext.path)
                            explanation("Log collection", sessionContext.context.logPredicate + " · level " + sessionContext.context.logLevel)
                        } else {
                            explanation("Host session context unavailable", "This investigation has no verified capture-context sidecar. Missing log bootUUID fields remain unknown; current Mac boot identity is never applied to an older capture.")
                        }
                        detailLine("Match window", "\(investigation.settings.windowMilliseconds) ms")
                        detailLine("Uncertainty", "\(investigation.settings.uncertaintyMilliseconds) ms")
                        detailLine("Alignment", investigation.settings.clocksVerified ? investigation.settings.alignmentMethod : "Not verified")
                    }
                }
                Button("Export investigation JSON…") { exportReport() }.buttonStyle(.borderedProminent)
            }
        }
    }

    var methodView: some View {
        VStack(alignment: .leading, spacing: 16) {
            notice
            card {
                VStack(alignment: .leading, spacing: 12) {
                    sectionTitle("Observed vs inferred", detail: "The detail panel links each claim to the frames or log records that support it.")
                    explanation("Direct observation", "A capture frame, PKTAP header, or Unified Log message carries this value. The original timestamp and source artifact remain visible.")
                    explanation("Inferred relationship", "The app compares observations after explicit offsets. A common endpoint, hostname, or time is a candidate relationship, not attribution.")
                    explanation("Flow hostname", "When SNI or HTTP Host appears in one frame, the app may associate it with another frame in the same decoded TCP/UDP stream. The supporting frame ID is shown.")
                }
            }
            card {
                VStack(alignment: .leading, spacing: 12) {
                    sectionTitle("Evidence-strength rubric", detail: "Points are transparent heuristics; they are not statistical probabilities.")
                    explanation("High", "Requires a strong endpoint match, a shared observed flow hostname, a labeled outbound Mac process, verified clocks with at most 50 ms uncertainty, and no competing Mac process.")
                    explanation("Moderate", "Several signals agree, but a required High condition is missing. Confirm the details manually.")
                    explanation("Low", "Limited or ambiguous evidence. Treat as a search lead.")
                    explanation("Clock alignment", "Offsets and uncertainty are investigator-supplied. Nearby timestamps do not establish event order when uncertainty is larger than the gap.")
                }
            }
            card {
                VStack(alignment: .leading, spacing: 12) {
                    sectionTitle("Capture and log inputs", detail: "A live session saves original RVI, PKTAP, and Unified Log streams together; existing files can also be imported.")
                    explanation("iPhone", "Live capture uses Apple's rvictl plus RVI-Sentinel's RVI/tcpdump flow. Existing RVI-Sentinel PCAP/PCAPNG files can also be imported.")
                    explanation("Mac", "Use a PCAP/PCAPNG containing PKTAP headers with interface and process metadata. Frames from rvi interfaces are excluded from cross-host candidates because they may be mirrored iPhone traffic.")
                    explanation("Unified Log", "Import UTF-8 JSON Lines with timestamp, eventMessage, processID, processImagePath, subsystem, and category. Log support requires the same Mac PID and an explicit endpoint or hostname mention. Redacted messages cannot supply a match.")
                }
            }
        }
    }

    var detailPanel: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text(selectedCorrelation != nil ? "POSSIBLE CORRELATION" : selectedObservation != nil ? "OBSERVATION" : "PACKET SESSION")
                        .font(.caption.bold()).tracking(1.6).foregroundStyle(.secondary)
                    Spacer()
                    Button { selectedCorrelationID = nil; selectedObservationID = nil; selectedSessionID = nil } label: { Image(systemName: "xmark.circle.fill") }.buttonStyle(.plain)
                }
                if let correlation = selectedCorrelation { correlationDetail(correlation) }
                if let observation = selectedObservation { observationDetail(observation) }
                else if let session = selectedSession { sessionDetail(session) }
            }.padding(20)
        }.background(.white)
    }

    func correlationDetail(_ correlation: Correlation) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text(correlation.confidence.rawValue).font(.title.bold()).foregroundStyle(confidenceColor(correlation.confidence))
                Spacer()
                Text("\(correlation.score) / 100").font(.headline.monospacedDigit())
            }
            Text("Evidence strength · \(String(format: "%.1f", correlation.deltaMilliseconds)) ms apart")
                .font(.subheadline).foregroundStyle(.secondary)
            Button("View cited records on timeline") {
                focusedPeerID = nil; focusedCorrelationID = correlation.id
                search = ""
                sourceFilter = nil
                selectedTab = .timeline
            }
            .buttonStyle(.borderedProminent)
            .accessibilityIdentifier("correlation.viewEvidence")
            if let phone = observation(correlation.iphoneID), let mac = observation(correlation.macID) {
                VStack(alignment: .leading, spacing: 9) {
                    explanation("iPhone RVI", "\(phone.summary)\n\(phone.destinationIP ?? "Unknown IP"):\(phone.destinationPort ?? "?") · frame \(phone.record)")
                    explanation("Mac PKTAP", "\(mac.process ?? "Unknown process") · PID \(mac.pid ?? "?")\n\(mac.remoteIP ?? "Unknown IP"):\(mac.remotePort ?? "?") · \(mac.interface ?? "unknown interface") · \(mac.direction.rawValue)")
                }
            }
            Divider()
            Text("WHY IT APPEARS").font(.caption.bold()).tracking(1.4).foregroundStyle(.secondary)
            ForEach(correlation.reasons, id: \.self) { reason in
                HStack(alignment: .top, spacing: 9) {
                    Image(systemName: reason.points > 0 ? "checkmark.circle.fill" : "minus.circle.fill")
                        .foregroundStyle(reason.points > 0 ? Color.green : Color.secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(reason.title) · \(reason.points > 0 ? "+\(reason.points)" : "not scored")").font(.subheadline.weight(.semibold))
                        Text(reason.detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                        Text(reason.observationIDs.joined(separator: " · ")).font(.caption2.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                    }
                }
            }
            Divider()
            Text("LIMITS AND UNCERTAINTY").font(.caption.bold()).tracking(1.4).foregroundStyle(.secondary)
            ForEach(correlation.limitations, id: \.self) { limitation in
                Label(limitation, systemImage: "exclamationmark.circle").font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if !correlation.logIDs.isEmpty {
                Divider()
                Text("SUPPORTING LOG RECORDS").font(.caption.bold()).tracking(1.4)
                ForEach(correlation.logIDs, id: \.self) { id in
                    evidenceRecordButton(id)
                }
            }
        }
    }

    func observationDetail(_ observation: Observation) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(observation.kind).font(.title3.bold()).foregroundStyle(ink)
            Text("Directly observed · \(observation.source.rawValue)").font(.caption.weight(.medium)).foregroundStyle(color(observation.source))
            Text(observation.summary).font(.subheadline).textSelection(.enabled)
            Divider()
            detailLine("Adjusted local time", timeLabel(observation.timeMicroseconds))
            detailLine("Original local time", timeLabel(observation.originalMicroseconds))
            detailLine("Original epoch microseconds", String(observation.originalMicroseconds))
            detailLine("Artifact", observation.artifactID)
            detailLine("Record", "\(observation.record)")
            if observation.source == .iphone || observation.source == .mac {
                rawPacketButton(observation)
                detailLine("Protocol stack", observation.protocols.joined(separator: " → "))
                detailLine("Source", "\(observation.sourceIP ?? "?"):\(observation.sourcePort ?? "?")")
                detailLine("Destination", "\(observation.destinationIP ?? "?"):\(observation.destinationPort ?? "?")")
                detailLine("Process", "\(observation.process ?? "unavailable") · PID \(observation.pid ?? "?")")
                detailLine("Effective process", "\(observation.effectiveProcess ?? "unavailable") · PID \(observation.effectivePID ?? "?")")
                Text(observation.source == .mac
                    ? "These process labels describe captured Mac traffic; they do not identify the process responsible for iPhone traffic."
                    : "These process labels are recorded in the iPhone-source capture. Their presence is observed metadata, not independently verified device process identity.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("PID/name is not a process lifetime identifier; missing labels are unknown, never PID 0 attribution.").font(.caption).foregroundStyle(.secondary)
                detailLine("Interface", "\(observation.interface ?? "unavailable") · \(observation.direction.rawValue)")
            }
            Divider()
            if observation.source == .log { logActivityDetails(observation) }
            else if observation.source == .iosLog {
                if let returnID = iosLogReturnID, self.observation(returnID) != nil {
                    Button("Return to RVI packet") { selectedObservationID = returnID; iosLogReturnID = nil }
                        .accessibilityIdentifier("evidence.iosLog.return")
                }
                explanation("iPhone process evidence", "This process emitted the device log. It is not Mac PKTAP attribution or proof that the process owns any RVI packet. Boot identity and activity identifiers are unavailable; PID and image UUID do not prove a process lifetime.")
                explanation("Clock and collection provenance", "Original collector timestamp is retained below. TZ=UTC was applied when collecting; clock offset is 0 ms and alignment remains unverified. Missing messages and redacted fields cannot support a link.")
            } else { hostnameDetails(observation) }
            if observation.source == .iphone { iosLogContextDetails(observation) }
            if let rejection = investigation?.diagnostics.rejections.first(where: { $0.observationID == observation.id }) {
                explanation("Why no candidate", rejection.reason + (rejection.nearestMilliseconds.map { " Nearest matching Mac packet: \(String(format: "%.3f", $0)) ms." } ?? ""))
            }
            Text("DECODED FIELDS").font(.caption.bold()).tracking(1.4).foregroundStyle(.secondary)
            ForEach(observation.fields.keys.sorted(), id: \.self) { key in
                VStack(alignment: .leading, spacing: 2) {
                    Text(fieldInfo(key).title).font(.caption.weight(.semibold))
                    Text(observation.values(key).joined(separator: ", ")).font(.caption.monospaced()).foregroundStyle(ink)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    Text(fieldInfo(key).explanation).font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Text("Only fields present in this decoded record are shown. Payload encryption and capture loss can hide other metadata.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    func observation(_ id: String) -> Observation? { displayedObservations.first { $0.id == id } }


}
