import AppKit
import CorrelatorCore
import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @State var sessionContext: SessionContextEvidence?
    @State var focusedPeerID: String?
    @State var peerReturnID: String?
    @State var expandedPeerFlowIDs: Set<String> = []
    @State var selectedTab: WorkspaceTab = .overview
    @State var imports: [EvidenceSource: ImportedEvidence] = [:]
    @State var investigation: Investigation?
    @State var isDemoSession = false
    @State var selectedCorrelationID: String?
    @State var selectedObservationID: String?
    @State var selectedSessionID: String?
    @State var focusedSessionID: String?
    @State var sessionSearch = ""
    @State var rawPacketID: String?
    @State var rawPacket: RawPacketEvidence?
    @State var rawPacketBusy = false
    @State var rawPacketError: String?
    @State var selectedByteRangeID: String?
    @State var iosLogReturnID: String?
    @State var focusedCorrelationID: String?
    @State var pendingSource: EvidenceSource?
    @State var pickingFile = false
    @State var busy = false
    @State var error: String?
    @State var search = ""
    @State var sourceFilter: EvidenceSource?
    @State var windowText = "250"
    @State var uncertaintyText = "1000"
    @State var phoneOffsetText = "0"
    @State var macOffsetText = "0"
    @State var logOffsetText = "0"
    @State var clocksVerified = false
    @State var alignmentMethod = ""
    @State var calibrations: [ClockCalibration] = []
    @State var calibrationSource: EvidenceSource = .iphone
    @State var calibrationSourceRecords = ""
    @State var calibrationReferenceRecords = ""
    @State var calibrationMarkers = ""
    @State var calibrationMethod = ""
    @State var calibrationUncertainty = ""
    @State var calibrationAttested = false
    @State var calibrationPreview: ClockCalibration?
    @State var activeDNSQuery = ""
    @State var activeDNSResults: [ActiveDNSResult] = []
    @State var activeDNSBusy = false
    @State var activeDNSError: String?
    @State var captureDevices: [CaptureDevice] = []
    @State var selectedDeviceID = ""
    @State var liveSession: LiveSession?
    @State var liveStatus: LiveCaptureStatus?
    @State var liveFinalized = false
    @State var liveStarting = false
    @State var collectIOSLogs = false
    @State var iosLogExecutable = LiveCaptureService.iosLogExecutable()
    @State var iosLogProcessID = ""
    @State var liveWarning: String?
    @State var liveHealthFailure: String?
    @State var savedSessionDirectory: URL?

    var selectedCorrelation: Correlation? { investigation?.correlations.first { $0.id == selectedCorrelationID } }
    var selectedSession: PacketSession? { investigation?.sessions.first { $0.id == selectedSessionID } }
    var focusedSession: PacketSession? { investigation?.sessions.first { $0.id == focusedSessionID } }
    var displayedObservations: [Observation] {
        investigation?.observations ?? imports.values.flatMap(\.observations).sorted { $0.timeMicroseconds < $1.timeMicroseconds }
    }
    var selectedObservation: Observation? {
        guard let selectedObservationID else { return nil }
        return displayedObservations.first { $0.id == selectedObservationID }
    }
    var focusedCorrelation: Correlation? { investigation?.correlations.first { $0.id == focusedCorrelationID } }
    var focusedPeer: PeerFlow? { investigation?.peerReview.flows.first { $0.id == focusedPeerID } }
    var filteredObservations: [Observation] {
        if let focusedSession {
            let correlations = investigation?.correlations.filter { focusedSession.correlationIDs.contains($0.id) } ?? []
            let peers = investigation?.peerReview.flows.filter { focusedSession.peerFlowIDs.contains($0.id) } ?? []
            let ids = Set(focusedSession.packetIDs + correlations.flatMap { [$0.iphoneID, $0.macID] + $0.logIDs } +
                          peers.flatMap { $0.pairs.flatMap { [$0.iphoneID, $0.macID] } + $0.logIDs })
            return displayedObservations.filter { ids.contains($0.id) }
        }
        if let focusedPeer {
            let ids = Set(focusedPeer.pairs.flatMap { [$0.iphoneID, $0.macID] } + focusedPeer.logIDs)
            return displayedObservations.filter { ids.contains($0.id) }
        }
        if focusedCorrelationID == nil && sourceFilter == nil && search.isEmpty { return displayedObservations }
        let focusedIDs = focusedCorrelation.map { correlation in
            Set([correlation.iphoneID, correlation.macID] + correlation.logIDs + correlation.reasons.flatMap(\.observationIDs))
        }
        return displayedObservations.filter { observation in
            (focusedCorrelationID == nil || focusedIDs?.contains(observation.id) == true) &&
            (sourceFilter == nil || observation.source == sourceFilter) &&
            (search.isEmpty || observation.summary.localizedCaseInsensitiveContains(search) ||
             (investigation?.hostnameEvidence[observation.id] ?? []).contains { $0.name.localizedCaseInsensitiveContains(search) } ||
             observation.kind.localizedCaseInsensitiveContains(search) ||
             observation.process?.localizedCaseInsensitiveContains(search) == true ||
             observation.destinationIP?.contains(search) == true)
        }
    }

    var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            HStack(spacing: 0) {
                ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        titleArea
                        mainArea
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(30)
                }
                .background(canvas)
                .onChange(of: selectedTab) { _, tab in
                    if tab == .sessions {
                        selectedObservationID = nil
                        selectedCorrelationID = nil
                    }
                    if tab == .correlations, let peerReturnID {
                        Task { await Task.yield(); proxy.scrollTo(peerReturnID, anchor: .top) }
                    }
                }
                }
                if selectedCorrelation != nil || selectedObservation != nil || selectedSession != nil {
                    Divider()
                    detailPanel.frame(minWidth: 330, idealWidth: 370, maxWidth: 420)
                }
            }
        }
        .tint(accent)
        .fileImporter(isPresented: $pickingFile, allowedContentTypes: [.data, .json, .item], allowsMultipleSelection: false) { result in
            do {
                guard let url = try result.get().first, let source = pendingSource else { return }
                importFile(url, source: source)
            } catch { self.error = "File selection failed: \(error.localizedDescription)" }
        }
        .alert("Could not complete analysis", isPresented: Binding(get: { error != nil }, set: { if !$0 { error = nil } })) {
            Button("OK") { error = nil }
        } message: { Text(error ?? "") }
        .task {
            await refreshCaptureDevices()
            let arguments = CommandLine.arguments
            if let option = arguments.firstIndex(of: "--open-session") {
                guard option + 1 < arguments.count else {
                    error = "--open-session requires the path to a finalized session folder."
                    return
                }
                loadSavedSession(URL(fileURLWithPath: arguments[option + 1], isDirectory: true))
            }
        }
        .task(id: liveSession?.id) {
            guard let session = liveSession else { return }
            await watchLiveSession(session)
        }
    }

    var sidebar: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 10) {
                Image(nsImage: RVICorrelatorApp.brandLogo)
                    .resizable().interpolation(.high).scaledToFit()
                    .frame(width: 48, height: 48)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text("RVI + PKTAP").font(.headline).foregroundStyle(ink)
                    Text("CORRELATOR").font(.system(size: 10, weight: .bold, design: .rounded)).tracking(2).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 16).padding(.top, 24)
            List(selection: $selectedTab) {
                Section("INVESTIGATE") {
                    ForEach([WorkspaceTab.overview, .sessions, .correlations, .timeline], id: \.self) { tab in
                        Label(tab.rawValue, systemImage: tab.symbol).tag(tab).accessibilityIdentifier("navigation.\(tab.rawValue)")
                    }
                }
                Section("REFERENCE") {
                    ForEach([WorkspaceTab.sources, .method], id: \.self) { tab in
                        Label(tab.rawValue, systemImage: tab.symbol).tag(tab).accessibilityIdentifier("navigation.\(tab.rawValue)")
                    }
                }
            }
            .scrollContentBackground(.hidden)
            Spacer(minLength: 0)
            VStack(alignment: .leading, spacing: 10) {
                Text("EVIDENCE LOADED").font(.system(size: 10, weight: .bold)).tracking(1.5).foregroundStyle(.secondary)
                ForEach(EvidenceSource.allCases, id: \.self) { source in
                    HStack {
                        Circle().fill(imports[source] == nil ? Color.gray.opacity(0.3) : color(source)).frame(width: 7, height: 7)
                        Text(source.rawValue).font(.caption)
                        Spacer()
                        Text(imports[source].map { String($0.artifact.records) } ?? "—").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
            }
            .padding(16)
            .background(.white.opacity(0.7), in: RoundedRectangle(cornerRadius: 14))
            .padding(.horizontal, 12)
            .padding(.bottom, 16)
        }
        .frame(minWidth: 225)
        .background(Color(red: 0.91, green: 0.94, blue: 0.97))
    }

    var titleArea: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 7) {
                Text(selectedTab.rawValue).font(.system(size: 31, weight: .bold, design: .rounded)).foregroundStyle(ink)
                Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
            }
            Spacer()
            if let investigation, investigation.isDemonstration {
                Text("SYNTHETIC DEMO").font(.caption.weight(.bold)).padding(.horizontal, 10).padding(.vertical, 6)
                    .background(Color.orange.opacity(0.15), in: Capsule()).foregroundStyle(.orange)
            }
            if busy { ProgressView().controlSize(.small) }
        }
    }

    var subtitle: String {
        switch selectedTab {
        case .overview: "Place packet and log evidence on one accountable timeline."
        case .sessions: "Observed packet flows within one capture, with inferred links kept separate."
        case .correlations: "Candidate relationships with visible evidence and uncertainty."
        case .timeline: "Direct observations, ordered by adjusted capture time in the Mac's local timezone."
        case .sources: "Original artifacts, integrity, clock offsets, and coverage."
        case .method: "What the score means, and what it cannot establish."
        }
    }

    @ViewBuilder var mainArea: some View {
        switch selectedTab {
        case .overview: overview
        case .sessions: sessionsView
        case .correlations: correlationsView
        case .timeline: timelineView
        case .sources: sourcesView
        case .method: methodView
        }
    }


}
