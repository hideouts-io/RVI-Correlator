import AppKit
import CorrelatorCore
import SwiftUI

extension ContentView {
    var selectedCaptureDevice: CaptureDevice? { captureDevices.first { $0.id == selectedDeviceID } }
    var captureReady: Bool {
        selectedCaptureDevice?.isConnected == true && LiveCaptureService.rviExecutable() != nil && (try? tsharkExecutable()) != nil
    }

    var liveCaptureCard: some View {
        card {
            VStack(alignment: .leading, spacing: 15) {
                HStack {
                    sectionTitle("Live capture", detail: "One session starts iPhone RVI, Mac PKTAP, and Mac Unified Log together. Original streams are saved in Documents/RVI-Correlator/Sessions.")
                    Spacer()
                    Text(liveHealthFailure != nil ? "HEALTH UNKNOWN" : liveStatus?.phase.uppercased() ?? (liveStarting || liveSession != nil ? "STARTING" : captureReady ? "READY" : "SETUP NEEDED"))
                        .font(.caption.bold()).foregroundStyle(liveHealthFailure != nil ? .orange : liveStatus?.phase == "running" ? .green : .secondary)
                }
                HStack(spacing: 10) {
                    Picker("iPhone", selection: $selectedDeviceID) {
                        Text("Select a USB-connected iPhone").tag("")
                        ForEach(captureDevices) { device in
                            Text("\(device.name) · \(device.connection)").tag(device.id)
                        }
                    }.frame(maxWidth: 470).disabled(liveSession != nil || liveStarting)
                        .accessibilityIdentifier("capture.device")
                    Button("Refresh devices") { Task { await refreshCaptureDevices() } }
                        .disabled(liveStarting || liveStatus?.phase == "running")
                        .accessibilityIdentifier("capture.refreshDevices")
                    if liveSession == nil {
                        Button("Start live session") { startLiveCapture() }
                            .buttonStyle(.borderedProminent).disabled(!captureReady || liveStarting)
                            .accessibilityIdentifier("capture.start")
                    } else if liveStatus?.phase == "running" {
                        Button("Stop and finalize") { stopLiveCapture() }
                            .buttonStyle(.borderedProminent)
                            .accessibilityIdentifier("capture.stop")
                    } else if liveStatus?.phase == "stopped" && !liveFinalized {
                        Button("Finalize evidence") { Task { if let session = liveSession { await finalizeLiveEvidence(session) } } }
                    }
                    if liveFinalized || liveStatus?.phase == "failed" || liveStatus?.phase == "stopped" {
                        Button("New session") {
                            liveSession = nil
                            liveStatus = nil
                            liveFinalized = false
                            liveWarning = nil
                            liveHealthFailure = nil
                            iosLogImportFailure = nil
                            iosLogProcessID = ""
                        }
                    }
                }
                if liveSession == nil {
                    VStack(alignment: .leading, spacing: 8) {
                        Toggle("Include iPhone process logs (experimental)", isOn: $collectIOSLogs)
                            .accessibilityIdentifier("capture.iosLogs.enabled")
                        if collectIOSLogs {
                            TextField("pymobiledevice3 executable path", text: $iosLogExecutable)
                                .textFieldStyle(.roundedBorder).accessibilityIdentifier("capture.iosLogs.executable")
                            TextField("Current iPhone process PID", text: $iosLogProcessID)
                                .textFieldStyle(.roundedBorder).frame(maxWidth: 250).accessibilityIdentifier("capture.iosLogs.pid")
                            Text("Choose one current device PID from Console or idevicesyslog pidlist. Uses the paired device’s OS trace relay at default/error/fault levels; no automatic installation. A restarted process needs a new capture. PID reuse cannot be excluded.")
                                .font(.caption).foregroundStyle(.secondary)
                            Text("Device logs provide unscored endpoint context. Offset stays 0 ms, alignment unverified. Private fields and missing messages remain unavailable; log loss is not measurable.")
                                .font(.caption).foregroundStyle(.secondary)
                            Text("Capability labels: \(iosLogCapabilityLabels().map(\.rawValue).joined(separator: " · ")). Live capture currently implements only OSLog / Unified Logging through the device trace relay; the other labels remain distinct, unavailable import/capability states.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }.disabled(liveStarting)
                    HStack(alignment: .top, spacing: 14) {
                        readinessItem("Device", ready: selectedCaptureDevice?.isConnected == true,
                                      detail: selectedCaptureDevice == nil ? "Connect, unlock, trust, then refresh." :
                                        selectedCaptureDevice?.isConnected == true ? "Paired physical iPhone matched to the current USB registry. RVI service checked at start; developer tunnel not required." : "No current USB match for this paired iPhone. Connect, unlock, trust, then refresh.")
                        readinessItem("Apple RVI", ready: LiveCaptureService.rviExecutable() != nil,
                                      detail: LiveCaptureService.rviExecutable() == nil ? "rvictl missing; install Xcode device support." : "rvictl available for capture setup.")
                        readinessItem("Decoder", ready: (try? tsharkExecutable()) != nil,
                                      detail: (try? tsharkExecutable()) == nil ? "Install TShark to decode live evidence." : "TShark available for the timeline.")
                    }
                }
                if let session = liveSession {
                    HStack(spacing: 10) {
                        let evidenceDirectory = liveFinalized ? session.directory : session.captureDirectory
                        Text("Session: \(evidenceDirectory.path)").font(.caption.monospaced()).textSelection(.enabled)
                        Button("Reveal in Finder") {
                            if !NSWorkspace.shared.open(evidenceDirectory) {
                                error = "Finder could not open \(evidenceDirectory.path)."
                            }
                        }
                            .buttonStyle(.bordered).accessibilityIdentifier("capture.revealSession")
                    }
                    if let status = liveStatus {
                        if let collection = status.iosLogStatus {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("iPhone Unified Logging").font(.caption.bold())
                                Text("Collector launcher: \(liveHealthFailure == nil ? iosLogLifecycleLabel(collection.state) : "last status may be stale")")
                                    .accessibilityIdentifier("capture.iosLogs.collector")
                                Text("\(liveHealthFailure == nil ? "Evidence" : "Last reported evidence"): \(iosLogImportFailure == nil ? iosLogEvidenceLabel(collection.evidence) : "Live import failed; original bytes retained")")
                                    .accessibilityIdentifier("capture.iosLogs.evidence")
                                Text("\(liveHealthFailure == nil ? "Saved data" : "Last reported saved data"): \(status.iosLogBytes.map { "\($0) bytes" } ?? "output file not created")")
                                    .accessibilityIdentifier("capture.iosLogs.bytes")
                                Text("Decoded records: \(imports[.iosLog].map { "\($0.observations.count) from the last successful import" } ?? "not yet imported")")
                                    .accessibilityIdentifier("capture.iosLogs.decodedRecords")
                                DisclosureGroup("Collection details") {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text("Source: \(collection.source.rawValue) via OS trace relay")
                                        Text(status.iosLogPID.map { "Launcher PID: \($0)" } ?? "Launcher not started")
                                        Text("Redaction: \(collection.redaction.rawValue)")
                                            .accessibilityIdentifier("capture.iosLogs.redaction")
                                        Text("Dropped records: \(collection.droppedRecords.rawValue)")
                                            .accessibilityIdentifier("capture.iosLogs.droppedRecords")
                                        Text("Clock alignment: \(collection.clockAlignment.rawValue)")
                                            .accessibilityIdentifier("capture.iosLogs.clockAlignment")
                                        Text(collection.detail)
                                    }.font(.caption2).foregroundStyle(.secondary)
                                }
                                if let iosLogImportFailure {
                                    Text("Record import failed: \(iosLogImportFailure)")
                                        .foregroundStyle(.red).accessibilityIdentifier("capture.iosLogs.importFailure")
                                }
                                if collection.state == .failed, let failure = status.error {
                                    Text("Capture failure: \(failure)")
                                        .foregroundStyle(.red).accessibilityIdentifier("capture.iosLogs.failure")
                                }
                            }.font(.caption).foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        HStack(spacing: 22) {
                            healthLabel("iPhone RVI", pid: status.rviPID, packets: status.rviPackets, dropped: status.rviDropped)
                            healthLabel("Mac PKTAP", pid: status.pktapPID, packets: status.pktapPackets, dropped: status.pktapDropped)
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Unified Log").font(.caption.bold())
                                Text(status.logPID.map { "PID \($0)" } ?? "Collector pending").font(.caption.monospaced()).foregroundStyle(.secondary)
                                Text("Raw log saved separately").font(.caption)
                                Text("Packet counters do not apply").font(.caption).foregroundStyle(.secondary)
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                        if let interface = status.rviInterface { Text("Mac RVI interface: \(interface) · packet-reported iPhone interfaces appear under Evidence sources.").font(.caption).foregroundStyle(.secondary) }
                        if let first = status.rviStreamStartedAt, let last = status.logStreamStartedAt {
                            Text("Collector start separation: \(Int(last.timeIntervalSince(first))) s (status precision: 1 s). This does not measure clock alignment. Original packet and log timestamps are retained.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        if let failure = status.error { Text(failure).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
                        if (status.rviDropped ?? 0) > 0 || (status.pktapDropped ?? 0) > 0 {
                            Label("Kernel drops were reported. The saved capture may be incomplete.", systemImage: "exclamationmark.triangle.fill")
                                .font(.caption.weight(.medium)).foregroundStyle(.orange)
                        }
                    }
                }
                if let liveWarning { Label(liveWarning, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange).textSelection(.enabled) }
                Text("RVI visibility is measured from captured packets. Loopback and inner VPN/tunnel traffic may remain unavailable. Unified Log collects default-level network and selected Apple-service events; other processes and redacted data may be absent.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    func iosLogLifecycleLabel(_ state: IOSLogCollectionState) -> String {
        switch state {
        case .unavailable: "Not requested"
        case .starting: "Starting"
        case .running: "Running"
        case .stopping: "Stopping"
        case .stopped: "Stopped; finalization is separate"
        case .failed: "Session failed; inspect diagnostics"
        case .streaming: "Legacy streaming status; delivery unverified"
        case .partial: "Legacy partial status; failure cause unverified"
        }
    }

    func iosLogEvidenceLabel(_ evidence: IOSLogEvidenceObservation?) -> String {
        switch evidence ?? .unknown {
        case .unknown: "Unverified in this saved status"
        case .notObserved: "No bytes observed"
        case .bytesObserved: "Bytes observed; record validity unverified"
        case .incompleteRecord: "Current file ends with an incomplete record; earlier lines may exist"
        case .completeLinesObserved: "Complete lines observed; decode result shown separately"
        }
    }

    func readinessItem(_ title: String, ready: Bool, detail: String) -> some View {
        HStack(alignment: .top, spacing: 7) {
            Image(systemName: ready ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                .foregroundStyle(ready ? .green : .orange)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption.weight(.semibold))
                Text(detail).font(.caption2).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    func healthLabel(_ title: String, pid: Int32?, packets: Int?, dropped: Int?) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption.weight(.semibold))
            Text(pid.map { "PID \($0)" } ?? "Not started").font(.caption2.monospaced()).foregroundStyle(.secondary)
            if pid != nil {
                Text(packets.map { "\($0) captured" } ?? "Packet count pending").font(.caption2)
                Text(dropped.map { "\($0) kernel drops" } ?? "Kernel drops not yet measured").font(.caption2).foregroundStyle(dropped ?? 0 > 0 ? .orange : .secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    var liveCoverageCard: some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                sectionTitle("iPhone interface coverage", detail: "Only packet-reported interface names are directly observed. Status is per session, not a claim that all traffic on that interface was captured.")
                ForEach(iphoneInterfaceCoverage(displayedObservations)) { item in
                    HStack(alignment: .top, spacing: 12) {
                        Text(item.id).font(.caption.weight(.semibold)).frame(width: 190, alignment: .leading)
                        Text(item.status).font(.caption).frame(width: 155, alignment: .leading)
                        Text(item.detail).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("A supported Network Extension packet tunnel can observe traffic routed through that particular tunnel with an appropriate entitlement and device-side deployment. It is not a general all-interface capture and cannot validate loopback or unrelated VPN traffic.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    func refreshCaptureDevices() async {
        do {
            let devices = try await Task.detached(priority: .userInitiated) { try LiveCaptureService.devices() }.value
            captureDevices = devices
            if !devices.contains(where: { $0.id == selectedDeviceID }) {
                selectedDeviceID = devices.first(where: \.isConnected)?.id ?? ""
            }
        } catch { self.error = error.localizedDescription }
    }

    func startLiveCapture() {
        guard let device = captureDevices.first(where: { $0.id == selectedDeviceID }) else {
            error = "Select an iPhone before starting capture."
            return
        }
        liveStarting = true
        liveWarning = nil
        iosLogImportFailure = nil
        let includeIOS = collectIOSLogs
        let executable = iosLogExecutable
        let processID = iosLogProcessID
        Task {
            do {
                let session = try await Task.detached(priority: .userInitiated) {
                    let config = includeIOS ? try LiveCaptureService.iosLogConfiguration(executable: executable, processID: processID) : nil
                    return try LiveCaptureService.start(device: device, iosLogConfiguration: config)
                }.value
                phoneOffsetText = "0"; macOffsetText = "0"; logOffsetText = "0"
                clocksVerified = false; alignmentMethod = ""; calibrations = []; calibrationPreview = nil
                sessionContext = nil; focusedPeerID = nil; peerReturnID = nil; expandedPeerFlowIDs = []
                imports = [:]
                savedSessionDirectory = nil
                investigation = nil
                isDemoSession = false
                selectedCorrelationID = nil
                selectedObservationID = nil
                focusedCorrelationID = nil
                liveFinalized = false
                liveStatus = nil
                liveSession = session
                liveStarting = false
            } catch { liveStarting = false; self.error = error.localizedDescription }
        }
    }

    func stopLiveCapture() {
        guard let session = liveSession else { return }
        do { try LiveCaptureService.stop(session) }
        catch { self.error = "Could not request a clean stop for \(session.directory.path): \(error.localizedDescription)" }
    }

    func watchLiveSession(_ session: LiveSession) async {
        while !Task.isCancelled {
            do {
                let status = try await Task.detached { try LiveCaptureService.status(session) }.value
                guard liveSession?.id == session.id, !Task.isCancelled else { return }
                liveStatus = status
                if status?.phase == "failed" {
                    await refreshLiveEvidence(session)
                    guard liveSession?.id == session.id, !Task.isCancelled else { return }
                    let detail = [status?.error, liveWarning].compactMap { $0 }.joined(separator: " ")
                    liveWarning = detail.isEmpty ? "Capture helper failed. Inspect saved diagnostics." : detail
                    return
                }
                if status?.phase == "running" { await refreshLiveEvidence(session) }
                if status?.phase == "stopped" {
                    await finalizeLiveEvidence(session)
                    return
                }
            } catch {
                guard liveSession?.id == session.id, !Task.isCancelled else { return }
                liveHealthFailure = error.localizedDescription
                liveWarning = error.localizedDescription
                return
            }
            try? await Task.sleep(for: .seconds(4))
        }
    }

    func liveSettings() throws -> CorrelationSettings {
        guard let window = Double(windowText), let uncertainty = Double(uncertaintyText) else {
            throw AnalysisError.invalidInput("Enter numeric match-window and clock-uncertainty values before live analysis.")
        }
        let settings = CorrelationSettings(windowMilliseconds: window, uncertaintyMilliseconds: uncertainty,
                                           clocksVerified: clocksVerified, alignmentMethod: alignmentMethod)
        try settings.validate()
        return settings
    }

    func refreshLiveEvidence(_ session: LiveSession) async {
        do {
            let settings = try liveSettings()
            let existing = imports
            let oldPhone = existing[.iphone]?.observations ?? []
            let oldMac = existing[.mac]?.observations ?? []
            let result = try await Task.detached(priority: .userInitiated) { () throws -> (items: [ImportedEvidence], investigation: Investigation?, iosLogFailure: String?) in
                let updates = try LiveCaptureService.liveEvidence(session, existingPhone: oldPhone, existingMac: oldMac)
                let items = try updates.items.map { update -> ImportedEvidence in
                    guard update.artifact.source == .iphone || update.artifact.source == .mac,
                          let previous = existing[update.artifact.source] else { return update }
                    return try mergeLiveCapture(previous, update: update)
                }
                var displayedItems = items
                if updates.iosLogFailure != nil, let previous = existing[.iosLog] {
                    let old = previous.artifact
                    let warning = "Live iPhone OS trace import failed after this snapshot. The current file may contain undecoded bytes; this prefix is not final evidence."
                    let warnings = old.warnings.contains(warning) ? old.warnings : old.warnings + [warning]
                    let artifact = Artifact(id: old.id, source: old.source, path: old.path, sha256: old.sha256,
                                            bytes: old.bytes, records: old.records, decoder: old.decoder,
                                            offsetMicroseconds: old.offsetMicroseconds, warnings: warnings)
                    displayedItems.append(ImportedEvidence(artifact: artifact, observations: previous.observations))
                }
                guard displayedItems.contains(where: { $0.artifact.source == .iphone }),
                      displayedItems.contains(where: { $0.artifact.source == .mac }) else { return (displayedItems, nil, updates.iosLogFailure) }
                return (displayedItems, try correlate(displayedItems, settings: settings, isDemonstration: false), updates.iosLogFailure)
            }.value
            guard liveSession?.id == session.id, !Task.isCancelled else { return }
            if !result.items.isEmpty {
                imports = Dictionary(uniqueKeysWithValues: result.items.map { ($0.artifact.source, $0) })
                investigation = result.investigation
            }
            iosLogImportFailure = result.iosLogFailure
            liveWarning = result.iosLogFailure.map { "iPhone record import failed: \($0). Previously decoded records are retained; final import is still required." }
        } catch {
            guard liveSession?.id == session.id, !Task.isCancelled else { return }
            liveWarning = "Live evidence refresh failed: \(error.localizedDescription)"
        }
    }

    func finalizeLiveEvidence(_ session: LiveSession) async {
        do {
            let settings = try liveSettings()
            let oldPhone = imports[.iphone]?.observations ?? []
            let oldMac = imports[.mac]?.observations ?? []
            let result = try await Task.detached(priority: .userInitiated) { () throws -> ([ImportedEvidence], Investigation) in
                let items = try LiveCaptureService.finalEvidence(session, existingPhone: oldPhone, existingMac: oldMac)
                return (items, try correlate(items, settings: settings, isDemonstration: false))
            }.value
            guard liveSession?.id == session.id, !Task.isCancelled else { return }
            imports = Dictionary(uniqueKeysWithValues: result.0.map { ($0.artifact.source, $0) })
            investigation = result.1
            sessionContext = try LiveCaptureService.savedContext(session.directory)
            liveFinalized = true
            liveWarning = nil
            iosLogImportFailure = nil
        } catch {
            guard liveSession?.id == session.id, !Task.isCancelled else { return }
            liveWarning = "Final evidence verification failed: \(error.localizedDescription)"
        }
    }
}
