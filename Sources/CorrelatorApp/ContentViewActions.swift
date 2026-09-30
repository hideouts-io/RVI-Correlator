import AppKit
import CorrelatorCore
import SwiftUI
import UniformTypeIdentifiers

extension ContentView {
    func openSavedSession() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = "Choose a finalized RVI Correlator session folder containing manifest.json."
        guard panel.runModal() == .OK, let directory = panel.url else { return }
        loadSavedSession(directory)
    }

    func loadSavedSession(_ directory: URL) {
        busy = true
        Task {
            do {
                let items = try await Task.detached(priority: .userInitiated) {
                    let access = directory.startAccessingSecurityScopedResource()
                    defer { if access { directory.stopAccessingSecurityScopedResource() } }
                    return try LiveCaptureService.loadSavedSession(directory)
                }.value
                focusedPeerID = nil; peerReturnID = nil; expandedPeerFlowIDs = []
                imports = Dictionary(uniqueKeysWithValues: items.map { ($0.artifact.source, $0) })
                liveSession = nil
                liveStatus = nil
                sessionContext = try LiveCaptureService.savedContext(directory)
                savedSessionDirectory = directory
                isDemoSession = false
                selectedCorrelationID = nil
                selectedObservationID = nil
                focusedCorrelationID = nil
                phoneOffsetText = "0"
                macOffsetText = "0"
                logOffsetText = "0"
                calibrations = []
                activeDNSResults = []
                calibrationPreview = nil
                clocksVerified = false
                alignmentMethod = ""
                rebuild(demonstration: false)
            } catch { busy = false; self.error = "Could not open saved session: \(error.localizedDescription)" }
        }
    }

    func importButton(_ source: EvidenceSource, _ title: String, _ symbol: String) -> some View {
        Button {
            pendingSource = source
            pickingFile = true
        } label: { Label(title, systemImage: symbol).frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent).controlSize(.large).disabled(busy)
    }

    func importFile(_ url: URL, source: EvidenceSource) {
        let offset: Int64
        do { offset = try parseOffset(source) }
        catch { self.error = error.localizedDescription; return }
        busy = true
        Task {
            do {
                let item = try await Task.detached(priority: .userInitiated) {
                    let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    if source == .log { return try importUnifiedLog(url, offsetMicroseconds: offset) }
                    return try importCapture(url, source: source, offsetMicroseconds: offset)
                }.value
                if isDemoSession { imports.removeAll(); isDemoSession = false }
                sessionContext = nil; focusedPeerID = nil; peerReturnID = nil
                savedSessionDirectory = nil
                calibrations = []; calibrationPreview = nil; clocksVerified = false
                imports[source] = item
                investigation = nil
                selectedCorrelationID = nil
                selectedObservationID = nil
                focusedCorrelationID = nil
                rebuild()
            } catch { busy = false; self.error = error.localizedDescription }
        }
    }

    func loadDemo() {
        guard let phone = Bundle.module.url(forResource: "iphone", withExtension: "pcap", subdirectory: "Samples"),
              let mac = Bundle.module.url(forResource: "mac-pktap", withExtension: "pcap", subdirectory: "Samples"),
              let log = Bundle.module.url(forResource: "unified-log", withExtension: "ndjson", subdirectory: "Samples") else {
            error = "The synthetic example is missing from the application bundle. Rebuild the app resources."
            return
        }
        busy = true
        Task {
            do {
                let items = try await Task.detached(priority: .userInitiated) {
                    [try importCapture(phone, source: .iphone, offsetMicroseconds: 0),
                     try importCapture(mac, source: .mac, offsetMicroseconds: 0),
                     try importUnifiedLog(log, offsetMicroseconds: 0)]
                }.value
                focusedPeerID = nil; peerReturnID = nil; expandedPeerFlowIDs = []
                imports = Dictionary(uniqueKeysWithValues: items.map { ($0.artifact.source, $0) })
                sessionContext = nil; focusedPeerID = nil; peerReturnID = nil
                savedSessionDirectory = nil
                isDemoSession = true
                investigation = nil
                selectedCorrelationID = nil
                selectedObservationID = nil
                focusedCorrelationID = nil
                rebuild(demonstration: true)
            } catch { busy = false; self.error = error.localizedDescription }
        }
    }

    func parseOffset(_ source: EvidenceSource) throws -> Int64 {
        let value = source == .iphone ? phoneOffsetText : source == .mac ? macOffsetText : logOffsetText
        guard let ms = Double(value), ms.isFinite, abs(ms) <= 86_400_000 else {
            throw AnalysisError.invalidInput("\(source.rawValue) clock offset must be a finite number of milliseconds within one day.")
        }
        return Int64((ms * 1_000).rounded())
    }

    func rebuild() { rebuild(demonstration: isDemoSession) }

    func rebuild(demonstration: Bool) {
        guard imports[.iphone] != nil, imports[.mac] != nil else { busy = false; investigation = nil; return }
        do {
            guard let window = Double(windowText), let uncertainty = Double(uncertaintyText) else {
                throw AnalysisError.invalidInput("Enter numeric match-window and clock-uncertainty values in milliseconds.")
            }
            let settings = CorrelationSettings(windowMilliseconds: window, uncertaintyMilliseconds: uncertainty, clocksVerified: clocksVerified, alignmentMethod: alignmentMethod, calibrations: calibrations)
            try settings.validate()
            let offsets = try Dictionary(uniqueKeysWithValues: imports.keys.map { ($0, try parseOffset($0)) })
            let evidence = Array(imports.values)
            busy = true
            Task {
                do {
                    let (updated, result) = try await Task.detached(priority: .userInitiated) {
                        let updated = try evidence.map { item -> ImportedEvidence in
                            guard let newOffset = offsets[item.artifact.source] else {
                                throw AnalysisError.invalidInput("Missing clock offset for \(item.artifact.source.rawValue).")
                            }
                            let delta = newOffset - item.artifact.offsetMicroseconds
                            let shifted = try item.observations.map { observation -> Observation in
                                let (time, overflow) = observation.timeMicroseconds.addingReportingOverflow(delta)
                                guard !overflow else { throw AnalysisError.invalidInput("Clock offset overflows an observation timestamp.") }
                                return Observation(id: observation.id, source: observation.source, artifactID: observation.artifactID, record: observation.record,
                                                   originalMicroseconds: observation.originalMicroseconds, timeMicroseconds: time,
                                                   protocols: observation.protocols, fields: observation.fields, dnsRecords: observation.dnsRecords)
                            }
                            let old = item.artifact
                            let artifact = Artifact(id: old.id, source: old.source, path: old.path, sha256: old.sha256, bytes: old.bytes,
                                                    records: old.records, decoder: old.decoder, offsetMicroseconds: newOffset, warnings: old.warnings)
                            return ImportedEvidence(artifact: artifact, observations: shifted)
                        }
                        let result = try correlate(updated, settings: settings, isDemonstration: demonstration)
                        return (updated, result)
                    }.value
                    investigation = result
                    imports = Dictionary(uniqueKeysWithValues: updated.map { ($0.artifact.source, $0) })
                    busy = false
                } catch { busy = false; self.error = error.localizedDescription }
            }
        } catch { busy = false; self.error = error.localizedDescription }
    }

    func exportReport() {
        guard let investigation else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "rvi-correlation-investigation.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            try encoder.encode(InvestigationExport(investigation: investigation, activeLookups: activeDNSResults, sessionContext: sessionContext)).write(to: url, options: .atomic)
        } catch { self.error = "Could not export report to \(url.path): \(error.localizedDescription)" }
    }


}

private struct InvestigationExport: Encodable {
    let investigation: Investigation
    let activeLookups: [ActiveDNSResult]
    let sessionContext: SessionContextEvidence?
}
