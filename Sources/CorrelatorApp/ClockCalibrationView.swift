import CorrelatorCore
import SwiftUI

extension ContentView {
    var calibrationCard: some View {
        card {
            DisclosureGroup("Measure clock alignment from independent reference events") {
                VStack(alignment: .leading, spacing: 10) {
                    Text("Mac packet timestamps are the reference. Enter at least two corresponding source and Mac record numbers, comma-separated, plus a distinct identity for each marker (semicolon-separated). Only use independently identified shared events; similar endpoints or nearby activity are insufficient.").font(.caption)
                    Picker("Source to calibrate", selection: $calibrationSource) {
                        Text("iPhone RVI").tag(EvidenceSource.iphone)
                        Text("Unified Log").tag(EvidenceSource.log)
                    }.accessibilityIdentifier("clock.source")
                    TextField("Source record numbers, e.g. 10, 50", text: $calibrationSourceRecords).accessibilityIdentifier("clock.sourceRecords")
                    TextField("Corresponding Mac record numbers", text: $calibrationReferenceRecords).accessibilityIdentifier("clock.referenceRecords")
                    TextField("Distinct marker identities, separated by semicolons", text: $calibrationMarkers).accessibilityIdentifier("clock.markerIdentities")
                    TextField("How did you independently identify these events?", text: $calibrationMethod).accessibilityIdentifier("clock.method")
                    TextField("Measurement uncertainty, ms", text: $calibrationUncertainty).accessibilityIdentifier("clock.measurementUncertainty")
                    Toggle("I independently identified the same reference events in both sources", isOn: $calibrationAttested).accessibilityIdentifier("clock.attestation")
                    Button("Calculate correction") { calculateCalibration() }.disabled(!calibrationAttested || busy).accessibilityIdentifier("clock.calculate")
                    if let preview = calibrationPreview {
                        Text(preview.summary).font(.caption).textSelection(.enabled)
                        Text("Valid only over the measured interval. Residual + measurement uncertainty is a conservative bound for these markers, not a statistical probability. Drift outside that interval is unverified.").font(.caption).foregroundStyle(.secondary)
                        Button("Apply this measured offset") { applyCalibration(preview) }.disabled(liveStatus?.phase == "running").accessibilityIdentifier("clock.apply")
                    }
                    ForEach(calibrations, id: \.source) { result in Text(result.summary).font(.caption).textSelection(.enabled) }
                }.textFieldStyle(.roundedBorder)
            }.accessibilityElement(children: .contain).accessibilityIdentifier("clock.calibration")
        }.onChange(of: [calibrationSource.rawValue, calibrationSourceRecords, calibrationReferenceRecords, calibrationMarkers, calibrationMethod, calibrationUncertainty]) { _, _ in
            calibrationPreview = nil
        }
    }

    func calculateCalibration() {
        do {
            func numbers(_ value: String) throws -> [Int] {
                try value.split(separator: ",", omittingEmptySubsequences: false).map {
                    guard let number = Int($0.trimmingCharacters(in: .whitespaces)), number > 0 else { throw AnalysisError.invalidInput("Calibration record numbers must be positive integers separated by commas.") }
                    return number
                }
            }
            let sources = try numbers(calibrationSourceRecords), references = try numbers(calibrationReferenceRecords)
            let identities = calibrationMarkers.split(separator: ";", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
            guard sources.count == references.count, sources.count == identities.count, let uncertainty = Double(calibrationUncertainty) else { throw AnalysisError.invalidInput("Provide equal counts of source records, Mac records and marker identities, plus numeric measurement uncertainty.") }
            let packets = displayedObservations
            let markers = try sources.indices.map { index -> ClockMarker in
                guard let source = packets.first(where: { $0.source == calibrationSource && $0.record == sources[index] }),
                      let reference = packets.first(where: { $0.source == .mac && $0.record == references[index] }) else {
                    throw AnalysisError.invalidInput("Calibration pair \(index + 1) does not identify loaded source and Mac records.")
                }
                return ClockMarker(sourceID: source.id, referenceID: reference.id, identity: identities[index])
            }
            calibrationPreview = try calibrateClock(source: calibrationSource, markers: markers, observations: packets, measurementUncertaintyMilliseconds: uncertainty, method: calibrationMethod)
        } catch { calibrationPreview = nil; self.error = error.localizedDescription }
    }

    func applyCalibration(_ result: ClockCalibration) {
        guard result.uncertaintyMilliseconds <= 60_000 else { error = "Measured uncertainty exceeds the supported 60,000 ms. Review event identity and clock drift."; return }
        let remaining = calibrations.filter { $0.source != result.source }
        calibrations = remaining + [result]
        if result.source == .iphone { phoneOffsetText = String(Double(result.offsetMicroseconds) / 1_000) }
        else { logOffsetText = String(Double(result.offsetMicroseconds) / 1_000) }
        macOffsetText = "0"
        uncertaintyText = String(calibrations.map(\.uncertaintyMilliseconds).max() ?? result.uncertaintyMilliseconds)
        alignmentMethod = calibrations.map(\.summary).joined(separator: "\n")
        clocksVerified = false
        rebuild()
    }
}
