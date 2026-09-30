import Foundation

public struct ClockMarker: Codable, Hashable, Sendable {
    public let sourceID: String
    public let referenceID: String
    public let identity: String
    public init(sourceID: String, referenceID: String, identity: String) {
        self.sourceID = sourceID; self.referenceID = referenceID; self.identity = identity
    }
}

public struct ClockCalibration: Codable, Sendable {
    public let source: EvidenceSource
    public let markers: [ClockMarker]
    public let offsetMicroseconds: Int64
    public let residualMilliseconds: Double
    public let uncertaintyMilliseconds: Double
    public let driftPPM: Double
    public let startMicroseconds: Int64
    public let endMicroseconds: Int64
    public let method: String
    public var summary: String {
        "\(source.rawValue): add \(Double(offsetMicroseconds) / 1_000) ms; max residual \(residualMilliseconds) ms; uncertainty \(uncertaintyMilliseconds) ms; observed drift \(String(format: "%.2f", driftPPM)) ppm. Method: \(method). Independent marker identity is investigator-attested, not proven by timing. No drift correction is applied."
    }
}

/// Fit a constant offset from independently identified events; keep originals untouched and expose drift.
public func calibrateClock(source: EvidenceSource, markers: [ClockMarker], observations: [Observation], measurementUncertaintyMilliseconds: Double, method: String) throws -> ClockCalibration {
    guard source != .mac, markers.count >= 2, Set(markers.map(\.sourceID)).count == markers.count,
          Set(markers.map(\.referenceID)).count == markers.count, Set(markers.map(\.identity)).count == markers.count,
          markers.allSatisfy({ !$0.identity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }),
          !method.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw AnalysisError.invalidInput("Calibration requires at least two distinct, independently identified source/Mac event pairs, unique marker descriptions, and a recorded method. Mac is the reference.")
    }
    guard measurementUncertaintyMilliseconds.isFinite, measurementUncertaintyMilliseconds >= 0, measurementUncertaintyMilliseconds <= 60_000 else {
        throw AnalysisError.invalidInput("Reference measurement uncertainty must be finite and between 0 and 60,000 ms.")
    }
    let lookup = Dictionary(uniqueKeysWithValues: observations.map { ($0.id, $0) })
    let samples = try markers.map { marker -> (time: Int64, delta: Int64) in
        guard let left = lookup[marker.sourceID], let right = lookup[marker.referenceID], left.source == source, right.source == .mac else {
            throw AnalysisError.invalidInput("Marker \(marker.identity) must identify existing \(source.rawValue) and Mac records from this investigation.")
        }
        let (delta, overflow) = right.originalMicroseconds.subtractingReportingOverflow(left.originalMicroseconds)
        guard !overflow, abs(Double(delta)) <= 86_400_000_000 else { throw AnalysisError.invalidInput("Clock marker \(marker.identity) implies an offset beyond one day.") }
        return (left.originalMicroseconds, delta)
    }.sorted { $0.time < $1.time }
    guard let first = samples.first, let last = samples.last, last.time > first.time else {
        throw AnalysisError.invalidInput("Calibration markers must span distinct source timestamps to assess residuals and drift.")
    }
    let deltas = samples.map(\.delta).sorted()
    let middle = deltas.count / 2
    let offset = deltas.count.isMultiple(of: 2) ? Int64((Double(deltas[middle - 1]) + Double(deltas[middle])) / 2) : deltas[middle]
    let residual = samples.map { abs(Double($0.delta) - Double(offset)) / 1_000 }.max() ?? 0
    return ClockCalibration(source: source, markers: markers, offsetMicroseconds: offset, residualMilliseconds: residual,
        uncertaintyMilliseconds: residual + measurementUncertaintyMilliseconds,
        driftPPM: Double(last.delta - first.delta) / Double(last.time - first.time) * 1_000_000,
        startMicroseconds: first.time, endMicroseconds: last.time, method: method)
}
