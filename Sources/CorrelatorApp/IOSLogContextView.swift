import CorrelatorCore
import SwiftUI

extension ContentView {
    func iosLogContextDetails(_ packet: Observation) -> some View {
        let logs = imports[.iosLog]?.observations ?? []
        let window = Int64((investigation?.settings.windowMilliseconds ?? 250) * 1_000)
        let review = iosLogContext(packet, logs: logs, windowMicroseconds: window)
        return VStack(alignment: .leading, spacing: 8) {
            Text("iPHONE LOG CONTEXT · UNSCORED").font(.caption.bold())
            if logs.isEmpty {
                Text("No device log records collected for this session. Missing evidence is not evidence that activity did not occur.").font(.caption).foregroundStyle(.secondary)
            } else {
                Text("\(review.matches.count) endpoint-mention records inside the \(window / 1_000) ms window. \(review.outsideWindow) endpoint mentions outside it; \(review.withoutEndpoint) records lack a matching endpoint or observed hostname.")
                    .font(.caption).foregroundStyle(.secondary)
                Text("These are inferred review links based on explicit text mentions and unverified clocks. An address may be shared, multicast, or mentioned as context. No port ownership, causal relationship, or confidence increase is established; other processes may be missing.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(review.matches.prefix(20))) { log in
                    Button {
                        iosLogReturnID = packet.id
                        selectedObservationID = log.id
                    } label: {
                        Text("iPhone log #\(log.record) · \(log.process ?? "unknown process") · \(timeLabel(log.timeMicroseconds))").font(.caption)
                    }.buttonStyle(.link).accessibilityIdentifier("evidence.iosLog.\(log.id)")
                }
                if review.matches.count > 20 { Text("First 20 links shown. Filter the iPhone OS trace source in the timeline for the remaining records.").font(.caption) }
            }
        }.accessibilityIdentifier("evidence.iosLogContext")
    }
}
