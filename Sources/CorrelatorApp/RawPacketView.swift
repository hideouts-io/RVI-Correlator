import CorrelatorCore
import SwiftUI

extension ContentView {
    func rawPacketButton(_ observation: Observation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            if let selectedSession, selectedSession.packetIDs.contains(observation.id) || focusedSessionID == selectedSession.id {
                Button("Return to packet session") { selectedObservationID = nil; selectedTab = .sessions }
                    .accessibilityIdentifier("session.returnFromPacket")
            }
            Button("Inspect original packet bytes") { loadRawPacket(observation) }
                .buttonStyle(.bordered)
                .disabled(rawPacketBusy)
                .accessibilityIdentifier("packet.inspectRaw")
            if rawPacketBusy && rawPacketID == observation.id { ProgressView("Checking original capture and byte ranges…").controlSize(.small) }
            if rawPacketID == observation.id, let rawPacketError {
                Label(rawPacketError, systemImage: "exclamationmark.triangle").font(.caption).foregroundStyle(.orange)
            }
            if rawPacketID == observation.id, let rawPacket { rawPacketDetail(rawPacket) }
        }
    }

    func loadRawPacket(_ observation: Observation) {
        guard let artifact = investigation?.artifacts.first(where: { $0.id == observation.artifactID }) ?? imports[observation.source]?.artifact else {
            rawPacketID = observation.id
            rawPacketError = "The original capture artifact for frame \(observation.record) is unavailable. Reimport the saved capture."
            return
        }
        rawPacketID = observation.id
        rawPacket = nil
        rawPacketError = nil
        selectedByteRangeID = nil
        rawPacketBusy = true
        Task {
            do {
                let result = try await Task.detached(priority: .userInitiated) {
                    try inspectRawPacket(observation, artifact: artifact)
                }.value
                if rawPacketID == observation.id { rawPacket = result }
            } catch {
                if rawPacketID == observation.id { rawPacketError = error.localizedDescription }
            }
            rawPacketBusy = false
        }
    }

    func rawPacketDetail(_ packet: RawPacketEvidence) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Divider()
            Text("ORIGINAL FRAME BYTES").font(.caption.bold()).tracking(1.2)
            Text("\(packet.bytes.count) captured bytes. Byte ranges below are shown only when TShark’s reported raw value exactly matches this saved frame at that offset.")
                .font(.caption).foregroundStyle(.secondary)
            if packet.ranges.isEmpty { Text("No decoded field has a verified byte range in this frame.").font(.caption).foregroundStyle(.orange) }
            else {
                Text("VERIFIED FIELD RANGES").font(.caption.bold()).tracking(1.2)
                ForEach(packet.ranges.prefix(32)) { range in
                    Button("\(range.field) · bytes \(range.offset)–\(range.offset + range.length - 1)") {
                        selectedByteRangeID = range.id
                    }.font(.caption.monospaced()).buttonStyle(.link)
                        .accessibilityIdentifier("raw.field.\(range.id)")
                }
                if packet.ranges.count > 32 { Text("First 32 mapped fields shown.").font(.caption).foregroundStyle(.secondary) }
            }
            let selected = packet.ranges.first { $0.id == selectedByteRangeID }
            let start = selected.map { max(0, ($0.offset - 32) / 16 * 16) } ?? 0
            let end = min(packet.bytes.count, start + 512)
            ScrollView(.horizontal) {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(stride(from: start, to: end, by: 16)), id: \.self) { offset in
                        HStack(spacing: 2) {
                            Text(String(format: "%06X", offset)).foregroundStyle(.secondary).frame(width: 48, alignment: .leading)
                            ForEach(offset..<min(offset + 16, end), id: \.self) { index in
                                Text(String(format: "%02X", packet.bytes[index]))
                                    .padding(.horizontal, 1)
                                    .background(selected.map { index >= $0.offset && index < $0.offset + $0.length } == true ? Color.yellow.opacity(0.7) : Color.clear)
                            }
                        }.font(.system(size: 10, design: .monospaced))
                    }
                }.padding(8)
            }
            .background(Color.black.opacity(0.035), in: RoundedRectangle(cornerRadius: 8))
            .accessibilityIdentifier("raw.hex")
            if packet.bytes.count > end { Text("Showing bytes \(start)–\(end - 1) of \(packet.bytes.count); select a field to move the hex window.").font(.caption).foregroundStyle(.secondary) }
            Text("\(packet.unmappedFields.count) decoded fields have no verified direct byte mapping, including synthesized, bit-level, reassembled, unavailable, or byte-mismatched values. Their decoded values remain visible above.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
