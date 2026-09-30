import AppKit
import CorrelatorCore
import SwiftUI
import UniformTypeIdentifiers

extension ContentView {
    func metric(_ name: String, _ count: Int, _ detail: String, _ symbol: String) -> some View {
        card {
            VStack(alignment: .leading, spacing: 12) {
                HStack { Text(name).font(.caption.bold()).tracking(1.2); Spacer(); Image(systemName: symbol) }.foregroundStyle(.secondary)
                Text("\(count)").font(.system(size: 32, weight: .bold, design: .rounded)).foregroundStyle(ink)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }.frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    func correlationRow(_ correlation: Correlation) -> some View {
        let phone = observation(correlation.iphoneID)
        let mac = observation(correlation.macID)
        return HStack(spacing: 14) {
            RoundedRectangle(cornerRadius: 3).fill(confidenceColor(correlation.confidence)).frame(width: 4)
            VStack(alignment: .leading, spacing: 4) {
                Text(phone?.summary ?? "iPhone frame").font(.subheadline.weight(.semibold)).lineLimit(1)
                Text("\(mac?.process ?? "Unknown Mac process") · \(mac?.remoteIP ?? "?"):\(mac?.remotePort ?? "?")")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Text("\(String(format: "%.1f", correlation.deltaMilliseconds)) ms").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            Text(correlation.confidence.rawValue).font(.caption.weight(.bold)).foregroundStyle(confidenceColor(correlation.confidence))
                .frame(width: 76)
            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
        }
        .foregroundStyle(ink)
        .padding(13)
        .background(.white, in: RoundedRectangle(cornerRadius: 10))
    }

    func card<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        content().padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(.white, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(Color.black.opacity(0.045)))
    }

    func sectionTitle(_ title: String, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline).foregroundStyle(ink)
            Text(detail).font(.subheadline).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    func offsetField(_ label: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.caption.weight(.medium)).foregroundStyle(.secondary)
            TextField(label, text: text).textFieldStyle(.roundedBorder).font(.system(.body, design: .monospaced))
        }.frame(maxWidth: .infinity)
    }
    func explanation(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(ink)
            Text(body).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    func detailLine(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label.uppercased()).font(.system(size: 10, weight: .bold)).tracking(1).foregroundStyle(.secondary)
            Text(value).font(.caption.monospaced()).foregroundStyle(ink).textSelection(.enabled)
        }
    }
    func emptyMessage(_ message: String) -> some View {
        Text(message).font(.subheadline).foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 100)
    }
}

func color(_ source: EvidenceSource) -> Color {
    switch source { case .iphone: .blue; case .mac: .purple; case .log: .orange }
}

func confidenceColor(_ confidence: Confidence) -> Color {
    switch confidence { case .high: .green; case .moderate: .orange; case .low: .red }
}

func timeLabel(_ microseconds: Int64) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
    return formatter.string(from: Date(timeIntervalSince1970: Double(microseconds) / 1_000_000))
}
