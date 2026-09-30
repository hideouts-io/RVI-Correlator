import AppKit
import CorrelatorCore
import SwiftUI
import UniformTypeIdentifiers

@main
struct RVICorrelatorApp: App {
    static let brandLogo: NSImage = {
        guard let url = Bundle.module.url(forResource: "BrandLogo", withExtension: "png"),
              let image = NSImage(contentsOf: url) else {
            fatalError("Required BrandLogo.png is missing or invalid in the app resource bundle. Rebuild the packaged app.")
        }
        return image
    }()

    init() {
        NSApplication.shared.applicationIconImage = Self.brandLogo
    }

    var body: some Scene {
        WindowGroup { ContentView() }
            .windowStyle(.hiddenTitleBar)
            .defaultSize(width: 1380, height: 880)
    }
}

enum WorkspaceTab: String, CaseIterable, Hashable {
    case overview = "Overview"
    case correlations = "Correlations"
    case timeline = "Timeline"
    case sources = "Evidence sources"
    case method = "How to read results"
    var symbol: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .correlations: "point.3.connected.trianglepath.dotted"
        case .timeline: "clock.arrow.circlepath"
        case .sources: "externaldrive"
        case .method: "text.book.closed"
        }
    }
}

let ink = Color(red: 0.10, green: 0.16, blue: 0.24)
let accent = Color(red: 0.10, green: 0.39, blue: 0.67)
let canvas = Color(red: 0.955, green: 0.97, blue: 0.985)
