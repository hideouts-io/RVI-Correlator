import AppKit
import Foundation

// Resample the approved logo for macOS packaging without changing its artwork or alpha.
guard CommandLine.arguments.count == 3 else {
    fatalError("Usage: swift generate-icon.swift <source-logo.png> <output-1024.png>")
}
let sourceURL = URL(fileURLWithPath: CommandLine.arguments[1])
let outputURL = URL(fileURLWithPath: CommandLine.arguments[2])
guard let source = NSImage(contentsOf: sourceURL), source.size.width == source.size.height else {
    fatalError("Cannot load square source logo at \(sourceURL.path)")
}
let size = 1024
guard let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
                                    bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                    isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0,
                                    bitsPerPixel: 0), let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
    fatalError("Could not create app icon bitmap")
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.imageInterpolation = .high
source.draw(in: NSRect(x: 0, y: 0, width: size, height: size), from: .zero, operation: .copy, fraction: 1)
context.flushGraphics()
NSGraphicsContext.restoreGraphicsState()
guard let data = bitmap.representation(using: .png, properties: [:]) else { fatalError("Could not encode app icon") }
try data.write(to: outputURL, options: .atomic)
