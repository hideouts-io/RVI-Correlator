import Foundation

/// One parser per import/normalization pass; accepted OS and ISO forms share range checks.
struct UnifiedLogTimestampParser {
    private let apple: DateFormatter
    private let iso: ISO8601DateFormatter

    init() {
        let apple = DateFormatter()
        apple.locale = Locale(identifier: "en_US_POSIX")
        apple.dateFormat = "yyyy-MM-dd HH:mm:ssZ"
        apple.isLenient = false
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        self.apple = apple; self.iso = iso
    }

    func microseconds(_ stamp: String) throws -> Int64 {
        guard stamp.utf8.count <= 128 else { throw AnalysisError.invalidInput("Unified Log timestamp exceeds 128 bytes.") }
        let base: String
        let fraction: Int64
        if let dot = stamp.firstIndex(of: ".") {
            let remainder = stamp[stamp.index(after: dot)...]
            let digits = String(remainder.prefix(while: { $0.isASCII && $0.isNumber }))
            guard !digits.isEmpty, digits.count <= 9,
                  let micros = Int64(String(digits.prefix(6)).padding(toLength: 6, withPad: "0", startingAt: 0)) else {
                throw AnalysisError.invalidInput("Unified Log timestamp has an invalid fractional second.")
            }
            base = String(stamp[..<dot]) + remainder.dropFirst(digits.count)
            fraction = micros
        } else { base = stamp; fraction = 0 }
        guard let date = apple.date(from: base) ?? iso.date(from: base) else {
            throw AnalysisError.invalidInput("Unified Log timestamp is not a supported OS/ISO timestamp.")
        }
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= Double(Int64.min), seconds < Double(Int64.max) else {
            throw AnalysisError.invalidInput("Unified Log timestamp is outside the supported range.")
        }
        let (whole, overflow) = Int64(seconds).multipliedReportingOverflow(by: 1_000_000)
        let (epoch, fractionOverflow) = whole.addingReportingOverflow(fraction)
        guard !overflow, !fractionOverflow else { throw AnalysisError.invalidInput("Unified Log timestamp overflows microsecond precision.") }
        return epoch
    }
}
