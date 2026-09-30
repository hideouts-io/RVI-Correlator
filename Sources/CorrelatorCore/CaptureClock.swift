import Foundation

/// Reads container timestamp resolution without decoding packet payloads. Resolution is not accuracy.
public func captureTimestampDescription(_ url: URL) throws -> String {
    let input = try FileHandle(forReadingFrom: url)
    defer { try? input.close() }
    func read(_ count: Int) throws -> Data {
        let bytes = try input.read(upToCount: count) ?? Data()
        guard bytes.count == count else { throw AnalysisError.invalidInput("Truncated capture header while reading timestamp resolution: \(url.path)") }
        return bytes
    }
    let magic = try read(4)
    if magic == Data([0xd4, 0xc3, 0xb2, 0xa1]) || magic == Data([0xa1, 0xb2, 0xc3, 0xd4]) {
        return "PCAP timestamps: microsecond storage resolution. Capture-writer clock origin and accuracy are not established by this file."
    }
    if magic == Data([0x4d, 0x3c, 0xb2, 0xa1]) || magic == Data([0xa1, 0xb2, 0x3c, 0x4d]) {
        return "PCAP timestamps: nanosecond storage resolution; analysis truncates to microseconds while retaining the original decoded timestamp. Clock accuracy is unverified."
    }
    guard magic == Data([0x0a, 0x0d, 0x0d, 0x0a]) else { throw AnalysisError.invalidInput("Unknown capture container for timestamp provenance: \(url.path)") }
    try input.seek(toOffset: 0)
    var little = true
    var descriptions = Set<String>()
    let size = try input.seekToEnd()
    try input.seek(toOffset: 0)
    while try input.offset() < size {
        let offset = try input.offset()
        let header = try read(12)
        if header.prefix(4) == magic {
            let order = Array(header[8..<12])
            guard order == [0x4d, 0x3c, 0x2b, 0x1a] || order == [0x1a, 0x2b, 0x3c, 0x4d] else { throw AnalysisError.invalidInput("Invalid PCAPNG byte-order magic: \(url.path)") }
            little = order[0] == 0x4d
        }
        func number(_ bytes: Data) -> UInt32 {
            let values = little ? Array(bytes.reversed()) : Array(bytes)
            return values.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        }
        let type = number(Data(header[0..<4])), length = number(Data(header[4..<8]))
        guard length >= 12, length % 4 == 0, offset + UInt64(length) <= size else { throw AnalysisError.invalidInput("Incomplete PCAPNG block while reading timestamp provenance: \(url.path)") }
        if type == 1 {
            guard length >= 20 else { throw AnalysisError.invalidInput("Short PCAPNG interface block: \(url.path)") }
            let rest = try read(Int(length) - 12)
            var position = 4
            var resolution = "10^-6 seconds (default microseconds)"
            while position + 4 <= rest.count - 4 {
                let code = number(Data(rest[position..<position + 2])), count = Int(number(Data(rest[position + 2..<position + 4])))
                guard position + 4 + count <= rest.count - 4 else { throw AnalysisError.invalidInput("Invalid PCAPNG interface option length: \(url.path)") }
                if code == 0 { break }
                if code == 9 {
                    guard count == 1 else { throw AnalysisError.invalidInput("Invalid PCAPNG timestamp resolution option: \(url.path)") }
                    let value = rest[position + 4]
                    resolution = "\(value & 128 == 0 ? 10 : 2)^-\(value & 127) seconds"
                }
                position += 4 + ((count + 3) / 4) * 4
            }
            descriptions.insert(resolution)
        }
        try input.seek(toOffset: offset + UInt64(length))
    }
    return "PCAPNG interface timestamp resolution: \(descriptions.sorted().joined(separator: ", ")). TShark applies container timestamp offsets. Analysis uses microseconds; raw timestamp fields and originals are retained. Capture-writer clock origin, synchronization and accuracy are unverified."
}
