import Darwin
import Foundation

/// Exact executable basenames verified on the capture host. These events are context,
/// not packet attribution; scoring still requires its own PID/name/endpoint evidence.
public let deviceLogProcesses: Set<String> = ["CoreDeviceService", "remoted", "usbmuxd", "AMPDeviceDiscoveryAgent"]

public let unifiedLogPredicate = "subsystem BEGINSWITH[c] \"com.apple.network\" OR process IN {\"networkd\", \"apsd\", \"mDNSResponder\", \"cloudd\", \"rapportd\", \"configd\", \"sharingd\", \"identityservicesd\", \"bird\", \"accountsd\", \"nsurlsessiond\", \"neagent\", \"CoreDeviceService\", \"remoted\", \"usbmuxd\", \"AMPDeviceDiscoveryAgent\"}"

public struct HostBootSample: Codable, Sendable {
    public let sampledAt: Date
    public let uptimeSeconds: Double
    public let bootSessionUUID: String
    public let method: String
}

/// Reads a host-level kernel boot-session identifier. It is never an event's bootUUID.
public func sampleHostBoot() throws -> HostBootSample {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size <= 128 else {
        throw AnalysisError.invalidInput("Cannot size kern.bootsessionuuid: errno \(errno). Host capture provenance could not be collected.")
    }
    var bytes = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else {
        throw AnalysisError.invalidInput("Cannot read kern.bootsessionuuid: errno \(errno). Host capture provenance could not be collected.")
    }
    let value = String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    guard let uuid = UUID(uuidString: value) else { throw AnalysisError.invalidInput("kern.bootsessionuuid returned a non-UUID value; cannot establish host provenance.") }
    return HostBootSample(sampledAt: Date(), uptimeSeconds: ProcessInfo.processInfo.systemUptime, bootSessionUUID: uuid.uuidString, method: "sysctlbyname(kern.bootsessionuuid)")
}

public struct CaptureContext: Codable, Sendable {
    public let schemaVersion: Int
    public let logPredicate: String
    public let logLevel: String
    public let start: HostBootSample
    public let end: HostBootSample?
    public let normalization: String

    public init(start: HostBootSample, end: HostBootSample?) {
        schemaVersion = 1; logPredicate = unifiedLogPredicate; logLevel = "default"
        self.start = start; self.end = end
        normalization = "Retain exact device-service process basenames as context, or packet PID plus bounded endpoint/hostname mention; preserve original line references. Context retention never proves a packet match."
    }

    public func validate() throws {
        guard schemaVersion == 1, !logPredicate.isEmpty, logLevel == "default",
              UUID(uuidString: start.bootSessionUUID) != nil, start.uptimeSeconds.isFinite, start.uptimeSeconds >= 0 else {
            throw AnalysisError.invalidInput("Capture context has unsupported schema, missing collection settings or invalid starting boot sample.")
        }
        if let end {
            guard UUID(uuidString: end.bootSessionUUID) != nil, end.uptimeSeconds.isFinite, end.uptimeSeconds >= 0,
                  end.sampledAt >= start.sampledAt else { throw AnalysisError.invalidInput("Capture context has invalid ending boot sample or reversed wall-clock interval.") }
        }
    }

    public var summary: String {
        guard let end else { return "Host boot identity sampled at capture start only; no completed interval. Log event bootUUID fields remain unchanged." }
        guard start.bootSessionUUID == end.bootSessionUUID, end.uptimeSeconds >= start.uptimeSeconds else {
            return "Host boot samples disagree or uptime regressed. Do not use this sidecar to scope log activity."
        }
        return "Start/end host samples agree on boot session \(start.bootSessionUUID). This is session-level context, not a directly logged bootUUID. It does not establish a process lifetime, event identity or clock alignment. Automatic activity grouping still requires original log bootUUID fields."
    }
}

public func captureContextData(_ context: CaptureContext) throws -> Data {
    try context.validate()
    let encoder = JSONEncoder(); encoder.dateEncodingStrategy = .iso8601; encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    return try encoder.encode(context)
}

public func writeCaptureContext(_ context: CaptureContext, to url: URL) throws {
    try captureContextData(context).write(to: url, options: .atomic)
}

public func readCaptureContext(_ url: URL) throws -> CaptureContext {
    let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
    let context = try decoder.decode(CaptureContext.self, from: Data(contentsOf: url))
    try context.validate()
    return context
}
