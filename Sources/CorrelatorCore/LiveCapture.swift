import Foundation

public struct CaptureDevice: Identifiable, Sendable {
    public let id: String
    public let name: String
    public let connection: String
    public let isConnected: Bool

    public init(id: String, name: String, connection: String, isConnected: Bool) {
        self.id = id
        self.name = name
        self.connection = connection
        self.isConnected = isConnected
    }
}

private struct DeviceList: Decodable {
    let result: Result
    struct Result: Decodable { let devices: [Device] }
    struct Device: Decodable {
        let hardwareProperties: Hardware
        let deviceProperties: Properties
        let connectionProperties: Connection
    }
    struct Hardware: Decodable {
        let udid: String
        let reality: Reality
        let deviceType: String
        let platform: String
    }
    enum Reality: String, Decodable { case physical, simulated }
    struct Properties: Decodable { let name: String }
    struct Connection: Decodable {
        let pairingState: String
        let tunnelState: String?
        let transportType: String?
    }
}

public func parseCaptureDevices(_ data: Data) throws -> [CaptureDevice] {
    let list: DeviceList
    do { list = try JSONDecoder().decode(DeviceList.self, from: data) }
    catch { throw AnalysisError.invalidInput("devicectl device list has an unexpected structure: \(error)") }
    return list.result.devices.filter { device in
        device.hardwareProperties.reality == .physical && device.hardwareProperties.deviceType == "iPhone" && device.hardwareProperties.platform == "iOS"
    }.map { device in
        let connection = device.connectionProperties
        let transport: String
        switch connection.transportType {
        case "wired": transport = "USB"
        case "localNetwork": transport = "Wi-Fi"
        case .some(let value): transport = value
        case nil: transport = "transport unknown"
        }
        return CaptureDevice(id: device.hardwareProperties.udid, name: device.deviceProperties.name,
                             connection: "\(connection.pairingState) · \(transport) · tunnel \(connection.tunnelState ?? "unknown")",
                             isConnected: connection.pairingState == "paired" && connection.tunnelState == "connected" && connection.transportType == "wired")
    }
}

public struct LiveCaptureStatus: Codable, Sendable {
    public let phase: String
    public let startedAt: Date
    public let updatedAt: Date
    public let rviInterface: String?
    public let rviStreamStartedAt: Date?
    public let pktapStreamStartedAt: Date?
    public let logStreamStartedAt: Date?
    public let rviPID: Int32?
    public let pktapPID: Int32?
    public let logPID: Int32?
    public let error: String?
    public let rviPackets: Int?
    public let rviDropped: Int?
    public let pktapPackets: Int?
    public let pktapDropped: Int?

    public init(phase: String, startedAt: Date, updatedAt: Date, rviInterface: String?, rviStreamStartedAt: Date?, pktapStreamStartedAt: Date?, logStreamStartedAt: Date?, rviPID: Int32?, pktapPID: Int32?, logPID: Int32?, error: String?, rviPackets: Int?, rviDropped: Int?, pktapPackets: Int?, pktapDropped: Int?) {
        self.phase = phase; self.startedAt = startedAt; self.updatedAt = updatedAt
        self.rviInterface = rviInterface; self.rviStreamStartedAt = rviStreamStartedAt
        self.pktapStreamStartedAt = pktapStreamStartedAt; self.logStreamStartedAt = logStreamStartedAt
        self.rviPID = rviPID; self.pktapPID = pktapPID; self.logPID = logPID
        self.error = error; self.rviPackets = rviPackets; self.rviDropped = rviDropped
        self.pktapPackets = pktapPackets; self.pktapDropped = pktapDropped
    }
}

public struct InterfaceCoverage: Identifiable, Codable, Sendable {
    public let id: String
    public let status: String
    public let detail: String
}

public func iphoneInterfaceCoverage(_ observations: [Observation]) -> [InterfaceCoverage] {
    let names = Set(observations.filter { $0.source == .iphone }.compactMap { $0.interface }.filter { !$0.hasPrefix("rvi") }).sorted()
    let observed = names.map { InterfaceCoverage(id: $0, status: "Directly observed", detail: "RVI packet metadata names this interface. This establishes visibility for these packets only.") }
    let special = [
        InterfaceCoverage(id: "Wi-Fi / cellular / Ethernet / tethering", status: "Unverified until observed", detail: "RVI can include traffic from active physical interfaces. A missing packet does not prove that an interface was inactive or fully covered."),
        InterfaceCoverage(id: "Loopback", status: "Unavailable or unverified", detail: "RVI does not establish complete visibility into internal loopback traffic. An on-device capture method is required to verify it."),
        InterfaceCoverage(id: "VPN / tunnel", status: "Partial or unverified", detail: "RVI may show the physical outer flow while inner utun traffic remains unavailable. Do not equate outer packets with full tunnel contents."),
        InterfaceCoverage(id: "Other device interfaces", status: "Unverified", detail: "iOS does not expose a supported, comprehensive interface inventory through this Mac-side capture session.")
    ]
    return observed + special
}

public struct CaptureCounters: Equatable, Sendable {
    public let captured: Int?
    public let dropped: Int?
}

public func parseTcpdumpCounters(_ stderr: String) -> CaptureCounters {
    let lines = stderr.replacingOccurrences(of: "tcpdump:", with: "").components(separatedBy: CharacterSet(charactersIn: ",\n"))
    func lastCount(_ suffix: String) -> Int? {
        lines.reversed().first { $0.trimmingCharacters(in: .whitespaces).hasSuffix(suffix) }
            .flatMap { Int($0.trimmingCharacters(in: .whitespaces).split(separator: " ").first ?? "") }
    }
    return CaptureCounters(captured: lastCount("packets captured"), dropped: lastCount("packets dropped by kernel"))
}
