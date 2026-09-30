import Foundation

public struct CandidateRejection: Codable, Sendable, Identifiable {
    public let observationID: String
    public let reason: String
    public let nearestMilliseconds: Double?
    public var id: String { observationID }
}

public struct CorrelationDiagnostics: Codable, Sendable {
    public let phonePackets: Int
    public let inboundInitiationSignatures: Int
    public let initiationPackets: Int
    public let noEndpointMatch: Int
    public let excludedInterfaceOnly: Int
    public let outsideWindow: Int
    public let matchedInitiations: Int
    public let rejections: [CandidateRejection]
    public let notes: [String]
}
