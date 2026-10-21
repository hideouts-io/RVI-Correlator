import Foundation

/// A protected status write failed after the status was successfully encoded.
/// Periodic writes may report this failure without interrupting acquisition.
public struct CaptureStatusPersistenceError: LocalizedError {
    public let cause: Error

    public var errorDescription: String? {
        "Could not persist capture status: \(cause.localizedDescription)"
    }
}

public func persistCaptureStatus(_ status: LiveCaptureStatus, to directory: ProtectedCaptureDirectory) throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(status)
    do { try directory.write(data, name: "status.json") }
    catch { throw CaptureStatusPersistenceError(cause: error) }
}

/// Only a periodic status-write failure is recoverable. Snapshot, encoding,
/// acquisition, and terminal failures still propagate to the capture worker.
public func periodicCaptureStatusFailure(in directory: ProtectedCaptureDirectory, update: () throws -> Void) throws -> CaptureStatusPersistenceError? {
    do { try update(); return nil }
    catch let failure as CaptureStatusPersistenceError {
        try directory.validateProtection()
        return failure
    }
}
