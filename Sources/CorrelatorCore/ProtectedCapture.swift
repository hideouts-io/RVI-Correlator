import CapturePlatform
import CryptoKit
import Darwin
import Foundation

public struct CaptureRequester: Codable, Equatable, Sendable {
    public let pid: Int32
    public let uid: uid_t
    public let startedSeconds: UInt64
    public let startedMicroseconds: UInt64
}

public struct CaptureLaunchConfiguration: Codable, Sendable {
    public let workerSHA256: String
    public let iosLog: IOSLogConfiguration?
    public init(workerSHA256: String, iosLog: IOSLogConfiguration?) {
        self.workerSHA256 = workerSHA256; self.iosLog = iosLog
    }
}

/// Kernel process identity is a launch/lifetime consistency check, not IPC authentication.
public func captureRequester(_ pid: Int32) throws -> CaptureRequester {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    guard pid > 1, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
          info.pbi_pid == UInt32(pid), info.pbi_uid > 0, info.pbi_uid == info.pbi_ruid else {
        throw AnalysisError.invalidInput("Cannot establish the non-root capture app identity for PID \(pid). Restart the app and retry.")
    }
    return CaptureRequester(pid: pid, uid: info.pbi_uid, startedSeconds: info.pbi_start_tvsec,
                            startedMicroseconds: info.pbi_start_tvusec)
}

public func protectedCaptureURL(sessionID: String, requesterUID: uid_t) throws -> URL {
    guard sessionID.hasPrefix("session-"), sessionID.count <= 100,
          sessionID.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }), requesterUID > 0 else {
        throw AnalysisError.invalidInput("Invalid protected capture session identifier or requester UID.")
    }
    return URL(fileURLWithPath: "/Library/Application Support/RVI-Correlator/Captures", isDirectory: true)
        .appendingPathComponent(String(requesterUID), isDirectory: true).appendingPathComponent(sessionID, isDirectory: true)
}

private func captureIOError(_ operation: String) -> AnalysisError {
    .invalidInput("Protected capture \(operation) failed (errno \(errno)). Check the capture directory ownership and permissions; no user-writable output is used.")
}

/// Reject even inherited ACL mutation rights; POSIX mode alone does not exclude ACL writes.
func validateCaptureDirectory(_ descriptor: Int32, ownerUID: uid_t) throws {
    var info = stat()
    guard fstat(descriptor, &info) == 0 else { throw captureIOError("directory stat") }
    guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == ownerUID, info.st_mode & 0o022 == 0 else {
        throw AnalysisError.invalidInput("Protected capture ancestors must be directories owned by UID \(ownerUID), without group or other write permission.")
    }
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
        // Darwin reports ENOENT for an existing inode with no extended ACL.
        if errno == ENOENT { return }
        throw captureIOError("directory ACL read")
    }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    guard acl_valid(acl) == 0 else { throw captureIOError("directory ACL validation") }
    let mutations: [acl_perm_t] = [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
        ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
    var entry: acl_entry_t?
    var selector = Int32(ACL_FIRST_ENTRY.rawValue)
    while true {
        let result = acl_get_entry(acl, selector, &entry)
        if result == -1 && errno == EINVAL { break }
        guard result == 0, let entry else { throw captureIOError("directory ACL enumeration") }
        selector = Int32(ACL_NEXT_ENTRY.rawValue)
        var tag = ACL_UNDEFINED_TAG
        var permissions: acl_permset_t?
        guard acl_get_tag_type(entry, &tag) == 0, acl_get_permset(entry, &permissions) == 0, let permissions else {
            throw captureIOError("directory ACL permissions")
        }
        if tag == ACL_EXTENDED_ALLOW {
            for permission in mutations {
                let granted = acl_get_perm_np(permissions, permission)
                guard granted == 0 else {
                    if granted < 0 { throw captureIOError("directory ACL permission query") }
                    throw AnalysisError.invalidInput("Protected capture ancestor has an ACL granting mutation rights. Remove that unsafe grant before retrying.")
                }
            }
        }
    }
}

func setCaptureReadACL(_ descriptor: Int32, readerUID: uid_t) throws {
    var list: acl_t? = acl_init(1)
    guard list != nil else { throw captureIOError("ACL allocation") }
    defer { if let list { acl_free(UnsafeMutableRawPointer(list)) } }
    var entry: acl_entry_t?
    guard acl_create_entry(&list, &entry) == 0, let entry, let list else { throw captureIOError("ACL entry creation") }
    var identity = UUID().uuid
    let result = withUnsafeMutablePointer(to: &identity) { pointer in
        pointer.withMemoryRebound(to: UInt8.self, capacity: 16) { rvi_uid_to_uuid(readerUID, $0) }
    }
    guard result == 0, acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0, acl_set_qualifier(entry, &identity) == 0 else {
        throw captureIOError("reader ACL identity")
    }
    var permissions: acl_permset_t?
    guard acl_get_permset(entry, &permissions) == 0, let permissions, acl_clear_perms(permissions) == 0 else {
        throw captureIOError("reader ACL permission setup")
    }
    for permission: acl_perm_t in [ACL_LIST_DIRECTORY, ACL_SEARCH, ACL_READ_ATTRIBUTES, ACL_READ_EXTATTRIBUTES, ACL_READ_SECURITY] {
        guard acl_add_perm(permissions, permission) == 0 else { throw captureIOError("reader ACL permission grant") }
    }
    var flags: acl_flagset_t?
    guard acl_get_flagset_np(UnsafeMutableRawPointer(list), &flags) == 0, let flags, acl_add_flag_np(flags, ACL_FLAG_NO_INHERIT) == 0,
          acl_set_fd_np(descriptor, list, ACL_TYPE_EXTENDED) == 0 else { throw captureIOError("reader ACL installation") }
}

private func captureName(_ name: String) throws {
    guard !name.isEmpty, name != ".", name != "..", name.count <= 120,
          name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-_. ".contains($0)) }) else {
        throw AnalysisError.invalidInput("Protected capture output requires a single safe filename.")
    }
}

func openCaptureChild(_ parent: Int32, name: String, ownerUID: uid_t) throws -> FileHandle {
    try captureName(name)
    try validateCaptureDirectory(parent, ownerUID: ownerUID)
    let descriptor = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw captureIOError("open directory \(name)") }
    let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    do { try validateCaptureDirectory(descriptor, ownerUID: ownerUID) }
    catch { try handle.close(); throw error }
    return handle
}

private func createCaptureChild(_ parent: Int32, name: String, mode: mode_t) throws {
    try captureName(name)
    try validateCaptureDirectory(parent, ownerUID: 0)
    if mkdirat(parent, name, mode) != 0 && errno != EEXIST { throw captureIOError("create directory \(name)") }
}

func createCaptureSession(_ parent: Int32, sessionID: String, ownerUID: uid_t) throws -> FileHandle {
    try captureName(sessionID)
    try validateCaptureDirectory(parent, ownerUID: ownerUID)
    guard mkdirat(parent, sessionID, 0o700) == 0 else { throw captureIOError("new session directory") }
    return try openCaptureChild(parent, name: sessionID, ownerUID: ownerUID)
}

/// Owns the I/O boundary to a trusted directory. Files are created by descriptor,
/// never by caller-supplied paths; only the requester can traverse the session ACL.
public final class ProtectedCaptureDirectory {
    public let url: URL
    private let handle: FileHandle
    private let ownerUID: uid_t

    init(url: URL, handle: FileHandle, ownerUID: uid_t) {
        self.url = url; self.handle = handle; self.ownerUID = ownerUID
    }

    public func createFile(_ name: String) throws -> FileHandle {
        try captureName(name)
        try validateCaptureDirectory(handle.fileDescriptor, ownerUID: ownerUID)
        let descriptor = openat(handle.fileDescriptor, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o644)
        guard descriptor >= 0 else { throw captureIOError("exclusive file creation \(name)") }
        let output = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            var info = stat()
            guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == ownerUID, info.st_nlink == 1 else { throw captureIOError("new regular file validation \(name)") }
            guard fchmod(descriptor, 0o644) == 0, let acl = acl_init(0) else { throw captureIOError("file permissions \(name)") }
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            guard acl_set_fd_np(descriptor, acl, ACL_TYPE_EXTENDED) == 0 else { throw captureIOError("file ACL \(name)") }
        } catch { try output.close(); throw error }
        return output
    }

    public func write(_ data: Data, name: String) throws {
        try captureName(name)
        let temporary = "pending-\(UUID().uuidString)"
        let output = try createFile(temporary)
        do {
            try output.write(contentsOf: data)
            try output.close()
            guard renameat(handle.fileDescriptor, temporary, handle.fileDescriptor, name) == 0 else {
                throw captureIOError("atomic replacement \(name)")
            }
        } catch {
            let primary = error
            if unlinkat(handle.fileDescriptor, temporary, 0) != 0 {
                throw AnalysisError.invalidInput("\(primary.localizedDescription) Temporary capture cleanup failed (errno \(errno)).")
            }
            throw primary
        }
    }

    /// Bind the worker to bytes selected before authorization, then execute only
    /// the protected copy. A later bundle-path replacement cannot change it.
    public func installWorker(_ source: URL, expectedSHA256: String) throws -> URL {
        guard expectedSHA256.count == 64, expectedSHA256.allSatisfy({ $0.isASCII && $0.isHexDigit }) else {
            throw AnalysisError.invalidInput("Capture worker digest must be a SHA-256 hexadecimal value.")
        }
        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }
        let output = try createFile("capture-worker")
        defer { try? output.close() }
        var digest = SHA256()
        var bytes = 0
        while true {
            let chunk = try input.read(upToCount: 65_536) ?? Data()
            if chunk.isEmpty { break }
            guard chunk.count <= 64_000_000 - bytes else { throw AnalysisError.resourceLimit("Capture worker exceeds the 64 MB executable limit.") }
            bytes += chunk.count; digest.update(data: chunk)
            try output.write(contentsOf: chunk)
        }
        let actual = digest.finalize().map { String(format: "%02x", $0) }.joined()
        guard actual == expectedSHA256.lowercased() else {
            throw AnalysisError.evidenceChanged("Capture worker changed after preflight. No worker was launched; rebuild or re-select the app and retry.")
        }
        guard fchmod(output.fileDescriptor, 0o500) == 0 else { throw captureIOError("worker executable permissions") }
        return url.appendingPathComponent("capture-worker")
    }
}

public func createProtectedCaptureDirectory(sessionID: String, requesterUID: uid_t) throws -> ProtectedCaptureDirectory {
    let url = try protectedCaptureURL(sessionID: sessionID, requesterUID: requesterUID)
    guard geteuid() == 0 else { throw AnalysisError.invalidInput("Protected capture creation requires administrator authorization.") }
    let rootDescriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard rootDescriptor >= 0 else { throw captureIOError("open filesystem root") }
    var parent = FileHandle(fileDescriptor: rootDescriptor, closeOnDealloc: true)
    for name in ["Library", "Application Support"] {
        parent = try openCaptureChild(parent.fileDescriptor, name: name, ownerUID: 0)
    }
    for name in ["RVI-Correlator", "Captures"] {
        try createCaptureChild(parent.fileDescriptor, name: name, mode: 0o711)
        parent = try openCaptureChild(parent.fileDescriptor, name: name, ownerUID: 0)
        guard fchmod(parent.fileDescriptor, 0o711) == 0 else { throw captureIOError("shared capture traversal mode") }
    }
    let userDirectory = String(requesterUID)
    try createCaptureChild(parent.fileDescriptor, name: userDirectory, mode: 0o700)
    parent = try openCaptureChild(parent.fileDescriptor, name: userDirectory, ownerUID: 0)
    guard fchmod(parent.fileDescriptor, 0o700) == 0 else { throw captureIOError("requester directory mode") }
    try setCaptureReadACL(parent.fileDescriptor, readerUID: requesterUID)
    // A session is always new; an existing entry is never reused or truncated.
    let session = try createCaptureSession(parent.fileDescriptor, sessionID: sessionID, ownerUID: 0)
    try setCaptureReadACL(session.fileDescriptor, readerUID: requesterUID)
    return ProtectedCaptureDirectory(url: url, handle: session, ownerUID: 0)
}

/// The worker reopens only the canonical session prepared by the launcher.
public func openProtectedCaptureDirectory(sessionID: String, requesterUID: uid_t) throws -> ProtectedCaptureDirectory {
    let url = try protectedCaptureURL(sessionID: sessionID, requesterUID: requesterUID)
    guard geteuid() == 0 else { throw AnalysisError.invalidInput("Protected capture worker requires administrator authorization.") }
    let descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw captureIOError("open filesystem root") }
    var parent = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    for name in ["Library", "Application Support", "RVI-Correlator", "Captures", String(requesterUID), sessionID] {
        parent = try openCaptureChild(parent.fileDescriptor, name: name, ownerUID: 0)
    }
    return ProtectedCaptureDirectory(url: url, handle: parent, ownerUID: 0)
}

/// Runs only as the app user after collectors stop. Publication is retryable and
/// verifies each copy against its protected source before replacing the destination.
public func publishCaptureFiles(source: URL, destination: URL, names: [String]) throws {
    guard geteuid() != 0 else { throw AnalysisError.invalidInput("Capture publication must run as the app user, never root.") }
    for name in names {
        try captureName(name)
        let original = source.appendingPathComponent(name)
        let temporary = destination.appendingPathComponent(".capture-copy-\(UUID().uuidString)")
        let before = try fingerprint(original)
        do {
            try FileManager.default.copyItem(at: original, to: temporary)
            let copied = try fingerprint(temporary)
            let after = try fingerprint(original)
            guard before == after, copied == before else {
                throw AnalysisError.evidenceChanged("Capture changed while publishing \(name). Protected originals remain at \(source.path); retry finalization after a clean stop.")
            }
            guard rename(temporary.path, destination.appendingPathComponent(name).path) == 0 else {
                throw AnalysisError.invalidInput("Could not publish capture \(name) (errno \(errno)). Protected originals are preserved; check the destination and retry finalization.")
            }
        } catch {
            let primary = error
            if FileManager.default.fileExists(atPath: temporary.path) {
                do { try FileManager.default.removeItem(at: temporary) }
                catch { throw AnalysisError.invalidInput("\(primary.localizedDescription) Could not remove temporary publication file: \(error.localizedDescription)") }
            }
            throw primary
        }
    }
}
