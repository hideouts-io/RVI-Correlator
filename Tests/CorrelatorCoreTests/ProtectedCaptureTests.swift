import Darwin
import Foundation
import Testing
@testable import CorrelatorCore

private func protectedFixture() throws -> (URL, FileHandle) {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("protected-capture-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw AnalysisError.invalidInput("Could not open protected test directory: errno \(errno)") }
    return (url, FileHandle(fileDescriptor: descriptor, closeOnDealloc: true))
}

@Test func protectedCaptureRejectsSymlinksExistingFilesAndSessions() throws {
    let (root, handle) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let victim = root.appendingPathComponent("victim")
    try Data("unchanged".utf8).write(to: victim)
    let storage = ProtectedCaptureDirectory(url: root, handle: handle, ownerUID: geteuid())
    try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("helper.stderr"), withDestinationURL: victim)
    #expect(throws: AnalysisError.self) { try storage.createFile("helper.stderr") }
    #expect(throws: AnalysisError.self) { try storage.createFile("../victim") }
    #expect(try String(contentsOf: victim, encoding: .utf8) == "unchanged")
    try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("linked"), withDestinationURL: root)
    #expect(throws: AnalysisError.self) { try openCaptureChild(handle.fileDescriptor, name: "linked", ownerUID: geteuid()) }
    let session = try createCaptureSession(handle.fileDescriptor, sessionID: "session-test", ownerUID: geteuid())
    try session.close()
    #expect(throws: AnalysisError.self) { try createCaptureSession(handle.fileDescriptor, sessionID: "session-test", ownerUID: geteuid()) }
    let output = try storage.createFile("capture.pcapng")
    #expect(fcntl(output.fileDescriptor, F_GETFD) & FD_CLOEXEC != 0)
    try output.write(contentsOf: Data("capture".utf8)); try output.close()
    #expect(throws: AnalysisError.self) { try storage.createFile("capture.pcapng") }
    // Atomic metadata replaces the link itself, without opening its target.
    try storage.write(Data("status".utf8), name: "helper.stderr")
    #expect(try String(contentsOf: victim, encoding: .utf8) == "unchanged")
}

@Test func protectedCaptureRejectsWritableModesAndACLs() throws {
    let (root, handle) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    try validateCaptureDirectory(handle.fileDescriptor, ownerUID: geteuid())
    #expect(fchmod(handle.fileDescriptor, 0o720) == 0)
    #expect(throws: AnalysisError.self) { try validateCaptureDirectory(handle.fileDescriptor, ownerUID: geteuid()) }
    #expect(fchmod(handle.fileDescriptor, 0o700) == 0)
    try setCaptureReadACL(handle.fileDescriptor, readerUID: geteuid())
    try validateCaptureDirectory(handle.fileDescriptor, ownerUID: geteuid())
    let evidence = root.appendingPathComponent("evidence")
    try Data("readable".utf8).write(to: evidence)
    #expect(fchmod(handle.fileDescriptor, 0) == 0)
    #expect(try FileManager.default.contentsOfDirectory(atPath: root.path) == ["evidence"])
    #expect(try String(contentsOf: evidence, encoding: .utf8) == "readable")
    #expect(throws: Error.self) { try Data().write(to: root.appendingPathComponent("unprivileged-write")) }
    #expect(fchmod(handle.fileDescriptor, 0o700) == 0)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", "user:\(NSUserName()) allow writesecurity", root.path]
    try process.run(); process.waitUntilExit()
    #expect(process.terminationStatus == 0)
    #expect(throws: AnalysisError.self) { try validateCaptureDirectory(handle.fileDescriptor, ownerUID: geteuid()) }
}

@Test func protectedCaptureUsesOpenedDirectoryAfterPathReplacement() throws {
    let (root, handle) = try protectedFixture()
    let moved = root.appendingPathExtension("original")
    defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(at: moved) }
    let storage = ProtectedCaptureDirectory(url: root, handle: handle, ownerUID: geteuid())
    try FileManager.default.moveItem(at: root, to: moved)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    try storage.write(Data("trusted".utf8), name: "status.json")
    #expect(!FileManager.default.fileExists(atPath: root.appendingPathComponent("status.json").path))
    #expect(try String(contentsOf: moved.appendingPathComponent("status.json"), encoding: .utf8) == "trusted")
}

@Test func stoppedCapturePublicationCanRetryAndPreservesOriginals() throws {
    let (source, _) = try protectedFixture()
    let (destination, _) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: source); try? FileManager.default.removeItem(at: destination) }
    try Data("original".utf8).write(to: source.appendingPathComponent("capture.pcapng"))
    #expect(throws: Error.self) {
        try publishCaptureFiles(source: source, destination: destination, names: ["capture.pcapng", "status.json"])
    }
    try Data("stopped".utf8).write(to: source.appendingPathComponent("status.json"))
    try publishCaptureFiles(source: source, destination: destination, names: ["capture.pcapng", "status.json"])
    #expect(try Data(contentsOf: source.appendingPathComponent("capture.pcapng")) == Data(contentsOf: destination.appendingPathComponent("capture.pcapng")))
    #expect(try String(contentsOf: destination.appendingPathComponent("status.json"), encoding: .utf8) == "stopped")
    #expect(try FileManager.default.contentsOfDirectory(atPath: destination.path).count == 2)
    let requester = try captureRequester(getpid())
    #expect(requester.uid == geteuid())
    #expect(throws: AnalysisError.self) { try captureRequester(1) }
}

@Test func tcpdumpWritesApplePCAPNGThroughProtectedDescriptor() throws {
    let (root, handle) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let storage = ProtectedCaptureDirectory(url: root, handle: handle, ownerUID: geteuid())
    let output = try storage.createFile("capture.pcapng")
    let fixture = try #require(Bundle.module.url(forResource: "mac-apple", withExtension: "pcapng", subdirectory: "Fixtures"))
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
    process.arguments = ["-n", "-r", fixture.path, "-P", "--apple-pcapng", "-w", "-"]
    process.standardOutput = output
    let errors = Pipe(); process.standardError = errors
    try process.run(); process.waitUntilExit(); try output.close()
    let diagnostic = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    #expect(process.terminationStatus == 0, Comment(rawValue: diagnostic))
    let imported = try importCapture(root.appendingPathComponent("capture.pcapng"), source: .mac, offsetMicroseconds: 0)
    #expect(imported.observations.count == 1)
    #expect(imported.artifact.warnings.contains { $0.contains("PCAPNG") })
}

@Test func protectedWorkerIsBoundToPreflightBytes() throws {
    let (root, handle) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: root) }
    let source = root.appendingPathComponent("source")
    try Data("selected worker".utf8).write(to: source)
    let hash = try fingerprint(source).0
    let storage = ProtectedCaptureDirectory(url: root, handle: handle, ownerUID: geteuid())
    let installed = try storage.installWorker(source, expectedSHA256: hash)
    try Data("replacement".utf8).write(to: source)
    #expect(try String(contentsOf: installed, encoding: .utf8) == "selected worker")
    let (other, otherHandle) = try protectedFixture()
    defer { try? FileManager.default.removeItem(at: other) }
    #expect(throws: AnalysisError.self) {
        try ProtectedCaptureDirectory(url: other, handle: otherHandle, ownerUID: geteuid()).installWorker(source, expectedSHA256: hash)
    }
}
