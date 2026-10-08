import Darwin
import Foundation

struct ProcessOutputLimits {
    let stdoutBytes: Int
    let stderrBytes: Int
    let seconds: TimeInterval
}

private func stopOwnedProcess(_ process: Process) throws {
    if process.isRunning { process.terminate() }
    let grace = ProcessInfo.processInfo.systemUptime + 0.5
    while process.isRunning && ProcessInfo.processInfo.systemUptime < grace { Thread.sleep(forTimeInterval: 0.01) }
    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.01) }
    guard !process.isRunning else { throw AnalysisError.resourceLimit("Decoder did not exit after SIGKILL within two seconds.") }
}

/// Drains both streams without scratch files; quotas apply through EOF even after child exit.
/// Only the Process created here is signalled. Monotonic deadlines also bound inherited pipes.
func runBoundedProcess(_ executable: URL, arguments: [String], limits: ProcessOutputLimits) throws -> (Data, Data) {
    guard limits.stdoutBytes >= 0, limits.stderrBytes >= 0, limits.seconds.isFinite, limits.seconds > 0 else {
        throw AnalysisError.invalidInput("Decoder output limits and deadline must be nonnegative and finite.")
    }
    let output = Pipe(), errors = Pipe()
    defer { try? output.fileHandleForReading.close(); try? errors.fileHandleForReading.close() }
    for handle in [output.fileHandleForReading, errors.fileHandleForReading] {
        let flags = fcntl(handle.fileDescriptor, F_GETFL)
        guard flags >= 0, fcntl(handle.fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw AnalysisError.decoderFailed("Cannot configure decoder pipe (errno \(errno)).")
        }
    }
    let process = Process()
    process.executableURL = executable; process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output; process.standardError = errors
    try process.run()
    do {
        try output.fileHandleForWriting.close(); try errors.fileHandleForWriting.close()
        var buffers = [Data(), Data()]
        let quotas = [limits.stdoutBytes, limits.stderrBytes]
        var pipes = [pollfd(fd: output.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0),
                     pollfd(fd: errors.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)]
        let deadline = ProcessInfo.processInfo.systemUptime + limits.seconds
        var chunk = [UInt8](repeating: 0, count: 65_536)
        while pipes.contains(where: { $0.fd >= 0 }) || process.isRunning {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw AnalysisError.resourceLimit("Decoder exceeded its \(limits.seconds)-second deadline. Narrow the capture and retry.")
            }
            let ready = poll(&pipes, nfds_t(pipes.count), 20)
            guard ready >= 0 || errno == EINTR else { throw AnalysisError.decoderFailed("Decoder pipe poll failed (errno \(errno)).") }
            for index in pipes.indices where pipes[index].fd >= 0 {
                while true {
                    let count = read(pipes[index].fd, &chunk, chunk.count)
                    if count == 0 { pipes[index].fd = -1; break }
                    if count < 0 {
                        if errno == EINTR { continue }
                        if errno == EAGAIN { break }
                        throw AnalysisError.decoderFailed("Decoder pipe read failed (errno \(errno)).")
                    }
                    guard count <= quotas[index] - buffers[index].count else {
                        throw AnalysisError.resourceLimit("Decoder \(index == 0 ? "stdout" : "stderr") exceeds \(quotas[index]) bytes. Narrow the capture and retry.")
                    }
                    buffers[index].append(contentsOf: chunk.prefix(count))
                    guard ProcessInfo.processInfo.systemUptime < deadline else {
                        throw AnalysisError.resourceLimit("Decoder exceeded its output-drain deadline.")
                    }
                }
            }
        }
        guard process.terminationStatus == 0 else {
            throw AnalysisError.decoderFailed("Decoder exited with status \(process.terminationStatus): \(String(decoding: buffers[1].prefix(4_000), as: UTF8.self))")
        }
        return (buffers[0], buffers[1])
    } catch {
        let primary = error
        do { try stopOwnedProcess(process) }
        catch { throw AnalysisError.resourceLimit("\(primary.localizedDescription) Cleanup failed: \(error.localizedDescription)") }
        throw primary
    }
}
