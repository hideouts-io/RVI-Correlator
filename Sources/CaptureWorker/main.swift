import CorrelatorCore
import CryptoKit
import Darwin
import Foundation

enum CaptureFailure: LocalizedError {
    case setup(String)
    case command(String)
    case process(String)
    var errorDescription: String? {
        switch self { case .setup(let message), .command(let message), .process(let message): return message }
    }
}

func command(_ executable: String, _ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    process.waitUntilExit()
    let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    guard process.terminationStatus == 0 else {
        throw CaptureFailure.command("\(executable) \(arguments.first ?? "") failed (exit \(process.terminationStatus)): \(text.prefix(2_000))")
    }
    return text
}

func rviInterfaces() throws -> Set<String> {
    Set(try command("/sbin/ifconfig", ["-l"]).split(whereSeparator: \.isWhitespace).map(String.init).filter {
        $0.count > 3 && $0.hasPrefix("rvi") && $0.dropFirst(3).allSatisfy(\.isNumber)
    })
}

func writeStatus(_ status: LiveCaptureStatus, to directory: ProtectedCaptureDirectory) throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    try directory.write(encoder.encode(status), name: "status.json")
}

func startProcess(_ executable: String, _ arguments: [String], directory: ProtectedCaptureDirectory, output: String, error: String) throws -> Process {
    let stdout = try directory.createFile(output)
    let stderr = try directory.createFile(error)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = stdout
    process.standardError = stderr
    do { try process.run() }
    catch {
        try stdout.close()
        try stderr.close()
        throw CaptureFailure.process("Could not start \(executable) with \(arguments.first ?? "no arguments"): \(error)")
    }
    try stdout.close()
    try stderr.close()
    return process
}

func stopProcess(_ process: Process) throws {
    guard process.isRunning else { return }
    kill(process.processIdentifier, SIGINT)
    let deadline = Date().addingTimeInterval(15)
    while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
    guard !process.isRunning else {
        kill(process.processIdentifier, SIGTERM)
        throw CaptureFailure.process("Capture process \(process.processIdentifier) did not stop within 15 seconds after SIGINT; sent SIGTERM. Inspect the session diagnostics.")
    }
}

/// sudo may ignore SIGINT sent from its parent's process group. SIGTERM is
/// forwarded to the unprivileged logger. Output is unbuffered; final import
/// must still verify that the last NDJSON record is complete before hashing.
func stopIOSLog(_ process: Process) throws {
    guard process.isRunning else { return }
    process.terminate()
    let deadline = Date().addingTimeInterval(15)
    while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
    guard !process.isRunning else {
        throw CaptureFailure.process("iPhone log collector \(process.processIdentifier) did not exit after SIGTERM within 15 seconds. Session finalization is incomplete; inspect ios-log.stderr.")
    }
}

func counters(_ url: URL) throws -> CaptureCounters {
    let text = try String(contentsOf: url, encoding: .utf8)
    return parseTcpdumpCounters(text)
}

func runCapture(device: String, storage: ProtectedCaptureDirectory, controlDirectory: URL, requester: CaptureRequester, iosConfig: IOSLogConfiguration?) throws {
    guard geteuid() == 0 else { throw CaptureFailure.setup("Live capture helper must be launched through macOS administrator authorization.") }
    guard !device.isEmpty, device.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else {
        throw CaptureFailure.setup("Invalid device identifier supplied to capture helper.")
    }
    let directory = storage.url
    let rvictl = ["/Library/Apple/usr/bin/rvictl", "/usr/bin/rvictl"].first { FileManager.default.isExecutableFile(atPath: $0) }
    guard let rvictl else {
        throw CaptureFailure.setup("Apple rvictl is missing. Install Xcode device support and confirm /Library/Apple/usr/bin/rvictl exists before starting a live RVI session.")
    }
    let started = Date()
    let bootStart = try sampleHostBoot()
    try storage.write(captureContextData(CaptureContext(start: bootStart, end: nil)), name: "capture-context.json")
    var phoneStartedAt: Date?
    var macStartedAt: Date?
    var logStartedAt: Date?
    var iosLogStartedAt: Date?
    try iosConfig?.validate()
    func status(_ phase: String, _ interface: String?, _ processes: [Process], _ error: String?) throws {
        let phone = try counters(directory.appendingPathComponent("iphone-tcpdump.stderr"))
        let mac = try counters(directory.appendingPathComponent("mac-tcpdump.stderr"))
        try writeStatus(LiveCaptureStatus(phase: phase, startedAt: started, updatedAt: Date(), rviInterface: interface,
                                          rviStreamStartedAt: phoneStartedAt, pktapStreamStartedAt: macStartedAt,
                                          logStreamStartedAt: logStartedAt,
                                          rviPID: processes.first?.processIdentifier, pktapPID: processes.dropFirst().first?.processIdentifier,
                                          logPID: processes.dropFirst(2).first?.processIdentifier,
                                          iosLogPID: processes.dropFirst(3).first?.processIdentifier, iosLogStreamStartedAt: iosLogStartedAt,
                                          iosLogBytes: iosConfig == nil ? nil : try (FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("ios-log.ndjson").path)[.size] as? NSNumber)?.uint64Value,
                                          error: error,
                                          rviPackets: phone.captured, rviDropped: phone.dropped,
                                          pktapPackets: mac.captured, pktapDropped: mac.dropped), to: storage)
    }
    let before = try rviInterfaces()
    let rvictlOutput = try command(rvictl, ["-s", device])
    var rviNeedsTeardown = true
    defer {
        if rviNeedsTeardown {
            do { _ = try command(rvictl, ["-x", device]) }
            catch {
                let message = "RVI teardown failed: \(error.localizedDescription)"
                do { try storage.write(Data(message.utf8), name: "teardown.error") }
                catch { fputs("\(message); could not write teardown.error: \(error)\n", stderr) }
            }
        }
    }
    var created: Set<String> = []
    let interfaceDeadline = Date().addingTimeInterval(15)
    repeat {
        created = try rviInterfaces().subtracting(before)
        if created.count == 1 { break }
        Thread.sleep(forTimeInterval: 0.25)
    } while Date() < interfaceDeadline
    guard created.count == 1, let interface = created.first else {
        throw CaptureFailure.setup("rvictl started but did not create one identifiable RVI interface within 15 seconds. Before: \(before.sorted()); new: \(created.sorted()); output: \(rvictlOutput.prefix(1_000))")
    }
    let interfaces = try command("/usr/sbin/tcpdump", ["-D"])
    let listed = interfaces.components(separatedBy: .newlines).compactMap { line -> String? in
        guard let dot = line.firstIndex(of: "."), Int(line[..<dot]) != nil else { return nil }
        return String(line[line.index(after: dot)...].prefix(while: { !$0.isWhitespace }))
    }
    guard listed.contains(interface) else {
        throw CaptureFailure.setup("RVI interface \(interface) is not listed by tcpdump -D after rvictl start.")
    }
    var processes: [Process] = []
    do {
        let phone = try startProcess("/usr/sbin/tcpdump", ["-i", interface, "-s", "0", "-U", "-n", "-P", "--apple-pcapng", "-w", "-"],
                                     directory: storage, output: "iphone-rvi.pcapng", error: "iphone-tcpdump.stderr")
        phoneStartedAt = Date()
        processes.append(phone)
        let mac = try startProcess("/usr/sbin/tcpdump", ["-i", "pktap", "-s", "0", "-U", "-n", "-P", "--apple-pcapng", "-w", "-"],
                                   directory: storage, output: "mac-pktap.pcapng", error: "mac-tcpdump.stderr")
        macStartedAt = Date()
        processes.append(mac)

        let log = try startProcess("/usr/bin/log", ["stream", "--style", "ndjson", "--level", "default", "--predicate", unifiedLogPredicate],
                                   directory: storage, output: "unified-log.raw", error: "unified-log.stderr")
        logStartedAt = Date()
        processes.append(log)
        if let iosConfig {
            guard let account = getpwuid(requester.uid) else {
                throw CaptureFailure.setup("iPhone log collector requires a non-root session owner; it must not run with capture-helper privileges.")
            }
            let hash = SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: iosConfig.executable))).map { String(format: "%02x", $0) }.joined()
            guard hash == iosConfig.executableSHA256 else { throw CaptureFailure.setup("iPhone log collector executable changed after preflight. Re-select the collector and start a new session.") }
            let iosLog = try startProcess("/usr/bin/sudo", ["-n", "-H", "-u", "#\(requester.uid)", "--", "/usr/bin/env", "-i",
                "HOME=\(String(cString: account.pointee.pw_dir))", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TZ=UTC", "PYTHONUNBUFFERED=1",
                iosConfig.executable, "syslog", "live", "--udid", device, "--no-mobdev2", "--usbmux", "/var/run/usbmuxd",
                "--pid", String(iosConfig.processID), "--format", "json", "--no-debug", "--no-info"],
                directory: storage, output: "ios-log.ndjson", error: "ios-log.stderr")
            iosLogStartedAt = Date()
            processes.append(iosLog)
        }
        Thread.sleep(forTimeInterval: 1)
        guard processes.allSatisfy(\.isRunning) else {
            throw CaptureFailure.process("A requested capture stream exited during startup. Inspect tcpdump, Unified Log, and optional ios-log.stderr in \(directory.path).")
        }
        try status("running", interface, processes, nil)
        var nextCounters = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: controlDirectory.appendingPathComponent("stop.request").path) {
            guard try captureRequester(requester.pid) == requester else {
                throw CaptureFailure.process("The app process identity changed before Stop. Capture streams were interrupted to prevent an orphaned session.")
            }
            if Date().timeIntervalSince(started) > 1_800 {
                throw CaptureFailure.process("The 30-minute live-session safety limit was reached. Capture streams were interrupted; start a new session if needed.")
            }
            let logSize = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("unified-log.raw").path)[.size] as? NSNumber
            if let logSize, logSize.int64Value > 1_000_000_000 {
                throw CaptureFailure.process("Unified Log raw stream exceeded 1 GB. Capture streams were interrupted to protect disk space; review the saved session.")
            }
            if iosConfig != nil {
                let size = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("ios-log.ndjson").path)[.size] as? NSNumber
                if let size, size.int64Value > 60_000_000 { throw CaptureFailure.process("iPhone log reached the 60 MB live limit. Streams were stopped; preserve the session and start a shorter capture.") }
            }
            guard processes.allSatisfy(\.isRunning) else {
                throw CaptureFailure.process("A capture stream exited unexpectedly. Inspect the session stderr files in \(directory.path).")
            }
            if Date() >= nextCounters {
                kill(phone.processIdentifier, SIGINFO)
                kill(mac.processIdentifier, SIGINFO)
                nextCounters = Date().addingTimeInterval(5)
            }
            try status("running", interface, processes, nil)
            Thread.sleep(forTimeInterval: 1)
        }
        try status("stopping", interface, processes, nil)
        for process in processes.prefix(3) { try stopProcess(process) }
        if let iosLog = processes.dropFirst(3).first { try stopIOSLog(iosLog) }
        try storage.write(captureContextData(CaptureContext(start: bootStart, end: try sampleHostBoot())), name: "capture-context.json")
        _ = try command(rvictl, ["-x", device])
        rviNeedsTeardown = false
        try status("stopped", interface, processes, nil)
    } catch {
        var message = error.localizedDescription
        for (index, process) in processes.enumerated() {
            do {
                if index == 3 { try stopIOSLog(process) }
                else { try stopProcess(process) }
            }
            catch { message += " Cleanup of process \(process.processIdentifier) failed: \(error.localizedDescription)" }
        }
        do { try status("failed", interface, processes, message) }
        catch { message += " Could not write failed status: \(error.localizedDescription)" }
        throw CaptureFailure.process(message)
    }
}

let arguments = CommandLine.arguments
guard arguments.count == 6 else {
    fputs("Usage: RVICaptureHelper <device-udid> <session-id> <app-control-directory> <base64-requester> <base64-optional-ios-log-configuration>\n", stderr)
    exit(64)
}
var storage: ProtectedCaptureDirectory?
do {
    guard geteuid() == 0, let identity = Data(base64Encoded: arguments[4]), let data = Data(base64Encoded: arguments[5]) else {
        throw CaptureFailure.setup("Administrator authorization and valid encoded capture configuration are required.")
    }
    let requester = try JSONDecoder().decode(CaptureRequester.self, from: identity)
    guard try captureRequester(requester.pid) == requester else { throw CaptureFailure.setup("Capture app identity changed during authorization. Restart capture.") }
    let iosConfig = try JSONDecoder().decode(IOSLogConfiguration?.self, from: data)
    try iosConfig?.validate()
    let protected = try openProtectedCaptureDirectory(sessionID: arguments[2], requesterUID: requester.uid)
    storage = protected
    try runCapture(device: arguments[1], storage: protected, controlDirectory: URL(fileURLWithPath: arguments[3], isDirectory: true), requester: requester, iosConfig: iosConfig)
} catch {
    if let storage {
        do { try storage.write(Data(error.localizedDescription.utf8), name: "helper.error") }
        catch { fputs("Could not save protected helper error: \(error.localizedDescription)\n", stderr) }
    }
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}
