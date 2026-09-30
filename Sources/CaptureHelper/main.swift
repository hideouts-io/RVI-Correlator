import CorrelatorCore
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

func writeStatus(_ status: LiveCaptureStatus, to directory: URL) throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let url = directory.appendingPathComponent("status.json")
    do { try encoder.encode(status).write(to: url, options: .atomic) }
    catch {
        let detail = error as NSError
        throw CaptureFailure.process("Cannot write capture status at \(url.path): \(detail.domain) code \(detail.code), \(detail.userInfo).")
    }
}

func startProcess(_ executable: String, _ arguments: [String], output: URL, error: URL) throws -> Process {
    FileManager.default.createFile(atPath: output.path, contents: nil)
    FileManager.default.createFile(atPath: error.path, contents: nil)
    let stdout = try FileHandle(forWritingTo: output)
    let stderr = try FileHandle(forWritingTo: error)
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

func counters(_ url: URL) throws -> CaptureCounters {
    let text = try String(contentsOf: url, encoding: .utf8)
    return parseTcpdumpCounters(text)
}

func runCapture(device: String, directory: URL, appPID: Int32) throws {
    guard geteuid() == 0 else { throw CaptureFailure.setup("Live capture helper must be launched through macOS administrator authorization.") }
    guard !device.isEmpty, device.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else {
        throw CaptureFailure.setup("Invalid device identifier supplied to capture helper.")
    }
    var isDirectory: ObjCBool = false
    guard FileManager.default.fileExists(atPath: directory.path, isDirectory: &isDirectory), isDirectory.boolValue else {
        throw CaptureFailure.setup("Session directory does not exist: \(directory.path)")
    }
    let rvictl = ["/Library/Apple/usr/bin/rvictl", "/usr/bin/rvictl"].first { FileManager.default.isExecutableFile(atPath: $0) }
    guard let rvictl else {
        throw CaptureFailure.setup("Apple rvictl is missing. Install Xcode device support and confirm /Library/Apple/usr/bin/rvictl exists before starting a live RVI session.")
    }
    let started = Date()
    let bootStart = try sampleHostBoot()
    let contextURL = directory.appendingPathComponent("capture-context.json")
    try writeCaptureContext(CaptureContext(start: bootStart, end: nil), to: contextURL)
    var phoneStartedAt: Date?
    var macStartedAt: Date?
    var logStartedAt: Date?
    func status(_ phase: String, _ interface: String?, _ processes: [Process], _ error: String?) throws {
        let phone = try counters(directory.appendingPathComponent("iphone-tcpdump.stderr"))
        let mac = try counters(directory.appendingPathComponent("mac-tcpdump.stderr"))
        try writeStatus(LiveCaptureStatus(phase: phase, startedAt: started, updatedAt: Date(), rviInterface: interface,
                                          rviStreamStartedAt: phoneStartedAt, pktapStreamStartedAt: macStartedAt,
                                          logStreamStartedAt: logStartedAt,
                                          rviPID: processes.first?.processIdentifier, pktapPID: processes.dropFirst().first?.processIdentifier,
                                          logPID: processes.dropFirst(2).first?.processIdentifier, error: error,
                                          rviPackets: phone.captured, rviDropped: phone.dropped,
                                          pktapPackets: mac.captured, pktapDropped: mac.dropped), to: directory)
    }
    let before = try rviInterfaces()
    let rvictlOutput = try command(rvictl, ["-s", device])
    var rviNeedsTeardown = true
    defer {
        if rviNeedsTeardown {
            do { _ = try command(rvictl, ["-x", device]) }
            catch {
                let message = "RVI teardown failed: \(error.localizedDescription)"
                do { try message.write(to: directory.appendingPathComponent("teardown.error"), atomically: true, encoding: .utf8) }
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
        let phone = try startProcess("/usr/sbin/tcpdump", ["-i", interface, "-s", "0", "-U", "-n", "-P", "--apple-pcapng", "-w", directory.appendingPathComponent("iphone-rvi.pcapng").path],
                                     output: directory.appendingPathComponent("iphone-tcpdump.stdout"), error: directory.appendingPathComponent("iphone-tcpdump.stderr"))
        phoneStartedAt = Date()
        processes.append(phone)
        let mac = try startProcess("/usr/sbin/tcpdump", ["-i", "pktap", "-s", "0", "-U", "-n", "-P", "--apple-pcapng", "-w", directory.appendingPathComponent("mac-pktap.pcapng").path],
                                   output: directory.appendingPathComponent("mac-tcpdump.stdout"), error: directory.appendingPathComponent("mac-tcpdump.stderr"))
        macStartedAt = Date()
        processes.append(mac)

        let log = try startProcess("/usr/bin/log", ["stream", "--style", "ndjson", "--level", "default", "--predicate", unifiedLogPredicate],
                                   output: directory.appendingPathComponent("unified-log.raw"), error: directory.appendingPathComponent("unified-log.stderr"))
        logStartedAt = Date()
        processes.append(log)
        Thread.sleep(forTimeInterval: 1)
        guard processes.allSatisfy(\.isRunning) else {
            throw CaptureFailure.process("At least one of RVI tcpdump, PKTAP tcpdump, or Unified Log stream exited during startup. Inspect the three stderr files in \(directory.path).")
        }
        try status("running", interface, processes, nil)
        var nextCounters = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: directory.appendingPathComponent("stop.request").path) {
            if kill(appPID, 0) != 0 {
                throw CaptureFailure.process("The app process exited before Stop. Capture streams were interrupted to prevent an orphaned session.")
            }
            if Date().timeIntervalSince(started) > 1_800 {
                throw CaptureFailure.process("The 30-minute live-session safety limit was reached. Capture streams were interrupted; start a new session if needed.")
            }
            let logSize = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent("unified-log.raw").path)[.size] as? NSNumber
            if let logSize, logSize.int64Value > 1_000_000_000 {
                throw CaptureFailure.process("Unified Log raw stream exceeded 1 GB. Capture streams were interrupted to protect disk space; review the saved session.")
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
        for process in processes { try stopProcess(process) }
        try writeCaptureContext(CaptureContext(start: bootStart, end: try sampleHostBoot()), to: contextURL)
        _ = try command(rvictl, ["-x", device])
        rviNeedsTeardown = false
        try status("stopped", interface, processes, nil)
    } catch {
        var message = error.localizedDescription
        for process in processes {
            do { try stopProcess(process) }
            catch { message += " Cleanup of process \(process.processIdentifier) failed: \(error.localizedDescription)" }
        }
        do { try status("failed", interface, processes, message) }
        catch { message += " Could not write failed status: \(error.localizedDescription)" }
        throw CaptureFailure.process(message)
    }
}

let arguments = CommandLine.arguments
guard arguments.count == 4, let appPID = Int32(arguments[3]), appPID > 1 else {
    fputs("Usage: RVICaptureHelper <device-udid> <session-directory> <app-pid>\n", stderr)
    exit(64)
}
let directory = URL(fileURLWithPath: arguments[2], isDirectory: true)
do {
    try runCapture(device: arguments[1], directory: directory, appPID: appPID)
} catch {
    let errorURL = directory.appendingPathComponent("helper.error")
    try? error.localizedDescription.write(to: errorURL, atomically: true, encoding: .utf8)
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}
