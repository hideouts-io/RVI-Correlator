import CorrelatorCore
import CryptoKit
import Foundation

struct LiveSession: Sendable {
    let id: String
    let directory: URL
    let deviceName: String
    let captureDirectory: URL
}

private struct CapturedFile: Codable {
    let name: String
    let bytes: UInt64
    let sha256: String
}

private struct SessionManifest: Codable {
    let schemaVersion: Int
    let sessionID: String
    let deviceName: String
    let startedAt: Date
    let finalizedAt: Date
    let rviStreamStartedAt: Date?
    let pktapStreamStartedAt: Date?
    let logStreamStartedAt: Date?
    let rviInterface: String?
    let rviPackets: Int?
    let rviKernelDrops: Int?
    let pktapPackets: Int?
    let pktapKernelDrops: Int?
    let coverage: [InterfaceCoverage]
    let files: [CapturedFile]
    let interpretation: String
}

struct SessionContextEvidence: Codable, Sendable {
    let path: String
    let sha256: String
    let context: CaptureContext
}

enum LiveCaptureService {
    static func iosLogExecutable() -> String {
        let local = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/pymobiledevice3").path
        return [local, "/opt/homebrew/bin/pymobiledevice3", "/usr/local/bin/pymobiledevice3"].first { FileManager.default.isExecutableFile(atPath: $0) } ?? ""
    }

    static func iosLogConfiguration(executable: String, processID: String) throws -> IOSLogConfiguration {
        guard executable.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable),
              let pid = Int32(processID), pid > 0 else {
            throw AnalysisError.invalidInput("iPhone logs require an installed pymobiledevice3 executable and a positive current iPhone process PID. Find the device PID in Console or idevicesyslog pidlist; Mac PIDs do not apply.")
        }
        let process = Process(); let output = Pipe(); let errors = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["version"]; process.standardOutput = output; process.standardError = errors
        try process.run(); process.waitUntilExit()
        let version = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let diagnostic = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0, !version.isEmpty else { throw AnalysisError.invalidInput("iPhone log collector version check failed (exit \(process.terminationStatus)): \(diagnostic)") }
        let file = try capturedFile(URL(fileURLWithPath: executable), name: "collector")
        return IOSLogConfiguration(executable: executable, version: version, executableSHA256: file.sha256, processID: pid)
    }

    static func rviExecutable() -> URL? {
        ["/Library/Apple/usr/bin/rvictl", "/usr/bin/rvictl"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
            .map { URL(fileURLWithPath: $0) }
    }

    static func devices() throws -> [CaptureDevice] {
        let output = FileManager.default.temporaryDirectory.appendingPathComponent("rvi-devices-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: output) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = ["devicectl", "list", "devices", "--json-output", output.path]
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        process.waitUntilExit()
        let diagnostic = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw AnalysisError.invalidInput("devicectl could not list paired iPhones (exit \(process.terminationStatus)): \(diagnostic.prefix(1_000)). Connect, unlock, and trust the device, then retry.")
        }
        return try parseCaptureDevices(Data(contentsOf: output), usbSerials: connectedAppleUSBSerials())
    }

    static func start(device: CaptureDevice, iosLogConfiguration: IOSLogConfiguration?) throws -> LiveSession {
        guard device.isConnected,
              try devices().contains(where: { $0.id == device.id && $0.isConnected }) else {
            throw AnalysisError.invalidInput("Live capture requires a paired physical iPhone currently present on USB. Unlock, trust and refresh the device before retrying. A CoreDevice developer tunnel is not required for RVI.")
        }
        guard let helper = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("RVICaptureHelper"),
              FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw AnalysisError.invalidInput("RVICaptureHelper is missing from the app bundle. Rebuild the application before starting live capture.")
        }
        guard rviExecutable() != nil else {
            throw AnalysisError.invalidInput("Apple rvictl is not installed. Install Xcode device support, verify /Library/Apple/usr/bin/rvictl, and retry. No capture was started.")
        }
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let id = "session-\(stamp)-\(UUID().uuidString.prefix(8))"
        let root = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("RVI-Correlator/Sessions", isDirectory: true)
        let directory = root.appendingPathComponent(id, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        if let iosLogConfiguration {
            try iosLogConfiguration.validate()
            try JSONEncoder().encode(iosLogConfiguration).write(to: directory.appendingPathComponent("ios-log-config.json"), options: .atomic)
        }
        let requester = try captureRequester(ProcessInfo.processInfo.processIdentifier)
        let captureDirectory = try protectedCaptureURL(sessionID: id, requesterUID: requester.uid)
        let worker = helper.deletingLastPathComponent().appendingPathComponent("RVICaptureWorker")
        guard FileManager.default.isExecutableFile(atPath: worker.path) else {
            throw AnalysisError.invalidInput("RVICaptureWorker is missing. Rebuild the packaged app before capture.")
        }
        let workerIdentity = try capturedFile(worker, name: "RVICaptureWorker")
        guard workerIdentity.bytes <= 64_000_000 else { throw AnalysisError.resourceLimit("Capture worker exceeds 64 MB. Rebuild the app.") }
        let configuration = CaptureLaunchConfiguration(workerSHA256: workerIdentity.sha256, iosLog: iosLogConfiguration)
        let encodedConfiguration = try JSONEncoder().encode(configuration).base64EncodedString()
        let encodedRequester = try JSONEncoder().encode(requester).base64EncodedString()
        // Bootstrap runs synchronously so setup errors reach osascript. It launches
        // the worker with protected descriptors, never shell output redirections.
        let command = [helper.path, device.id, id, directory.path, encodedRequester, encodedConfiguration].map(shellQuoted).joined(separator: " ")
        let script = "do shell script \"\(appleScriptEscaped(command))\" with administrator privileges"
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = ["-e", script]
        let errors = Pipe()
        process.standardError = errors
        try process.run()
        process.waitUntilExit()
        let diagnostic = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard process.terminationStatus == 0 else {
            throw AnalysisError.invalidInput("macOS administrator authorization did not launch live capture (exit \(process.terminationStatus)): \(diagnostic.prefix(1_000)). Session directory: \(directory.path)")
        }
        let session = LiveSession(id: id, directory: directory, deviceName: device.name, captureDirectory: captureDirectory)
        let deadline = Date().addingTimeInterval(45)
        while Date() < deadline {
            if let health = try status(session) {
                guard health.phase == "running" else {
                    throw AnalysisError.invalidInput("Capture helper did not enter running state: \(health.error ?? health.phase). Inspect \(captureDirectory.path).")
                }
                return session
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        try stop(session)
        throw AnalysisError.invalidInput("Capture helper did not report readiness within 45 seconds. A stop was requested. Verify protected capture directory ownership, ACLs and helper diagnostics at \(captureDirectory.path), then retry.")
    }

    static func stop(_ session: LiveSession) throws {
        try Data().write(to: session.directory.appendingPathComponent("stop.request"), options: .atomic)
    }

    static func status(_ session: LiveSession) throws -> LiveCaptureStatus? {
        let url = session.captureDirectory.appendingPathComponent("status.json")
        let errorURL = session.captureDirectory.appendingPathComponent("helper.error")
        if FileManager.default.fileExists(atPath: errorURL.path) {
            throw AnalysisError.invalidInput("Capture helper failed: \(try String(contentsOf: errorURL, encoding: .utf8)). Diagnostics: \(session.captureDirectory.path)")
        }
        if !FileManager.default.fileExists(atPath: url.path) {
            return nil
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let status = try decoder.decode(LiveCaptureStatus.self, from: Data(contentsOf: url))
        if status.phase == "running" && Date().timeIntervalSince(status.updatedAt) > 12 {
            throw AnalysisError.invalidInput("Capture helper health has not updated for over 12 seconds. Inspect \(session.captureDirectory.path)/helper.stderr and stop the session if necessary.")
        }
        return status
    }

    static func liveEvidence(_ session: LiveSession, existingPhone: [Observation], existingMac: [Observation]) throws -> [ImportedEvidence] {
        let phone = session.captureDirectory.appendingPathComponent("iphone-rvi.pcapng")
        let mac = session.captureDirectory.appendingPathComponent("mac-pktap.pcapng")
        let phoneItem = try hasPackets(phone) ? importLiveCapture(phone, source: .iphone, sessionID: session.id,
                                                                   afterRecord: existingPhone.last?.record ?? 0) : nil
        let macItem = try hasPackets(mac) ? importLiveCapture(mac, source: .mac, sessionID: session.id,
                                                               afterRecord: existingMac.last?.record ?? 0) : nil
        let raw = session.captureDirectory.appendingPathComponent("unified-log.raw")
        let normalized = session.directory.appendingPathComponent("unified-log.ndjson")
        let phonePackets = try appendPacketObservations(existingPhone, incoming: phoneItem?.observations ?? [])
        let macPackets = try appendPacketObservations(existingMac, incoming: macItem?.observations ?? [])
        let normalization = try normalizeLiveLog(raw, destination: normalized, processIDs: processIDs(macPackets), tokens: logTokens(phonePackets + macPackets))
        let logItem = try stabilizeNormalizedLog(withLogNormalizationWarnings(try importUnifiedLog(normalized, offsetMicroseconds: 0), summary: normalization), sessionID: session.id)
        let iosItem = try FileManager.default.fileExists(atPath: session.captureDirectory.appendingPathComponent("ios-log-config.json").path)
            ? importLiveIOSLog(session.captureDirectory, sessionID: session.id, phoneArtifactID: "\(session.id)-iPhone RVI") : nil
        return [phoneItem, macItem, logItem, iosItem].compactMap { $0 }
    }

    static func finalEvidence(_ session: LiveSession, existingPhone: [Observation], existingMac: [Observation]) throws -> [ImportedEvidence] {
        let status = try status(session)
        guard status?.phase == "stopped" else {
            throw AnalysisError.invalidInput("Session \(session.directory.path) has not stopped cleanly. Final evidence hashing requires a stopped capture.")
        }
        let teardownError = session.captureDirectory.appendingPathComponent("teardown.error")
        if FileManager.default.fileExists(atPath: teardownError.path) {
            throw AnalysisError.invalidInput("RVI teardown failed: \(try String(contentsOf: teardownError, encoding: .utf8)). Review the session before finalizing.")
        }
        let names = ["iphone-rvi.pcapng", "mac-pktap.pcapng", "unified-log.raw", "iphone-tcpdump.stderr",
                     "mac-tcpdump.stderr", "unified-log.stderr", "status.json", "capture-context.json", "helper.stdout", "helper.stderr"] +
                    (status?.iosLogPID == nil ? [] : ["ios-log-config.json", "ios-log.ndjson", "ios-log.stderr"])
        try publishCaptureFiles(source: session.captureDirectory, destination: session.directory, names: names)
        let phone = session.directory.appendingPathComponent("iphone-rvi.pcapng")
        let mac = session.directory.appendingPathComponent("mac-pktap.pcapng")
        guard hasPackets(phone), hasPackets(mac) else {
            throw AnalysisError.invalidInput("Session \(session.directory.path) stopped without both nonempty packet captures. Inspect tcpdump stderr; final evidence cannot be marked complete.")
        }
        let phoneItem = try finalizeLiveCapture(phone, source: .iphone, sessionID: session.id, existing: existingPhone)
        let macItem = try finalizeLiveCapture(mac, source: .mac, sessionID: session.id, existing: existingMac)
        let raw = session.directory.appendingPathComponent("unified-log.raw")
        let normalized = session.directory.appendingPathComponent("unified-log.ndjson")
        try normalizeFinalLog(raw, destination: normalized, processIDs: processIDs(macItem.observations), tokens: logTokens(phoneItem.observations + macItem.observations))
        let logItem = try stabilizeNormalizedLog(try importUnifiedLog(normalized, offsetMicroseconds: 0), sessionID: session.id)
        let iosItem = try FileManager.default.fileExists(atPath: session.directory.appendingPathComponent("ios-log-config.json").path)
            ? importIOSLog(session.directory, sessionID: session.id, phoneArtifactID: phoneItem.artifact.id) : nil
        try writeManifest(session, status: status, observations: phoneItem.observations)
        return [phoneItem, macItem, logItem, iosItem].compactMap { $0 }
    }

    static func loadSavedSession(_ directory: URL) throws -> [ImportedEvidence] {
        let manifestURL = directory.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw AnalysisError.invalidInput("This folder has no finalized RVI Correlator manifest: \(directory.path)/manifest.json")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let manifest: SessionManifest
        do { manifest = try decoder.decode(SessionManifest.self, from: Data(contentsOf: manifestURL)) }
        catch { throw AnalysisError.invalidInput("Could not read the saved-session manifest at \(manifestURL.path): \(error)") }
        guard [1, 2, 3].contains(manifest.schemaVersion) else {
            throw AnalysisError.invalidInput("Saved session \(directory.path) uses unsupported manifest schema \(manifest.schemaVersion).")
        }
        let expected = Set(["iphone-rvi.pcapng", "mac-pktap.pcapng", "unified-log.raw", "unified-log.ndjson",
                            "iphone-tcpdump.stderr", "mac-tcpdump.stderr", "unified-log.stderr", "status.json"] + (manifest.schemaVersion >= 2 ? ["capture-context.json"] : []) + (manifest.schemaVersion == 3 ? ["ios-log-config.json", "ios-log.ndjson", "ios-log.stderr"] : []))
        let names = manifest.files.map(\.name)
        guard names.count == expected.count, Set(names) == expected else {
            throw AnalysisError.invalidInput("Saved-session manifest at \(manifestURL.path) has missing, duplicate, or unexpected evidence-file names.")
        }
        for record in manifest.files {
            let actual = try capturedFile(directory.appendingPathComponent(record.name), name: record.name)
            guard actual.bytes == record.bytes, actual.sha256 == record.sha256 else {
                throw AnalysisError.evidenceChanged("Saved evidence changed since finalization: \(directory.path)/\(record.name). Expected \(record.bytes) bytes and SHA-256 \(record.sha256); found \(actual.bytes) bytes and \(actual.sha256).")
            }
        }
        if manifest.schemaVersion >= 2 {
            let context = try readCaptureContext(directory.appendingPathComponent("capture-context.json"))
            guard context.end != nil else { throw AnalysisError.invalidInput("Finalized session context is missing its end sample: \(directory.path)") }
        }
        var evidence = [try importCapture(directory.appendingPathComponent("iphone-rvi.pcapng"), source: .iphone, offsetMicroseconds: 0),
                        try importCapture(directory.appendingPathComponent("mac-pktap.pcapng"), source: .mac, offsetMicroseconds: 0),
                        try importUnifiedLog(directory.appendingPathComponent("unified-log.ndjson"), offsetMicroseconds: 0)]
        if manifest.schemaVersion == 3 {
            evidence.append(try importIOSLog(directory, sessionID: manifest.sessionID, phoneArtifactID: evidence[0].artifact.id))
        }
        for item in evidence {
            let name = URL(fileURLWithPath: item.artifact.path).lastPathComponent
            guard let record = manifest.files.first(where: { $0.name == name }),
                  record.bytes == item.artifact.bytes, record.sha256 == item.artifact.sha256 else {
                throw AnalysisError.evidenceChanged("Saved evidence changed while importing \(directory.path)/\(name). Reopen a stable copy of the finalized session.")
            }
        }
        return evidence
    }

    static func savedContext(_ directory: URL) throws -> SessionContextEvidence? {
        let decoder = JSONDecoder(); decoder.dateDecodingStrategy = .iso8601
        let manifest = try decoder.decode(SessionManifest.self, from: Data(contentsOf: directory.appendingPathComponent("manifest.json")))
        guard manifest.schemaVersion >= 2 else { return nil }
        guard let record = manifest.files.first(where: { $0.name == "capture-context.json" }) else {
            throw AnalysisError.invalidInput("Schema-2 session is missing its capture-context.json manifest entry.")
        }
        let url = directory.appendingPathComponent(record.name)
        let actual = try capturedFile(url, name: record.name)
        guard actual.bytes == record.bytes, actual.sha256 == record.sha256 else { throw AnalysisError.evidenceChanged("Session context no longer matches its manifest: \(url.path)") }
        return SessionContextEvidence(path: url.path, sha256: actual.sha256, context: try readCaptureContext(url))
    }

    private static func writeManifest(_ session: LiveSession, status: LiveCaptureStatus?, observations: [Observation]) throws {
        guard let status else { throw AnalysisError.invalidInput("Capture status is missing for \(session.directory.path).") }
        let hasIOSLog = status.iosLogPID != nil
        let names = ["iphone-rvi.pcapng", "mac-pktap.pcapng", "unified-log.raw", "unified-log.ndjson",
                     "iphone-tcpdump.stderr", "mac-tcpdump.stderr", "unified-log.stderr", "status.json", "capture-context.json"] + (hasIOSLog ? ["ios-log-config.json", "ios-log.ndjson", "ios-log.stderr"] : [])
        let context = try readCaptureContext(session.directory.appendingPathComponent("capture-context.json"))
        guard context.end != nil else { throw AnalysisError.invalidInput("Cannot finalize session without the host boot end sample.") }
        let files = try names.map { try capturedFile(session.directory.appendingPathComponent($0), name: $0) }
        let manifest = SessionManifest(schemaVersion: hasIOSLog ? 3 : 2, sessionID: session.id, deviceName: session.deviceName,
                                       startedAt: status.startedAt, finalizedAt: Date(),
                                       rviStreamStartedAt: status.rviStreamStartedAt,
                                       pktapStreamStartedAt: status.pktapStreamStartedAt,
                                       logStreamStartedAt: status.logStreamStartedAt,
                                       rviInterface: status.rviInterface,
                                       rviPackets: status.rviPackets, rviKernelDrops: status.rviDropped,
                                       pktapPackets: status.pktapPackets, pktapKernelDrops: status.pktapDropped,
                                       coverage: iphoneInterfaceCoverage(observations), files: files,
                                       interpretation: interpretationNotice)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(manifest).write(to: session.directory.appendingPathComponent("manifest.json"), options: .atomic)
    }

    private static func capturedFile(_ url: URL, name: String) throws -> CapturedFile {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hash = SHA256()
        var bytes: UInt64 = 0
        while true {
            let chunk = try handle.read(upToCount: 1_048_576) ?? Data()
            if chunk.isEmpty { break }
            bytes += UInt64(chunk.count)
            hash.update(data: chunk)
        }
        return CapturedFile(name: name, bytes: bytes, sha256: hash.finalize().map { String(format: "%02x", $0) }.joined())
    }

    private static func hasPackets(_ url: URL) -> Bool {
        guard let size = try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber else { return false }
        return size.intValue > 32
    }

    private static func processIDs(_ observations: [Observation]) -> Set<Int> {
        Set(observations.compactMap { $0.pid.flatMap(Int.init) })
    }

    private static func logTokens(_ observations: [Observation]) -> Set<String> {
        Set(observations.flatMap { ($0.destinationIP.map { [$0] } ?? []) + $0.hostnames })
    }

    private static func shellQuoted(_ string: String) -> String {
        "'" + string.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func appleScriptEscaped(_ string: String) -> String {
        string.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}
