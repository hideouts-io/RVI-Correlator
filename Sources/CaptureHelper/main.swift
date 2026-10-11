import CorrelatorCore
import Darwin
import Foundation

// Bootstrap finishes before administrator authorization returns. The worker inherits
// only protected output handles, so no user-controlled privileged shell sink exists.
let arguments = CommandLine.arguments
var storage: ProtectedCaptureDirectory?
do {
    guard arguments.count == 6, geteuid() == 0,
          let identity = Data(base64Encoded: arguments[4]), let data = Data(base64Encoded: arguments[5]) else {
        throw AnalysisError.invalidInput("Capture bootstrap requires administrator authorization and valid encoded configuration.")
    }
    let requester = try JSONDecoder().decode(CaptureRequester.self, from: identity)
    guard try captureRequester(requester.pid) == requester else {
        throw AnalysisError.invalidInput("Capture app identity changed during authorization. Restart capture.")
    }
    let device = arguments[1]
    guard !device.isEmpty, device.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else {
        throw AnalysisError.invalidInput("Invalid device identifier supplied to capture bootstrap.")
    }
    let configuration = try JSONDecoder().decode(CaptureLaunchConfiguration.self, from: data)
    let iosConfig = configuration.iosLog
    try iosConfig?.validate()
    let protected = try createProtectedCaptureDirectory(sessionID: arguments[2], requesterUID: requester.uid)
    storage = protected
    if let iosConfig { try protected.write(JSONEncoder().encode(iosConfig), name: "ios-log-config.json") }
    let output = try protected.createFile("helper.stdout")
    let errors = try protected.createFile("helper.stderr")
    guard let worker = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("RVICaptureWorker"),
          FileManager.default.isExecutableFile(atPath: worker.path) else {
        throw AnalysisError.invalidInput("RVICaptureWorker is missing beside the helper. Rebuild the packaged app before capture.")
    }
    let process = Process()
    process.executableURL = try protected.installWorker(worker, expectedSHA256: configuration.workerSHA256)
    var workerArguments = Array(arguments.dropFirst())
    workerArguments[4] = try JSONEncoder().encode(iosConfig).base64EncodedString()
    process.arguments = workerArguments
    process.standardInput = FileHandle.nullDevice
    process.standardOutput = output; process.standardError = errors
    try process.run()
    try output.close(); try errors.close()
} catch {
    if let storage {
        do { try storage.write(Data(error.localizedDescription.utf8), name: "helper.error") }
        catch { fputs("Could not save protected bootstrap error: \(error.localizedDescription)\n", stderr) }
    }
    fputs("\(error.localizedDescription)\n", stderr)
    exit(1)
}
