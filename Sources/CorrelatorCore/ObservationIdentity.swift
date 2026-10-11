import Foundation

/// Public analysis callers may supply observations independently of the file importers.
/// Reject collisions explicitly before constructing any unique-key lookup.
func validateObservationIdentities(_ observations: [Observation]) throws {
    var identifiers: Set<String> = []
    var records: Set<String> = []
    for observation in observations {
        guard identifiers.insert(observation.id).inserted,
              records.insert("\(observation.artifactID):\(observation.record)").inserted else {
            throw AnalysisError.invalidInput("Duplicate observation identity or artifact record. Import each artifact once and retain distinct physical record identities.")
        }
    }
}

/// Called only after fresh normalization, whose encoder generates source-line annotations.
/// Imported external annotations remain provenance, never imported observation identities.
public func stabilizeNormalizedLog(_ item: ImportedEvidence, sessionID: String) throws -> ImportedEvidence {
    let id = "\(sessionID)-Unified Log"
    var lines: Set<Int> = []
    let observations = try item.observations.map { old in
        guard let text = old.first("log.captureLine"), let line = Int(text), line > 0,
              lines.insert(line).inserted else {
            throw AnalysisError.invalidInput("Freshly normalized Unified Log has missing or duplicate source-line provenance. Re-normalize the original stream.")
        }
        return Observation(id: "\(id):\(line)", source: .log, artifactID: id, record: line,
            originalMicroseconds: old.originalMicroseconds, timeMicroseconds: old.timeMicroseconds,
            protocols: old.protocols, fields: old.fields, dnsRecords: old.dnsRecords)
    }
    let old = item.artifact
    let artifact = Artifact(id: id, source: .log, path: old.path, sha256: old.sha256, bytes: old.bytes,
        records: old.records, decoder: old.decoder, offsetMicroseconds: old.offsetMicroseconds, warnings: old.warnings)
    return ImportedEvidence(artifact: artifact, observations: observations)
}
