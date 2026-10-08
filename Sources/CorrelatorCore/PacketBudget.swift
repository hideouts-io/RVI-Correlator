import Foundation

let maximumPacketRecords = 500_000
let maximumPacketBytes = 256_000_000

struct PacketBudget {
    let records: Int
    let bytes: Int
}

func addingPacketBudget(_ current: PacketBudget, records: Int, bytes: Int, limit: PacketBudget) throws -> PacketBudget {
    guard records >= 0, bytes >= 0, current.records >= 0, current.bytes >= 0,
          current.records <= limit.records, current.bytes <= limit.bytes,
          records <= limit.records - current.records, bytes <= limit.bytes - current.bytes else {
        throw AnalysisError.resourceLimit("Aggregate packet evidence exceeds \(limit.records) records or \(limit.bytes) budgeted bytes. Use a shorter capture.")
    }
    return PacketBudget(records: current.records + records, bytes: current.bytes + bytes)
}

func addingPacketFields(_ fields: [String: [String]], budget: PacketBudget, limit: PacketBudget) throws -> PacketBudget {
    var result = budget
    for (key, values) in fields {
        result = try addingPacketBudget(result, records: 0, bytes: 128 + key.utf8.count, limit: limit)
        for value in values {
            result = try addingPacketBudget(result, records: 0, bytes: 64 + value.utf8.count, limit: limit)
        }
    }
    return result
}

/// Counts retained UTF-8 plus conservative per-record/field/value overhead, including empty values.
/// This is an allocation budget, not a measurement of Swift's resident memory.
public func appendPacketObservations(_ existing: [Observation], incoming: [Observation]) throws -> [Observation] {
    let limit = PacketBudget(records: maximumPacketRecords, bytes: maximumPacketBytes)
    return try appendPacketObservations(existing, incoming: incoming, limit: limit)
}

func appendPacketObservations(_ existing: [Observation], incoming: [Observation], limit: PacketBudget) throws -> [Observation] {
    var budget = try addingPacketBudget(PacketBudget(records: 0, bytes: 0), records: existing.count, bytes: 0, limit: limit)
    budget = try addingPacketBudget(budget, records: incoming.count, bytes: 0, limit: limit)
    for collection in [existing, incoming] {
        for record in collection {
            budget = try addingPacketBudget(budget, records: 0, bytes: 384, limit: limit)
            let strings = [record.id, record.artifactID] + record.protocols
            for value in strings {
                budget = try addingPacketBudget(budget, records: 0, bytes: 64 + value.utf8.count, limit: limit)
            }
            budget = try addingPacketFields(record.fields, budget: budget, limit: limit)
            for answer in record.dnsRecords {
                budget = try addingPacketBudget(budget, records: 0, bytes: 128 + answer.owner.utf8.count + answer.value.utf8.count, limit: limit)
            }
        }
    }
    return existing + incoming
}
