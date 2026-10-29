import Foundation

/// Server replies are decoded strictly: an unknown field is a protocol error, like on the server side.
protocol WireBody: Decodable {
    static var fieldNames: Set<String> { get }
}

enum WireJSON {
    static func decode<T: WireBody>(_ type: T.Type, from data: Data) throws -> T {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(obj.keys).isSubset(of: T.fieldNames),
              let value = try? JSONDecoder().decode(T.self, from: data)
        else { throw ProtocolError() }
        return value
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        do { return try JSONEncoder().encode(value) } catch { throw ProtocolError() }
    }
}

struct Envelope: Codable {
    let body: String
    let sig: String
}

struct ListBody: Encodable {
    let deviceId: String
    let clientNonce: String
    let ts: Int64
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", clientNonce = "client_nonce", ts }
}

public struct DriveInfo: Decodable, Hashable, Sendable {
    public let luksUuid: String
    public let label: String
    public let size: Int64
    enum CodingKeys: String, CodingKey { case luksUuid = "luks_uuid", label, size }
}

public struct RequestView: Decodable, Hashable, Sendable, Identifiable {
    public let reqId: String
    public let expiresAt: Int64
    public let drives: [DriveInfo]
    public let ePub: String
    public let status: String
    public var id: String { reqId }
    enum CodingKeys: String, CodingKey { case reqId = "req_id", expiresAt = "expires_at", drives, ePub = "e_pub", status }
}

struct ListReply: WireBody {
    let clientNonce: String
    let serverTime: Int64
    let requests: [RequestView]
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce", serverTime = "server_time", requests }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct ScriptRunBody: Encodable {
    let deviceId: String
    let clientNonce: String
    let ts: Int64
    let script: String
    var challenge: String?
    var approvalSig: String?
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", clientNonce = "client_nonce", ts, script, challenge, approvalSig = "approval_sig" }
}

struct ScriptChallengeBody: Encodable {
    let deviceId: String
    let clientNonce: String
    let ts: Int64
    let challengeFor: String
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", clientNonce = "client_nonce", ts, challengeFor = "challenge_for" }
}

struct ScriptChallengeReply: WireBody {
    let clientNonce: String
    let script: String
    let challenge: String
    let expiresAt: Int64
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce", script, challenge, expiresAt = "expires_at" }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct ApprovalKeyBody: Encodable {
    let deviceId: String
    let clientNonce: String
    let ts: Int64
    let approvalPub: String
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", clientNonce = "client_nonce", ts, approvalPub = "approval_pub" }
}

struct ApprovalKeyReply: WireBody {
    let clientNonce: String
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce" }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

/// `mode`: auto | manual. `state`: idle | queued | running | ok | failed. `finishedAt` is unix seconds, 0 if never.
public struct ScriptView: Decodable, Hashable, Sendable, Identifiable {
    public let name: String
    public let label: String
    public let mode: String
    public let state: String
    public let finishedAt: Int64
    /// The app asks before running it (unless `biometricProtection` makes the biometric prompt the confirmation).
    public let requiresConfirmation: Bool
    /// Running it needs a biometric signature over a server challenge.
    public let biometricProtection: Bool
    public var busy: Bool { state == "queued" || state == "running" }
    public var id: String { name }

    enum CodingKeys: String, CodingKey, CaseIterable {
        case name, label, mode, state, finishedAt = "finished_at", requiresConfirmation = "requires_confirmation", biometricProtection = "biometric_protection"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        label = try c.decode(String.self, forKey: .label)
        mode = try c.decode(String.self, forKey: .mode)
        state = try c.decode(String.self, forKey: .state)
        finishedAt = try c.decode(Int64.self, forKey: .finishedAt)
        requiresConfirmation = try c.decodeIfPresent(Bool.self, forKey: .requiresConfirmation) ?? false
        biometricProtection = try c.decodeIfPresent(Bool.self, forKey: .biometricProtection) ?? false
    }
}

struct ScriptsReply: WireBody {
    let clientNonce: String
    let serverTime: Int64
    let unlocked: Bool
    let scripts: [ScriptView]
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce", serverTime = "server_time", unlocked, scripts }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct ScriptRunReply: WireBody {
    let clientNonce: String
    let script: String
    let state: String
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce", script, state }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct ApproveRequest: Encodable {
    let deviceId: String
    let clientNonce: String
    let uuids: [String]
    let enc: String
    let ct: String
    let sig: String
    enum CodingKeys: String, CodingKey { case deviceId = "device_id", clientNonce = "client_nonce", uuids, enc, ct, sig }
}

public struct DriveResult: Decodable, Hashable, Sendable {
    public let luksUuid: String
    public let result: String
    enum CodingKeys: String, CodingKey { case luksUuid = "luks_uuid", result }
}

struct ApproveReply: WireBody {
    let clientNonce: String
    let reqId: String
    let results: [DriveResult]
    enum CodingKeys: String, CodingKey, CaseIterable { case clientNonce = "client_nonce", reqId = "req_id", results }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct PairRequest: Encodable {
    let tok: String
    let devicePub: String
    let deviceName: String
    enum CodingKeys: String, CodingKey { case tok, devicePub = "device_pub", deviceName = "device_name" }
}

struct PairAck: WireBody {
    let deviceId: String
    let serverTime: Int64
    enum CodingKeys: String, CodingKey, CaseIterable { case deviceId = "device_id", serverTime = "server_time" }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}

struct ErrorBody: Decodable { let error: String }

/// `state`: absent | locked | open | mounted. `size` is the LUKS container; the rest is the mounted filesystem, 0 unless mounted.
public struct DriveStatus: Decodable, Hashable, Sendable, Identifiable {
    public let luksUuid: String
    public let label: String
    public let state: String
    public let size: Int64
    public let total: Int64
    public let used: Int64
    public let avail: Int64
    public var id: String { luksUuid }
    enum CodingKeys: String, CodingKey { case luksUuid = "luks_uuid", label, state, size, total, used, avail }
}

/// A pool mount such as mergerfs. Sizes are 0 unless `mounted`.
public struct PoolStatus: Decodable, Hashable, Sendable, Identifiable {
    public let name: String
    public let mountPoint: String
    public let fstype: String
    public let mounted: Bool
    public let total: Int64
    public let used: Int64
    public let avail: Int64
    public var id: String { mountPoint }
    enum CodingKeys: String, CodingKey { case name, mountPoint = "mount_point", fstype, mounted, total, used, avail }
}

/// Machine status. Sizes are bytes; `cpuPercent` is 0 to 100.
public struct ServerStatus: WireBody, Hashable, Sendable {
    let clientNonce: String
    let serverTime: Int64
    public let hostname: String
    public let kernel: String
    public let uptimeSecs: Int64
    public let load: [Double]
    public let cpus: Int
    public let cpuPercent: Double
    public let memTotal: Int64
    public let memAvailable: Int64
    public let swapTotal: Int64
    public let swapFree: Int64
    public let drives: [DriveStatus]
    public let pools: [PoolStatus]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case clientNonce = "client_nonce", serverTime = "server_time", hostname, kernel, uptimeSecs = "uptime_secs", load, cpus
        case cpuPercent = "cpu_percent", memTotal = "mem_total", memAvailable = "mem_available", swapTotal = "swap_total", swapFree = "swap_free"
        case drives, pools
    }
    static var fieldNames: Set<String> { Set(CodingKeys.allCases.map(\.rawValue)) }
}
