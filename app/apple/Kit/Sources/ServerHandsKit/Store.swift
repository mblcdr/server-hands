import Foundation

/// A drive the user enrolled a passphrase for. A passphrase is released only for UUIDs listed here.
public struct EnrolledDrive: Codable, Hashable, Sendable {
    public let uuid: String
    public let label: String
    public init(uuid: String, label: String) { self.uuid = uuid; self.label = label }
}

/// Public data about the one paired server. Nothing secret: keys live in the Keychain / Secure Enclave, passphrases in the vault.
public struct PairingRecord: Codable, Hashable, Sendable {
    public let host: String
    public let port: Int
    public let spki: String
    public let sid: String
    public let keyAlias: String
    public let deviceName: String
    public var drives: [EnrolledDrive]
    /// The server's MAC address for Wake-on-LAN. Not secret.
    public var mac: String?

    public init(host: String, port: Int, spki: String, sid: String, keyAlias: String, deviceName: String, drives: [EnrolledDrive] = [], mac: String? = nil) {
        self.host = host; self.port = port; self.spki = spki; self.sid = sid
        self.keyAlias = keyAlias; self.deviceName = deviceName; self.drives = drives; self.mac = mac
    }

    public var pin: Pin {
        get throws { Pin(host: host, port: port, spkiSha256: try Codec.b64d(spki), serverPub: try Codec.b64d(sid)) }
    }
    public var serverPub: Data { get throws { try Codec.b64d(sid) } }

    public static func alias(for serverPub: Data) -> String { "hands_device_" + Codec.hex(Codec.sha256(serverPub).prefix(6)) }
}

/// Plain files in the app's private directory, written atomically.
public struct PairingStore: Sendable {
    private let dir: URL

    public init(dir: URL) { self.dir = dir }

    public static func standard() throws -> PairingStore {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let dir = base.appendingPathComponent("ServerHands", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        var d = dir
        try? d.setResourceValues(v)
        return PairingStore(dir: dir)
    }

    private var record: URL { dir.appendingPathComponent("pairing.json") }
    private var vault: URL { dir.appendingPathComponent("vault.bin") }

    public func load() -> PairingRecord? {
        guard let d = try? Data(contentsOf: record) else { return nil }
        return try? JSONDecoder().decode(PairingRecord.self, from: d)
    }

    public func save(_ p: PairingRecord) throws { try write(record, JSONEncoder().encode(p)) }
    public func readVault() -> Data? { try? Data(contentsOf: vault) }
    public func writeVault(_ blob: Data) throws { try write(vault, blob) }
    public func clearVault() { try? FileManager.default.removeItem(at: vault) }
    public func clear() { try? FileManager.default.removeItem(at: record); clearVault() }

    private func write(_ url: URL, _ data: Data) throws {
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: .atomic)
        #endif
    }
}
