import CryptoKit
import Foundation

/// One drive passphrase. Raw bytes only; the owner must `wipe()` after use. Deliberately prints nothing.
public final class PasswordEntry: CustomStringConvertible, CustomDebugStringConvertible {
    public let uuid: Data
    public private(set) var passphrase: Data

    public init(uuid: Data, passphrase: Data) {
        self.uuid = uuid
        self.passphrase = passphrase
    }

    public func wipe() { passphrase.wipe() }
    public var description: String { "PasswordEntry(redacted)" }
    public var debugDescription: String { description }
}

/// Wire encodings around HPKE (see `HPKE`).
public enum Seal {
    public static let plaintextVersion: UInt8 = 1
    public static let padTo = 256
    public static let maxPassphraseLength = 1024
    public static let maxEntries = 32

    public static func info(serverPub: Data, reqId: Data, clientNonce: Data, deviceId: Data) -> Data {
        Codec.lp(Data("hands/v1/hpke".utf8), Codec.sha256(serverPub), reqId, clientNonce, deviceId)
    }

    /// `uuids` must be raw 16-byte values in strictly ascending order.
    public static func aad(_ uuids: [Data]) throws -> Data {
        for i in uuids.indices.dropFirst() where Codec.compareUnsigned(uuids[i - 1], uuids[i]) >= 0 { throw ProtocolError() }
        return Codec.lp(uuids)
    }

    /// Returns `(enc, ct || tag)`.
    public static func seal(ephPub: Data, info: Data, aad: Data, plaintext: Data) throws -> (enc: Data, ct: Data) {
        do {
            let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPub)
            return try HPKE.seal(recipient: pub, info: info, aad: aad, plaintext: plaintext)
        } catch {
            throw ProtocolError()
        }
    }

    /// Receiver side; the phone never needs it, but tests do.
    public static func open(ephPriv: Data, enc: Data, info: Data, aad: Data, ct: Data) throws -> Data {
        do {
            let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephPriv)
            return try HPKE.open(recipient: priv, enc: enc, info: info, aad: aad, ct: ct)
        } catch {
            throw ProtocolError()
        }
    }

    /// `0x01 || count || count x (uuid[16] || len_be16 || pw) || zero padding to a multiple of 256`.
    public static func encodePlaintext(_ entries: [PasswordEntry]) throws -> Data {
        guard !entries.isEmpty, entries.count <= maxEntries else { throw ProtocolError() }
        for (i, e) in entries.enumerated() {
            guard e.uuid.count == 16, !e.passphrase.isEmpty, e.passphrase.count <= maxPassphraseLength else { throw ProtocolError() }
            if i > 0, Codec.compareUnsigned(entries[i - 1].uuid, e.uuid) >= 0 { throw ProtocolError() }
        }
        let len = 2 + entries.reduce(0) { $0 + 18 + $1.passphrase.count }
        var out = Data(capacity: (len + padTo - 1) / padTo * padTo)
        out.append(plaintextVersion)
        out.append(UInt8(entries.count))
        for e in entries {
            out.append(e.uuid)
            out.append(UInt8(e.passphrase.count >> 8))
            out.append(UInt8(e.passphrase.count & 0xff))
            out.append(e.passphrase)
        }
        out.append(Data(count: (len + padTo - 1) / padTo * padTo - len))
        return out
    }

    public static func decodePlaintext(_ buf: Data) throws -> [PasswordEntry] {
        let b = [UInt8](buf)
        var i = 0
        func need(_ n: Int) throws { if n < 0 || i + n > b.count { throw ProtocolError() } }
        try need(2)
        guard b[i] == plaintextVersion else { throw ProtocolError() }
        i += 1
        let count = Int(b[i]); i += 1
        guard count != 0, count <= maxEntries, b.count % padTo == 0 else { throw ProtocolError() }
        var out: [PasswordEntry] = []
        for _ in 0..<count {
            try need(18)
            let uuid = Data(b[i..<i + 16]); i += 16
            let len = Int(b[i]) << 8 | Int(b[i + 1]); i += 2
            guard len != 0, len <= maxPassphraseLength else { throw ProtocolError() }
            if let last = out.last, Codec.compareUnsigned(last.uuid, uuid) >= 0 { throw ProtocolError() }
            try need(len)
            out.append(PasswordEntry(uuid: uuid, passphrase: Data(b[i..<i + len]))); i += len
        }
        guard b[i...].allSatisfy({ $0 == 0 }) else { throw ProtocolError() }
        return out
    }

    /// 6-digit pairing confirmation code.
    public static func sas(serverPub: Data, deviceSpki: Data, token: Data) -> String {
        let h = Codec.sha256(Data("hands/v1/sas".utf8) + Codec.lp(serverPub, deviceSpki, token))
        let n = UInt64(h[h.startIndex]) << 24 | UInt64(h[h.startIndex + 1]) << 16 | UInt64(h[h.startIndex + 2]) << 8 | UInt64(h[h.startIndex + 3])
        return String(format: "%06llu", n % 1_000_000)
    }
}
