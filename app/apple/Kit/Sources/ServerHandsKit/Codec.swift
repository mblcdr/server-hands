import CryptoKit
import Foundation

/// Opaque failure: callers cannot tell why verification or decoding failed (and no payload leaks).
public struct ProtocolError: Error {
    public init() {}
}

public enum Codec {
    /// base64url without padding.
    public static func b64e(_ bytes: Data) -> String {
        bytes.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func b64d(_ s: String) throws -> Data {
        guard s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { throw ProtocolError() }
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        switch t.count % 4 {
        case 0: break
        case 2: t += "=="
        case 3: t += "="
        default: throw ProtocolError()
        }
        guard let d = Data(base64Encoded: t) else { throw ProtocolError() }
        return d
    }

    public static func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

    /// `u32be(len) || bytes` per field.
    public static func lp(_ fields: Data...) -> Data { lp(fields) }

    public static func lp(_ fields: [Data]) -> Data {
        var out = Data()
        for f in fields {
            let n = UInt32(f.count)
            out.append(contentsOf: [UInt8(n >> 24), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
            out.append(f)
        }
        return out
    }

    /// `domain || 0x00 || body`: the exact bytes that get signed.
    public static func signedBytes(_ domain: String, _ body: Data) -> Data {
        Data(domain.utf8) + Data([0]) + body
    }

    public static func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }

    public static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    public static func fromHex(_ s: String) throws -> Data {
        guard s.count % 2 == 0 else { throw ProtocolError() }
        var out = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let b = UInt8(s[i..<j], radix: 16) else { throw ProtocolError() }
            out.append(b)
            i = j
        }
        return out
    }

    public static func compareUnsigned(_ a: Data, _ b: Data) -> Int {
        for (x, y) in zip(a, b) where x != y { return Int(x) - Int(y) }
        return a.count - b.count
    }
}

public enum Domain {
    public static let serverReply = "hands/v1/server-reply"
    public static let deviceRequest = "hands/v1/device-request"
    public static let approve = "hands/v1/approve"
    public static let pair = "hands/v1/pair"
    public static let scriptApprove = "hands/v1/script-approve"
}

extension Data {
    /// Overwrites the bytes in place. Best effort: Swift may have made copies, but the buffers we own are cleared.
    public mutating func wipe() {
        withUnsafeMutableBytes { raw in
            if let base = raw.baseAddress { memset_s(base, raw.count, 0, raw.count) }
        }
    }
}
