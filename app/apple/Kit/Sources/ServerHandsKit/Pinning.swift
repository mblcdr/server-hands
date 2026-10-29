import Foundation
import Security

/// What the pairing QR carries, and what the app stores afterwards: the only trust root for a server.
public struct Pin: Sendable, Hashable {
    public let host: String
    public let port: Int
    public let spkiSha256: Data
    public let serverPub: Data

    public init(host: String, port: Int, spkiSha256: Data, serverPub: Data) {
        self.host = host
        self.port = port
        self.spkiSha256 = spkiSha256
        self.serverPub = serverPub
    }

    /// First 16 hex chars of SHA-256(server key), grouped; shown to the user.
    public var fingerprint: String {
        let hex = Codec.hex(Codec.sha256(serverPub).prefix(8))
        return stride(from: 0, to: hex.count, by: 4).map { i in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 4)])
        }.joined(separator: " ")
    }
}

public struct PairingURI: Sendable {
    public let pin: Pin
    public let token: Data

    /// `hands://pair?v=1&host=..&port=..&spki=..&sid=..&tok=..`. Only ever called on scanned or pasted text.
    public static func parse(_ text: String) throws -> PairingURI {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = "hands://pair?"
        guard t.hasPrefix(prefix) else { throw ProtocolError() }
        var q: [String: String] = [:]
        for part in t.dropFirst(prefix.count).split(separator: "&") {
            guard let i = part.firstIndex(of: "=") else { continue }
            q[String(part[..<i])] = String(part[part.index(after: i)...])
        }
        func get(_ k: String) throws -> String {
            guard let v = q[k] else { throw ProtocolError() }
            return v
        }
        guard try get("v") == "1" else { throw ProtocolError() }
        let host = try get("host")
        guard !host.isEmpty, !host.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "@" }) else { throw ProtocolError() }
        guard let port = Int(try get("port")), (1...65535).contains(port) else { throw ProtocolError() }
        let spki = try Codec.b64d(try get("spki"))
        let sid = try Codec.b64d(try get("sid"))
        let tok = try Codec.b64d(try get("tok"))
        guard spki.count == 32, sid.count == 32, tok.count == 32 else { throw ProtocolError() }
        return PairingURI(pin: Pin(host: host, port: port, spkiSha256: spki, serverPub: sid), token: tok)
    }
}

/// Accepts exactly one certificate: the one whose SubjectPublicKeyInfo hashes to the pin. No CA store, no hostname.
final class PinnedSessionDelegate: NSObject, URLSessionDelegate {
    private let spkiSha256: Data

    init(spkiSha256: Data) { self.spkiSha256 = spkiSha256 }

    /// ASN.1 prefix of an uncompressed P-256 SubjectPublicKeyInfo; the server certificate key is always P-256.
    private static let p256SpkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first,
              let key = SecCertificateCopyKey(leaf),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              raw.count == 65
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        if Codec.constantTimeEquals(Codec.sha256(Self.p256SpkiHeader + raw), spkiSha256) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
