import CryptoKit
import Foundation

public enum Signatures {
    /// Verifies a server envelope (Ed25519, raw 32-byte key, raw 64-byte signature) and only then returns the body bytes.
    public static func serverVerify(serverPub: Data, domain: String, bodyB64: String, sigB64: String) throws -> Data {
        guard serverPub.count == 32 else { throw ProtocolError() }
        let body = try Codec.b64d(bodyB64)
        let sig = try Codec.b64d(sigB64)
        guard sig.count == 64,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: serverPub),
              key.isValidSignature(sig, for: Codec.signedBytes(domain, body))
        else { throw ProtocolError() }
        return body
    }

    /// `SHA-256(spki)[0..16]`
    public static func deviceId(spki: Data) -> Data { Data(Codec.sha256(spki).prefix(16)) }

    /// The bytes the device signs when approving a request.
    public static func approveMessage(reqId: Data, clientNonce: Data, enc: Data, ct: Data, aad: Data) -> Data {
        Codec.signedBytes(Domain.approve, Codec.lp(reqId, clientNonce, enc, Codec.sha256(ct), aad))
    }

    /// The bytes the biometric-bound approval key signs to authorise one run of a script.
    public static func scriptApproveMessage(serverPub: Data, deviceId: Data, script: String, challenge: Data) -> Data {
        Codec.signedBytes(Domain.scriptApprove, Codec.lp(serverPub, deviceId, Data(script.utf8), challenge))
    }
}

extension Signatures {
    /// ECDSA P-256 / SHA-256, DER signature, SPKI DER public key. Used for tests; the server does this in production.
    public static func deviceVerify(spki: Data, message: Data, sigDer: Data) throws {
        guard let key = try? P256.Signing.PublicKey(derRepresentation: spki),
              let sig = try? P256.Signing.ECDSASignature(derRepresentation: sigDer),
              key.isValidSignature(sig, for: message)
        else { throw ProtocolError() }
    }
}
