import CryptoKit
import Foundation

/// HPKE RFC 9180, base mode, single-shot: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305.
/// CryptoKit only ships HPKE from iOS 17, so this is built from its X25519, HKDF and ChaChaPoly primitives and
/// checked against the shared test vectors (sealed by Rust and by Kotlin).
enum HPKE {
    private static let kemSuite = Data("KEM".utf8) + i2osp(0x0020, 2)
    private static let suite = Data("HPKE".utf8) + i2osp(0x0020, 2) + i2osp(0x0001, 2) + i2osp(0x0003, 2)
    private static let version = Data("HPKE-v1".utf8)

    private static func i2osp(_ v: Int, _ n: Int) -> Data { Data((0..<n).map { UInt8((v >> (8 * (n - 1 - $0))) & 0xff) }) }

    private static func labeledExtract(_ suite: Data, salt: Data, label: String, ikm: Data) -> SymmetricKey {
        let prk = HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: version + suite + Data(label.utf8) + ikm), salt: salt)
        return SymmetricKey(data: Data(prk))
    }

    private static func labeledExpand(_ suite: Data, prk: SymmetricKey, label: String, info: Data, length: Int) -> Data {
        let labeledInfo = i2osp(length, 2) + version + suite + Data(label.utf8) + info
        let out = HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeledInfo, outputByteCount: length)
        return out.withUnsafeBytes { Data($0) }
    }

    private static func sharedSecret(dh: SharedSecret, kemContext: Data) -> Data {
        let dhBytes = dh.withUnsafeBytes { Data($0) }
        let prk = labeledExtract(kemSuite, salt: Data(), label: "eae_prk", ikm: dhBytes)
        return labeledExpand(kemSuite, prk: prk, label: "shared_secret", info: kemContext, length: 32)
    }

    /// Key schedule, mode 0 (base): returns the AEAD key and base nonce (the nonce of sequence number 0).
    private static func keySchedule(sharedSecret: Data, info: Data) -> (key: SymmetricKey, nonce: ChaChaPoly.Nonce) {
        let pskIdHash = labeledExtract(suite, salt: Data(), label: "psk_id_hash", ikm: Data())
        let infoHash = labeledExtract(suite, salt: Data(), label: "info_hash", ikm: info)
        let context = Data([0]) + pskIdHash.withUnsafeBytes { Data($0) } + infoHash.withUnsafeBytes { Data($0) }
        let secret = labeledExtract(suite, salt: sharedSecret, label: "secret", ikm: Data())
        let key = labeledExpand(suite, prk: secret, label: "key", info: context, length: 32)
        let nonce = labeledExpand(suite, prk: secret, label: "base_nonce", info: context, length: 12)
        return (SymmetricKey(data: key), try! ChaChaPoly.Nonce(data: nonce))
    }

    /// Returns `(enc, ct || tag)`.
    static func seal(recipient: Curve25519.KeyAgreement.PublicKey, info: Data, aad: Data, plaintext: Data) throws -> (enc: Data, ct: Data) {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let enc = eph.publicKey.rawRepresentation
        let dh = try eph.sharedSecretFromKeyAgreement(with: recipient)
        let ss = sharedSecret(dh: dh, kemContext: enc + recipient.rawRepresentation)
        let (key, nonce) = keySchedule(sharedSecret: ss, info: info)
        let box = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce, authenticating: aad)
        return (enc, box.ciphertext + box.tag)
    }

    static func open(recipient: Curve25519.KeyAgreement.PrivateKey, enc: Data, info: Data, aad: Data, ct: Data) throws -> Data {
        guard ct.count >= 16 else { throw ProtocolError() }
        let pkE = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: enc)
        let dh = try recipient.sharedSecretFromKeyAgreement(with: pkE)
        let ss = sharedSecret(dh: dh, kemContext: enc + recipient.publicKey.rawRepresentation)
        let (key, nonce) = keySchedule(sharedSecret: ss, info: info)
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16))
        return try ChaChaPoly.open(box, using: key, authenticating: aad)
    }
}
