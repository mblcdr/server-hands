import CryptoKit
import XCTest
@testable import ServerHandsKit

final class VectorsTests: XCTestCase {
    private var v: [String: Any]!

    override func setUpWithError() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "v1", withExtension: "json"))
        v = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func hex(_ o: Any?) throws -> Data { try Codec.fromHex(try XCTUnwrap(o as? String)) }

    func testPositiveVectors() throws {
        let keys = v["keys"] as! [String: Any], ids = v["ids"] as! [String: Any]
        let serverPub = try hex(keys["server_ed25519_pub"]), spki = try hex(keys["device_spki_der"])

        let envj = v["envelope"] as! [String: Any], env = envj["envelope"] as! [String: String]
        let body = try Signatures.serverVerify(serverPub: serverPub, domain: envj["domain"] as! String, bodyB64: env["body"]!, sigB64: env["sig"]!)
        XCTAssertEqual(Data((envj["body_utf8"] as! String).utf8), body)

        XCTAssertEqual(try hex(keys["device_id"]), Signatures.deviceId(spki: spki))

        let a = v["approve"] as! [String: Any]
        let reqId = try hex(ids["req_id"]), nonce = try hex(ids["client_nonce"]), devId = try hex(keys["device_id"])
        let info = Seal.info(serverPub: serverPub, reqId: reqId, clientNonce: nonce, deviceId: devId)
        XCTAssertEqual(try hex(a["info"]), info)
        let entries = a["entries"] as! [[String: String]]
        let aad = try Seal.aad(entries.map { try hex($0["uuid"]) })
        XCTAssertEqual(try hex(a["aad"]), aad)

        // Open a ciphertext sealed by Rust, and the server key pair matches.
        let ephPriv = try hex(keys["eph_priv"])
        let pub = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ephPriv).publicKey.rawRepresentation
        XCTAssertEqual(try hex(keys["eph_pub"]), pub)
        let pt = try Seal.open(ephPriv: ephPriv, enc: hex(a["enc"]), info: info, aad: aad, ct: hex(a["ct"]))
        XCTAssertEqual(try hex(a["plaintext"]), pt)
        let decoded = try Seal.decodePlaintext(pt)
        XCTAssertEqual(decoded.count, entries.count)
        for (e, d) in zip(entries, decoded) {
            XCTAssertEqual(try hex(e["uuid"]), d.uuid)
            XCTAssertEqual(try hex(e["passphrase_hex"]), d.passphrase)
        }
        // Re-encoding reproduces Rust's plaintext byte for byte.
        XCTAssertEqual(try hex(a["plaintext"]), try Seal.encodePlaintext(decoded))

        let msg = Signatures.approveMessage(reqId: reqId, clientNonce: nonce, enc: try hex(a["enc"]), ct: try hex(a["ct"]), aad: aad)
        XCTAssertEqual(try hex(a["signed_message"]), msg)
        try Signatures.deviceVerify(spki: spki, message: msg, sigDer: hex(a["device_sig_der"]))

        let s = v["sas"] as! [String: String]
        XCTAssertEqual(s["expected"], Seal.sas(serverPub: serverPub, deviceSpki: spki, token: try hex(s["token"])))
    }

    func testSwiftSealOpensWithServerKey() throws {
        let keys = v["keys"] as! [String: Any], ids = v["ids"] as! [String: Any]
        let info = Seal.info(serverPub: try hex(keys["server_ed25519_pub"]), reqId: try hex(ids["req_id"]), clientNonce: try hex(ids["client_nonce"]), deviceId: try hex(keys["device_id"]))
        let u1 = try ServerClient.parseUuid("00000000-0000-4000-8000-000000000001")
        let u2 = try ServerClient.parseUuid("00000000-0000-4000-8000-000000000002")
        let entries = [PasswordEntry(uuid: u1, passphrase: Data("FAKE-swift-one".utf8)), PasswordEntry(uuid: u2, passphrase: Data("FAKE-swift-two".utf8))]
        let pt = try Seal.encodePlaintext(entries)
        let aad = try Seal.aad([u1, u2])
        let (enc, ct) = try Seal.seal(ephPub: hex(keys["eph_pub"]), info: info, aad: aad, plaintext: pt)
        XCTAssertEqual(enc.count, 32)
        XCTAssertEqual(try Seal.open(ephPriv: hex(keys["eph_priv"]), enc: enc, info: info, aad: aad, ct: ct), pt)
    }

    /// Sealed by the Kotlin implementation; Swift must open it too.
    func testKotlinSealedVectorOpens() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../../protocol/vectors/v1-kotlin.json").standardized
        let k = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let keys = v["keys"] as! [String: Any]
        let pt = try Seal.open(ephPriv: hex(keys["eph_priv"]), enc: hex(k["enc"]), info: hex(k["info"]), aad: hex(k["aad"]), ct: hex(k["ct"]))
        XCTAssertEqual(try hex(k["plaintext"]), pt)
    }

    func testNegativeVectorsAreAllRejected() throws {
        let cases = v["negative"] as! [[String: Any]]
        XCTAssertGreaterThanOrEqual(cases.count, 20)
        for c in cases {
            let name = c["name"] as! String
            do {
                switch c["kind"] as! String {
                case "envelope_verify":
                    let e = c["envelope"] as! [String: String]
                    _ = try Signatures.serverVerify(serverPub: hex(c["server_pub"]), domain: c["domain"] as! String, bodyB64: e["body"]!, sigB64: e["sig"]!)
                case "hpke_open":
                    _ = try Seal.open(ephPriv: hex(c["eph_priv"]), enc: hex(c["enc"]), info: hex(c["info"]), aad: hex(c["aad"]), ct: hex(c["ct"]))
                case "device_verify":
                    try Signatures.deviceVerify(spki: hex(c["spki"]), message: hex(c["message"]), sigDer: hex(c["sig"]))
                case "plaintext_decode":
                    _ = try Seal.decodePlaintext(hex(c["bytes"]))
                default:
                    XCTFail("unknown kind")
                }
                XCTFail("negative vector accepted: \(name)")
            } catch is ProtocolError {
            }
        }
    }

    func testScriptApproveMessage() {
        let m = Signatures.scriptApproveMessage(serverPub: Data(repeating: 1, count: 32), deviceId: Data(repeating: 2, count: 16), script: "s", challenge: Data(repeating: 3, count: 32))
        XCTAssertTrue(m.starts(with: Data("hands/v1/script-approve".utf8) + Data([0])))
    }
}
