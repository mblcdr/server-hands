import XCTest
@testable import ServerHandsKit

final class MiscTests: XCTestCase {
    func testPairingUriParses() throws {
        let b = Codec.b64e(Data(repeating: 7, count: 32))
        let u = try PairingURI.parse(" hands://pair?v=1&host=192.168.1.5&port=8443&spki=\(b)&sid=\(b)&tok=\(b) \n")
        XCTAssertEqual(u.pin.host, "192.168.1.5")
        XCTAssertEqual(u.pin.port, 8443)
        XCTAssertEqual(u.token.count, 32)
        XCTAssertEqual(u.pin.fingerprint.split(separator: " ").count, 4)
    }

    func testPairingUriRejectsBadInput() {
        let b = Codec.b64e(Data(repeating: 7, count: 32))
        let bad = [
            "https://pair?v=1", "hands://pair?v=2&host=h&port=1&spki=\(b)&sid=\(b)&tok=\(b)",
            "hands://pair?v=1&host=a/b&port=1&spki=\(b)&sid=\(b)&tok=\(b)",
            "hands://pair?v=1&host=h&port=0&spki=\(b)&sid=\(b)&tok=\(b)",
            "hands://pair?v=1&host=h&port=1&spki=\(b)&sid=\(b)",
            "hands://pair?v=1&host=h&port=1&spki=AA&sid=\(b)&tok=\(b)",
        ]
        for t in bad { XCTAssertThrowsError(try PairingURI.parse(t), t) }
    }

    func testBase64Url() throws {
        XCTAssertEqual(Codec.b64e(Data([0xfb, 0xff])), "-_8")
        XCTAssertEqual(try Codec.b64d("-_8"), Data([0xfb, 0xff]))
        XCTAssertThrowsError(try Codec.b64d("a"))
        XCTAssertThrowsError(try Codec.b64d("ab=="))
    }

    func testUuidRoundTrip() throws {
        let s = "0123abcd-0000-4000-8000-0000000000ff"
        XCTAssertEqual(ServerClient.formatUuid(try ServerClient.parseUuid(s)), s)
        XCTAssertThrowsError(try ServerClient.parseUuid("nope"))
    }

    func testWakeOnLan() throws {
        XCTAssertEqual(WakeOnLan.normalize("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(WakeOnLan.normalize("aabbccddeeff"), "aa:bb:cc:dd:ee:ff")
        XCTAssertNil(WakeOnLan.normalize("aa:bb:cc"))
        XCTAssertNil(WakeOnLan.normalize("gg:bb:cc:dd:ee:ff"))
        let p = try XCTUnwrap(WakeOnLan.magicPacket("aa:bb:cc:dd:ee:ff"))
        XCTAssertEqual(p.count, 102)
        XCTAssertEqual(p.prefix(6), Data(repeating: 0xff, count: 6))
        XCTAssertEqual(p.suffix(6), Data([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
    }

    func testFormat() {
        XCTAssertEqual(formatBytes(4_000_000_000_000), "4.0 TB")
        XCTAssertEqual(formatBytes(512), "512 B")
        XCTAssertEqual(formatBytes(123_000_000_000), "123 GB")
        XCTAssertEqual(formatUptime(90_000), "1d 1h")
        XCTAssertEqual(formatUptime(45), "45s")
        XCTAssertEqual(percent(fraction(1, 4)), "25%")
    }

    func testPlaintextRejectsBadEntries() {
        let u = Data(repeating: 1, count: 16)
        XCTAssertThrowsError(try Seal.encodePlaintext([]))
        XCTAssertThrowsError(try Seal.encodePlaintext([PasswordEntry(uuid: u, passphrase: Data())]))
        XCTAssertThrowsError(try Seal.encodePlaintext([PasswordEntry(uuid: u, passphrase: Data([1])), PasswordEntry(uuid: u, passphrase: Data([1]))]))
    }

    func testStrictDecodingRejectsUnknownFields() throws {
        let ok = Data(#"{"client_nonce":"a","server_time":1,"requests":[]}"#.utf8)
        _ = try WireJSON.decode(ListReply.self, from: ok)
        let extra = Data(#"{"client_nonce":"a","server_time":1,"requests":[],"x":1}"#.utf8)
        XCTAssertThrowsError(try WireJSON.decode(ListReply.self, from: extra))
    }
}
