import CryptoKit
import XCTest
@testable import ServerHandsKit

/// Swift client against the real Rust daemon (TLS 1.3, SPKI pin, signed replies, HPKE) with a fake host.
/// Skipped unless `cargo build -p handsd --example fake_server` has been run in `server/`.
final class InteropTests: XCTestCase {
    private var proc: Process?
    private let uuid = "00000000-0000-4000-8000-000000000001"
    private let good = Data("correct horse battery staple".utf8)

    override func tearDown() { proc?.terminate() }

    private func startServer() throws -> (Pin, Data) {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../../..").standardized
        let exe = root.appendingPathComponent("server/target/debug/examples/fake_server")
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: exe.path), "fake_server not built; skipping interop test")
        let p = Process()
        p.executableURL = exe
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        try p.run()
        proc = p
        var line = Data()
        while let b = try out.fileHandleForReading.read(upToCount: 1), !b.isEmpty, b != Data("\n".utf8) { line.append(b) }
        let j = try XCTUnwrap(JSONSerialization.jsonObject(with: line) as? [String: Any])
        let pin = Pin(host: j["host"] as! String, port: Int("\(j["port"]!)")!, spkiSha256: try Codec.b64d(j["spki"] as! String), serverPub: try Codec.b64d(j["sid"] as! String))
        return (pin, try Codec.b64d(j["token"] as! String))
    }

    private func entry(_ pass: Data) throws -> PasswordEntry { PasswordEntry(uuid: try ServerClient.parseUuid(uuid), passphrase: pass) }

    private func serverCode(_ body: () async throws -> Void) async -> Int? {
        do { try await body(); return nil } catch let e as ServerError { return e.status } catch { return -1 }
    }

    func testPairListApproveRetry() async throws {
        let (pin, token) = try startServer()
        let client = ServerClient(pin: pin, signer: SoftwareDeviceSigner())
        let sas = SasBox()
        try await client.pair(token: token, deviceName: "swift test") { sas.value = $0 }
        XCTAssertEqual(sas.value.count, 6)

        let first = try await client.list()
        let req = try XCTUnwrap(first.requests.first)
        XCTAssertEqual(first.requests.count, 1)
        XCTAssertEqual(req.drives[0].luksUuid, uuid)
        XCTAssertEqual(req.drives[0].label, "Disk-1")

        let bad = try await client.approve(listing: first, request: req, entries: [entry(Data("nope".utf8))])
        XCTAssertEqual(bad.first?.result, "bad_passphrase")

        let second = try await client.list()
        let retry = try XCTUnwrap(second.requests.first)
        XCTAssertNotEqual(retry.reqId, req.reqId)
        XCTAssertNotEqual(retry.ePub, req.ePub)

        let replay = await serverCode { _ = try await client.approve(listing: first, request: req, entries: [try self.entry(self.good)]) }
        XCTAssertNotNil(replay)

        let ok = try await client.approve(listing: second, request: retry, entries: [entry(good)])
        XCTAssertEqual(ok.first?.result, "ok")
        let rest = try await client.list()
        XCTAssertTrue(rest.requests.isEmpty)
    }

    func testApproveWipesPassphrases() async throws {
        let (pin, token) = try startServer()
        let client = ServerClient(pin: pin, signer: SoftwareDeviceSigner())
        try await client.pair(token: token, deviceName: "swift test") { _ in }
        let l = try await client.list()
        let e = try entry(good)
        _ = try await client.approve(listing: l, request: l.requests[0], entries: [e])
        XCTAssertEqual(e.passphrase, Data(count: good.count))
    }

    func testStatusScriptsAndBiometricScript() async throws {
        let (pin, token) = try startServer()
        let client = ServerClient(pin: pin, signer: SoftwareDeviceSigner())
        try await client.pair(token: token, deviceName: "swift test") { _ in }

        let s = try await client.status()
        XCTAssertEqual(s.load.count, 3)
        XCTAssertTrue((0...100).contains(s.cpuPercent))

        let before = try await client.scripts()
        XCTAssertFalse(before.unlocked)
        let demo = try XCTUnwrap(before.scripts.first { $0.name == "demo" })
        XCTAssertEqual([demo.label, demo.mode, demo.state], ["Demo containers", "manual", "idle"])
        let notUnlocked = await serverCode { try await client.runScript("demo") }
        XCTAssertEqual(notUnlocked, 409)
        let unknown = await serverCode { try await client.runScript("nope") }
        XCTAssertEqual(unknown, 404)

        // Approval key stands in as a software key; on a device it is biometric-bound in the Secure Enclave.
        let secure = try XCTUnwrap(before.scripts.first { $0.name == "secure" })
        XCTAssertTrue(secure.biometricProtection && secure.requiresConfirmation)
        let approval = SoftwareDeviceSigner()
        let needsKey = await serverCode { _ = try await client.scriptChallenge("secure") }
        XCTAssertEqual(needsKey, 403)
        try await client.registerApprovalKey(spki: approval.spki)
        try await client.registerApprovalKey(spki: approval.spki)
        let conflict = await serverCode { try await client.registerApprovalKey(spki: SoftwareDeviceSigner().spki) }
        XCTAssertEqual(conflict, 409)

        let l = try await client.list()
        _ = try await client.approve(listing: l, request: l.requests[0], entries: [entry(good)])
        let unlocked = try await client.scripts()
        XCTAssertTrue(unlocked.unlocked)

        let challenge = try await client.scriptChallenge("secure")
        let sig = try approval.sign(challenge.message)
        try await client.runScript("secure", challenge: challenge, approvalSig: sig)
        var state = ""
        for _ in 0..<100 {
            state = try await client.scripts().scripts.first { $0.name == "secure" }?.state ?? ""
            if state == "ok" { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertEqual(state, "ok")
        let reuse = await serverCode { try await client.runScript("secure", challenge: challenge, approvalSig: sig) }
        XCTAssertEqual(reuse, 403)
    }

    func testWrongPinUnpairedDeviceAndWrongServerKeyAreRefused() async throws {
        let (pin, token) = try startServer()
        let signer = SoftwareDeviceSigner()
        try await ServerClient(pin: pin, signer: signer).pair(token: token, deviceName: "swift test") { _ in }

        let badPin = Pin(host: pin.host, port: pin.port, spkiSha256: Data(count: 32), serverPub: pin.serverPub)
        do {
            _ = try await ServerClient(pin: badPin, signer: signer).list()
            XCTFail("wrong TLS pin accepted")
        } catch is URLError {}

        let unpaired = await serverCode { _ = try await ServerClient(pin: pin, signer: SoftwareDeviceSigner()).list() }
        XCTAssertEqual(unpaired, 401)

        let wrongSid = Pin(host: pin.host, port: pin.port, spkiSha256: pin.spkiSha256, serverPub: Data(repeating: 1, count: 32))
        do {
            _ = try await ServerClient(pin: wrongSid, signer: signer).list()
            XCTFail("reply signed by another server accepted")
        } catch is ProtocolError {}
    }
}

private final class SasBox: @unchecked Sendable { var value = "" }
