import Foundation

/// The device key. In the app this is a Secure Enclave key; tests use a software key.
public protocol DeviceSigner: Sendable {
    /// X.509 SubjectPublicKeyInfo DER.
    var spki: Data { get }
    /// ECDSA P-256 / SHA-256, DER signature.
    func sign(_ message: Data) throws -> Data
}

extension DeviceSigner {
    public var id: Data { Signatures.deviceId(spki: spki) }
}

/// The server answered with an error body. Deliberately only the wire code, never details.
public struct ServerError: Error, Sendable {
    public let status: Int
    public let code: String
}

public struct Listing: Sendable {
    let clientNonce: Data
    public let serverTime: Int64
    public let requests: [RequestView]
}

/// Post-unlock scripts. `unlocked` is false until every drive is open; nothing can be started before.
public struct Scripts: Sendable {
    public let unlocked: Bool
    public let scripts: [ScriptView]
}

/// A single-use challenge the server issued for one run of `script`; `message` is what the approval key signs.
public struct ScriptChallenge: Sendable {
    public let script: String
    let challenge: Data
    public let expiresAt: Int64
    public let message: Data
}

/// Talks to one paired server. Every server reply is verified against the pinned Ed25519 key and bound to a
/// fresh nonce before anything in it is used.
public struct ServerClient: Sendable {
    private let pin: Pin
    private let signer: DeviceSigner
    private let nowSecs: @Sendable () -> Int64

    public init(pin: Pin, signer: DeviceSigner, nowSecs: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) }) {
        self.pin = pin
        self.signer = signer
        self.nowSecs = nowSecs
    }

    private func post(_ path: String, _ body: Data, timeout: TimeInterval = 15) async throws -> Data {
        var comps = URLComponents()
        comps.scheme = "https"
        comps.host = pin.host
        comps.port = pin.port
        comps.path = path
        guard let url = comps.url else { throw ProtocolError() }

        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        config.connectionProxyDictionary = [:] // never through a proxy
        config.urlCache = nil
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        let session = URLSession(configuration: config, delegate: PinnedSessionDelegate(spkiSha256: pin.spkiSha256), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "content-type")
        req.httpBody = body
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else { throw ProtocolError() }
        guard http.statusCode == 200 else {
            let code = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error ?? "unknown"
            throw ServerError(status: http.statusCode, code: code)
        }
        return data
    }

    private func verified(_ domain: String, _ data: Data) throws -> Data {
        guard let env = try? JSONDecoder().decode(Envelope.self, from: data) else { throw ProtocolError() }
        return try Signatures.serverVerify(serverPub: pin.serverPub, domain: domain, bodyB64: env.body, sigB64: env.sig)
    }

    /// Blocks until the operator confirms the code on the server console. `onSas` fires first.
    public func pair(token: Data, deviceName: String, onSas: @Sendable (String) -> Void) async throws {
        onSas(Seal.sas(serverPub: pin.serverPub, deviceSpki: signer.spki, token: token))
        let req = try WireJSON.encode(PairRequest(tok: Codec.b64e(token), devicePub: Codec.b64e(signer.spki), deviceName: deviceName))
        let text = try await post("/v1/pair", req, timeout: 330)
        let ack = try WireJSON.decode(PairAck.self, from: verified(Domain.pair, text))
        guard Codec.constantTimeEquals(try Codec.b64d(ack.deviceId), signer.id) else { throw ProtocolError() }
    }

    /// Signs `body` (which carries the fresh nonce), posts it and returns the verified reply bytes.
    private func signedCall(_ path: String, _ body: Data) async throws -> Data {
        let sig = try signer.sign(Codec.signedBytes(Domain.deviceRequest, body))
        let env = try WireJSON.encode(Envelope(body: Codec.b64e(body), sig: Codec.b64e(sig)))
        return try verified(Domain.serverReply, try await post(path, env))
    }

    private func freshNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw ProtocolError() }
        return Data(bytes)
    }

    private func checkFresh(_ echoed: String, _ nonce: Data, serverTime: Int64? = nil) throws {
        if echoed != Codec.b64e(nonce) { throw ProtocolError() }
        if let t = serverTime, abs(t - nowSecs()) > 60 { throw ProtocolError() }
    }

    private func listBody(_ nonce: Data) throws -> Data {
        try WireJSON.encode(ListBody(deviceId: Codec.b64e(signer.id), clientNonce: Codec.b64e(nonce), ts: nowSecs()))
    }

    public func list() async throws -> Listing {
        let nonce = try freshNonce()
        let reply = try WireJSON.decode(ListReply.self, from: await signedCall("/v1/requests/list", listBody(nonce)))
        try checkFresh(reply.clientNonce, nonce, serverTime: reply.serverTime)
        return Listing(clientNonce: nonce, serverTime: reply.serverTime, requests: reply.requests)
    }

    /// Uptime, CPU, memory and drive/pool usage. Read-only.
    public func status() async throws -> ServerStatus {
        let nonce = try freshNonce()
        let reply = try WireJSON.decode(ServerStatus.self, from: await signedCall("/v1/status", listBody(nonce)))
        try checkFresh(reply.clientNonce, nonce, serverTime: reply.serverTime)
        return reply
    }

    public func scripts() async throws -> Scripts {
        let nonce = try freshNonce()
        let reply = try WireJSON.decode(ScriptsReply.self, from: await signedCall("/v1/scripts/list", listBody(nonce)))
        try checkFresh(reply.clientNonce, nonce, serverTime: reply.serverTime)
        return Scripts(unlocked: reply.unlocked, scripts: reply.scripts)
    }

    /// Registers the biometric-bound approval key (`spki`, X.509 DER). The server keeps the first key it sees for
    /// this device; a different one is refused (`conflict`) until the operator resets it.
    public func registerApprovalKey(spki: Data) async throws {
        let nonce = try freshNonce()
        let body = try WireJSON.encode(ApprovalKeyBody(deviceId: Codec.b64e(signer.id), clientNonce: Codec.b64e(nonce), ts: nowSecs(), approvalPub: Codec.b64e(spki)))
        let reply = try WireJSON.decode(ApprovalKeyReply.self, from: await signedCall("/v1/device/approval-key", body))
        try checkFresh(reply.clientNonce, nonce)
    }

    /// Asks the server for the challenge a `biometricProtection` script run must be approved over.
    public func scriptChallenge(_ name: String) async throws -> ScriptChallenge {
        let nonce = try freshNonce()
        let body = try WireJSON.encode(ScriptChallengeBody(deviceId: Codec.b64e(signer.id), clientNonce: Codec.b64e(nonce), ts: nowSecs(), challengeFor: name))
        let reply = try WireJSON.decode(ScriptChallengeReply.self, from: await signedCall("/v1/scripts/challenge", body))
        try checkFresh(reply.clientNonce, nonce)
        let challenge = try Codec.b64d(reply.challenge)
        guard reply.script == name, challenge.count == 32 else { throw ProtocolError() }
        return ScriptChallenge(
            script: name, challenge: challenge, expiresAt: reply.expiresAt,
            message: Signatures.scriptApproveMessage(serverPub: pin.serverPub, deviceId: signer.id, script: name, challenge: challenge)
        )
    }

    /// Starts the named script (a name the server configured). Returns at once; read the outcome with `scripts()`.
    /// For a `biometricProtection` script pass the `challenge` and the approval key's `approvalSig` over its message.
    public func runScript(_ name: String, challenge: ScriptChallenge? = nil, approvalSig: Data? = nil) async throws {
        let nonce = try freshNonce()
        let body = try WireJSON.encode(ScriptRunBody(
            deviceId: Codec.b64e(signer.id), clientNonce: Codec.b64e(nonce), ts: nowSecs(), script: name,
            challenge: challenge.map { Codec.b64e($0.challenge) }, approvalSig: approvalSig.map(Codec.b64e)
        ))
        let reply = try WireJSON.decode(ScriptRunReply.self, from: await signedCall("/v1/scripts/run", body))
        try checkFresh(reply.clientNonce, nonce)
        guard reply.script == name else { throw ProtocolError() }
    }

    /// Seals `entries` (any order, any subset of the request's drives) to the request's ephemeral key and approves.
    /// The entries' passphrases are wiped before this returns, success or not.
    public func approve(listing: Listing, request: RequestView, entries: [PasswordEntry]) async throws -> [DriveResult] {
        var plain = Data()
        defer {
            plain.wipe()
            entries.forEach { $0.wipe() }
        }
        let sorted = entries.sorted { Codec.compareUnsigned($0.uuid, $1.uuid) < 0 }
        let reqId = try Codec.b64d(request.reqId)
        let info = Seal.info(serverPub: pin.serverPub, reqId: reqId, clientNonce: listing.clientNonce, deviceId: signer.id)
        let aad = try Seal.aad(sorted.map(\.uuid))
        plain = try Seal.encodePlaintext(sorted)
        let (enc, ct) = try Seal.seal(ephPub: Codec.b64d(request.ePub), info: info, aad: aad, plaintext: plain)
        let sig = try signer.sign(Signatures.approveMessage(reqId: reqId, clientNonce: listing.clientNonce, enc: enc, ct: ct, aad: aad))
        let body = try WireJSON.encode(ApproveRequest(
            deviceId: Codec.b64e(signer.id), clientNonce: Codec.b64e(listing.clientNonce),
            uuids: sorted.map { Self.formatUuid($0.uuid) }, enc: Codec.b64e(enc), ct: Codec.b64e(ct), sig: Codec.b64e(sig)
        ))
        let text = try await post("/v1/requests/\(request.reqId)/approve", body, timeout: 180)
        let reply = try WireJSON.decode(ApproveReply.self, from: verified(Domain.serverReply, text))
        guard reply.clientNonce == Codec.b64e(listing.clientNonce), reply.reqId == request.reqId else { throw ProtocolError() }
        return reply.results
    }

    public static func parseUuid(_ text: String) throws -> Data {
        let hex = text.replacingOccurrences(of: "-", with: "")
        guard text.count == 36, hex.count == 32 else { throw ProtocolError() }
        return try Codec.fromHex(hex)
    }

    public static func formatUuid(_ raw: Data) -> String {
        let h = Codec.hex(raw)
        let p = { (a: Int, b: Int) in String(h[h.index(h.startIndex, offsetBy: a)..<h.index(h.startIndex, offsetBy: b)]) }
        return "\(p(0, 8))-\(p(8, 12))-\(p(12, 16))-\(p(16, 20))-\(p(20, 32))"
    }
}
