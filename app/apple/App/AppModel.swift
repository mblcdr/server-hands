import Foundation
import ServerHandsKit
import SwiftUI

#if os(iOS)
import UIKit
#endif

/// Debug builds accept software-backed device keys (simulators); release builds refuse them.
let allowSoftwareKeys: Bool = {
    #if DEBUG
    true
    #else
    false
    #endif
}()

func currentDeviceName() -> String {
    #if os(iOS)
    UIDevice.current.name
    #else
    Host.current().localizedName ?? "Mac"
    #endif
}

@MainActor
final class AppModel: ObservableObject {
    private static let statusInterval: Duration = .seconds(5)

    @Published private(set) var pairing: PairingRecord?
    @Published private(set) var requests: [RequestView] = []
    @Published private(set) var sas: String?
    @Published private(set) var busy: String?
    @Published var message: String?
    @Published var results: [DriveResult] = []
    @Published private(set) var scripts: Scripts?
    /// nil until the first check; true when the last call reached the pinned server, false when it did not.
    @Published private(set) var connected: Bool?
    /// Latest machine and drive status; refreshed every few seconds while the app is in the foreground.
    @Published private(set) var status: ServerStatus?

    private let store: PairingStore?
    private var lastCheck = Date.distantPast
    private var pollTask: Task<Void, Never>?

    init() {
        store = try? PairingStore.standard()
        pairing = store?.load()
    }

    private func requireStore() throws -> PairingStore {
        guard let store else { throw KeySecurityError("The app's storage is not available.") }
        return store
    }

    private func client(_ p: PairingRecord) throws -> ServerClient {
        guard let signer = try DeviceKey.load(alias: p.keyAlias) else { throw KeySecurityError("The device key is gone; pair again.") }
        return ServerClient(pin: try p.pin, signer: signer)
    }

    /// Runs `block` with a busy label, turning every failure into a user message that never carries secrets.
    private func op(_ label: String, revocable: Bool = true, _ block: @escaping () async throws -> Void) {
        Task {
            busy = label
            message = nil
            connectionIssue = false
            do {
                try await block()
            } catch is Biometrics.Cancelled {
                message = "Cancelled."
            } catch {
                if revocable, forgetIfRevoked(error) {} else {
                    message = describe(error)
                    connectionIssue = error is URLError
                }
            }
            busy = nil
            sas = nil
        }
    }

    private func describe(_ e: Error) -> String {
        switch e {
        case let e as ServerError:
            switch e.code {
            case "unauthorized": return "The server does not accept this device (not paired, or revoked)."
            case "rate_limited": return "Too many failed attempts. Wait a few minutes."
            case "not_unlocked": return "That script needs the drives unlocked first."
            case "busy": return "That script is already running."
            case "approval_required": return "The server did not accept the biometric approval. Try again."
            case "conflict": return "The server already has a different approval key for this device. On the server run: sudo handsctl reset-approval-key <device-id>"
            case "unknown_script": return "The server no longer has that script. Refresh."
            case "expired": return "That request expired. Refresh."
            case "replayed": return "That request was already used. Refresh."
            default: return "The server refused the request (\(e.code))."
            }
        case is ProtocolError: return "The server's reply could not be verified. Nothing was sent."
        case let e as URLError:
            switch e.code {
            case .cancelled, .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
                 .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected:
                return "This is not the server you paired with (identity mismatch). Nothing was sent."
            case .notConnectedToInternet:
                return "Cannot reach the server. Allow Server Hands to use the local network in system settings (Privacy & Security > Local Network), then try again."
            default: return "Cannot reach the server on the local network."
            }
        case is VaultInvalidated:
            if let store { store.clearVault(); if var p = pairing { p.drives = []; try? store.save(p); pairing = p } }
            return "Biometrics changed, so the vault key was destroyed. Enter the drive passphrases again."
        case let e as KeySecurityError: return e.message
        case let e as KeychainError: return e.localizedDescription + " (keychain \(e.status))"
        case is WakeOnLan.SendFailed: return "Could not send the Wake-on-LAN packet. Check that Server Hands may use the local network."
        default:
            let ns = e as NSError
            return "Unexpected error: \(ns.localizedDescription) [\(ns.domain) \(ns.code)]"
        }
    }

    // MARK: Pairing

    func pair(_ text: String) {
        op("Pairing with server...", revocable: false) { [self] in
            let uri: PairingURI
            do { uri = try PairingURI.parse(text) } catch {
                message = "That is not a Server Hands pairing code."
                return
            }
            let store = try requireStore()
            let alias = PairingRecord.alias(for: uri.pin.serverPub)
            DeviceKey.delete(alias: alias)
            let signer = try DeviceKey.create(alias: alias, allowSoftware: allowSoftwareKeys)
            let name = currentDeviceName()
            do {
                try await Self.retryingWhileLocalNetworkPending {
                    try await ServerClient(pin: uri.pin, signer: signer).pair(token: uri.token, deviceName: name) { sas in
                        Task { @MainActor in self.sas = sas }
                    }
                }
            } catch {
                DeviceKey.delete(alias: alias)
                throw error
            }
            let rec = PairingRecord(host: uri.pin.host, port: uri.pin.port, spki: Codec.b64e(uri.pin.spkiSha256),
                                    sid: Codec.b64e(uri.pin.serverPub), keyAlias: alias, deviceName: name)
            store.clear()
            VaultKey.delete()
            ApprovalKey.delete()
            try store.save(rec)
            pairing = rec
            message = "Paired."
            startPolling()
        }
    }

    /// The first connection to a local host triggers the system's Local Network prompt and fails at once, before any
    /// byte is sent (so the single-use pairing token is untouched). Retry for a while so the user can answer it.
    private static func retryingWhileLocalNetworkPending(_ attempt: () async throws -> Void) async throws {
        let deadline = Date().addingTimeInterval(60)
        while true {
            do { return try await attempt() } catch let e as URLError where e.code == .notConnectedToInternet && Date() < deadline {
                try await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// The server answers "unauthorized" to a device it does not know (revoked or removed): drop the stale pairing.
    @discardableResult
    private func forgetIfRevoked(_ error: Error) -> Bool {
        guard pairing != nil, let e = error as? ServerError, e.code == "unauthorized" else { return false }
        forget()
        message = "The server removed this device, so it was forgotten. Pair again to reconnect."
        return true
    }

    func forget() {
        if let p = pairing { DeviceKey.delete(alias: p.keyAlias) }
        VaultKey.delete()
        ApprovalKey.delete()
        store?.clear()
        pollTask?.cancel()
        pairing = nil; requests = []; scripts = nil; status = nil; connected = nil; results = []; message = nil
    }

    // MARK: Checking

    func refresh() {
        op("Connecting to server...") { [self] in
            guard let p = pairing else { return }
            let c = try client(p)
            do {
                let listing = try await c.list()
                let s = try await c.scripts()
                requests = listing.requests
                scripts = s
                if let st = try? await c.status() { status = st }
                connected = true
            } catch {
                // A refusal means the server answered; anything else (timeout, wrong identity, bad reply) means it did not count.
                connected = error is ServerError
                throw error
            }
        }
    }

    /// Called when the app comes to the foreground: (re)connects or confirms the connection, unless something is
    /// running, and refreshes the server status every few seconds until `onPause`.
    func onResume() {
        if pairing != nil, busy == nil, Date().timeIntervalSince(lastCheck) >= 3 {
            lastCheck = Date()
            refresh()
        }
        startPolling()
    }

    /// (Re)starts the quiet status loop. Also called after pairing, because `forget` stops it.
    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollStatus()
                try? await Task.sleep(for: Self.statusInterval)
            }
        }
    }

    func onPause() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// Quiet: no busy spinner and no message, so it never gets in the way of an unlock.
    /// The last failure was "cannot reach the server": the poll clears it and loads what the failed check missed.
    private var connectionIssue = false

    private func pollStatus() async {
        guard let p = pairing, busy == nil, let c = try? client(p) else { return }
        do {
            let st = try await c.status()
            status = st
            connected = true
            // Connected but nothing loaded yet (just paired, or the first refresh failed): load it without a click.
            if (scripts == nil || connectionIssue), busy == nil {
                let listing = try await c.list()
                scripts = try await c.scripts()
                requests = listing.requests
                if connectionIssue { message = nil; connectionIssue = false }
            }
        } catch {
            if Task.isCancelled { return }
            if forgetIfRevoked(error) { return }
            connected = error is ServerError
        }
    }

    // MARK: Scripts

    /// Starts a script the server lists, then polls until nothing is queued or running. A `biometricProtection`
    /// script first gets a challenge from the server, which the biometric-bound approval key signs; that prompt
    /// is the confirmation, so the UI shows no extra dialog for it.
    func runScript(_ script: ScriptView) {
        op("Running script...") { [self] in
            guard let p = pairing else { return }
            let c = try client(p)
            if script.biometricProtection {
                if let why = Biometrics.unavailableReason() { throw KeySecurityError(why) }
                let challenge: ScriptChallenge
                do {
                    challenge = try await c.scriptChallenge(script.name)
                } catch let e as ServerError where e.code == "approval_required" {
                    // First protected script on this device: register the biometric-bound key, then ask again.
                    try await c.registerApprovalKey(spki: ApprovalKey.spki())
                    challenge = try await c.scriptChallenge(script.name)
                }
                let ctx = try await Biometrics.authenticate(reason: "Run \(script.label) on \(p.host)")
                let sig = try ApprovalKey.sign(challenge.message, context: ctx)
                try await c.runScript(script.name, challenge: challenge, approvalSig: sig)
            } else {
                try await c.runScript(script.name)
            }
            for _ in 0..<120 {
                let s = try await c.scripts()
                scripts = s
                if !s.scripts.contains(where: \.busy) { return }
                try await Task.sleep(for: .seconds(2))
            }
        }
    }

    // MARK: Vault

    /// Stores `passphrases` (uuid -> raw bytes, taken over and wiped) in the vault behind a biometric.
    func enroll(drives: [DriveInfo], passphrases: [String: Data]) {
        op("Saving passphrases...") { [self] in
            let fresh = try passphrases.map { PasswordEntry(uuid: try ServerClient.parseUuid($0.key), passphrase: $0.value) }
            var existing: [PasswordEntry] = []
            defer { (existing + fresh).forEach { $0.wipe() } }
            guard let p = pairing else { return }
            let store = try requireStore()
            if let why = Biometrics.unavailableReason() { throw KeySecurityError(why) }
            let blob = store.readVault()
            // A vault whose key is gone (biometrics changed) can never be opened again; start over.
            if blob != nil, !VaultKey.exists { store.clearVault(); pairing?.drives = [] }
            let key = try await VaultKey.get(reason: "Save passphrases for \(p.host)", createIfMissing: true)
            if let blob = store.readVault() {
                existing = try VaultFormat.open(key: key, serverPub: p.serverPub, blob: blob)
            }
            let merged = existing.filter { e in !fresh.contains { $0.uuid == e.uuid } } + fresh
            try store.writeVault(VaultFormat.seal(key: key, serverPub: p.serverPub, entries: merged))
            var rec = pairing ?? p
            rec.drives = rec.drives.filter { d in !drives.contains { $0.luksUuid == d.uuid } } +
                drives.filter { passphrases[$0.luksUuid] != nil }.map { EnrolledDrive(uuid: $0.luksUuid, label: $0.label) }
            try store.save(rec)
            pairing = rec
            message = "Saved."
        }
    }

    func unlock(_ request: RequestView) {
        op("Unlocking drives...") { [self] in
            guard let p = pairing else { return }
            let store = try requireStore()
            let c = try client(p)
            // Always act on a fresh, verified listing: its nonce is what the approval is bound to.
            let listing = try await c.list()
            guard let req = listing.requests.first(where: { $0.reqId == request.reqId }) else {
                requests = listing.requests
                message = "That request is gone. Refreshed."
                return
            }
            let wanted = req.drives.filter { d in p.drives.contains { $0.uuid == d.luksUuid } }
            if wanted.isEmpty {
                requests = listing.requests
                message = "No passphrase is saved for these drives."
                return
            }
            guard let blob = store.readVault(), VaultKey.exists else { throw VaultInvalidated() }
            let key = try await VaultKey.get(reason: "Unlock \(wanted.map { $0.label }.joined(separator: ", ")) on \(p.host)", createIfMissing: false)
            let all = try VaultFormat.open(key: key, serverPub: p.serverPub, blob: blob)
            // Release only passphrases for drives this request asks for AND that were enrolled for this server.
            let wantedRaw = try wanted.map { try ServerClient.parseUuid($0.luksUuid) }
            let chosen = all.filter { e in wantedRaw.contains(e.uuid) }
            all.filter { e in !chosen.contains { $0 === e } }.forEach { $0.wipe() }
            defer { chosen.forEach { $0.wipe() } }
            results = try await c.approve(listing: listing, request: req, entries: chosen) // wipes `chosen`
            let after = try await c.list()
            let s = try await c.scripts()
            requests = after.requests
            scripts = s
            message = nil
        }
    }

    // MARK: Wake-on-LAN

    /// Broadcasts a Wake-on-LAN packet; a `newMac` is validated and saved first.
    func wake(newMac: String? = nil) {
        op("Sending Wake-on-LAN packet...") { [self] in
            guard var p = pairing else { return }
            if let newMac {
                guard let mac = WakeOnLan.normalize(newMac) else {
                    message = "That is not a MAC address (like aa:bb:cc:dd:ee:ff)."
                    return
                }
                p.mac = mac
                try requireStore().save(p)
                pairing = p
            }
            guard let mac = p.mac else { return }
            try await Task.detached { try WakeOnLan.send(mac) }.value
            message = "Wake-on-LAN packet sent. The server may take a minute to start."
        }
    }
}
