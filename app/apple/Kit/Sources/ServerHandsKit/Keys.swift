import CryptoKit
import Foundation
import LocalAuthentication
import Security

public struct KeySecurityError: Error, LocalizedError {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

/// Software P-256 key. Tests, and simulators / Macs without a Secure Enclave when the build allows it.
public struct SoftwareDeviceSigner: DeviceSigner, @unchecked Sendable {
    private let key: P256.Signing.PrivateKey

    public init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) { self.key = key }

    public var spki: Data { key.publicKey.derRepresentation }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message).derRepresentation }
    var raw: Data { key.rawRepresentation }
    init(raw: Data) throws { key = try P256.Signing.PrivateKey(rawRepresentation: raw) }
}

public struct SecureEnclaveDeviceSigner: DeviceSigner, @unchecked Sendable {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    init(key: SecureEnclave.P256.Signing.PrivateKey) { self.key = key }

    public var spki: Data { key.publicKey.derRepresentation }
    public func sign(_ message: Data) throws -> Data { try key.signature(for: message).derRepresentation }
}

/// Plain Keychain items under one service. Everything is `ThisDeviceOnly`: nothing syncs, nothing is in backups.
enum Keychain {
    static let service = "dev.serverhands.app"

    private static func base(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    static func read(_ account: String, context: LAContext? = nil) throws -> Data? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context { q[kSecUseAuthenticationContext as String] = context }
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw KeychainError(status) }
        return data
    }

    static func write(_ account: String, _ data: Data, access: SecAccessControl?) throws {
        try delete(account)
        var q = base(account)
        q[kSecValueData as String] = data
        if let access { q[kSecAttrAccessControl as String] = access } else { q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly }
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status) }
    }

    static func delete(_ account: String) throws {
        let status = SecItemDelete(base(account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status) }
    }
}

public struct KeychainError: Error, LocalizedError {
    public let status: OSStatus
    init(_ status: OSStatus) { self.status = status }
    public var errorDescription: String? {
        if status == errSecMissingEntitlement {
            return "The keychain is not available to this build. Set a development team in Xcode so the app is signed."
        }
        return (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error \(status)."
    }
}

/// The device identity `D`: ECDSA P-256 in the Secure Enclave, never exportable. It signs without a prompt (the
/// Keychain item is only readable while the device is unlocked, like `setUnlockedDeviceRequired` on Android).
public enum DeviceKey {
    private static let seTag: UInt8 = 1
    private static let softTag: UInt8 = 2

    public static func account(for alias: String) -> String { "device-key." + alias }

    public static func load(alias: String) throws -> DeviceSigner? {
        guard let blob = try Keychain.read(account(for: alias)), let tag = blob.first else { return nil }
        let body = blob.dropFirst()
        switch tag {
        case seTag: return SecureEnclaveDeviceSigner(key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: body))
        case softTag: return try SoftwareDeviceSigner(raw: Data(body))
        default: return nil
        }
    }

    /// Creates the key. Without a Secure Enclave this fails unless `allowSoftware` (debug builds, simulators).
    public static func create(alias: String, allowSoftware: Bool) throws -> DeviceSigner {
        if SecureEnclave.isAvailable {
            let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)
            let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access!)
            try Keychain.write(account(for: alias), Data([seTag]) + key.dataRepresentation, access: nil)
            return SecureEnclaveDeviceSigner(key: key)
        }
        guard allowSoftware else { throw KeySecurityError("This device has no Secure Enclave, so the device key cannot be protected.") }
        let signer = SoftwareDeviceSigner()
        try Keychain.write(account(for: alias), Data([softTag]) + signer.raw, access: nil)
        return signer
    }

    public static func delete(alias: String) { try? Keychain.delete(account(for: alias)) }
}

/// Fresh biometric check. The returned context is already authenticated, so using a key or Keychain item with it
/// does not prompt a second time. There is no passcode fallback.
public enum Biometrics {
    public struct Cancelled: Error {}

    /// nil when a biometric is ready, otherwise a message for the user.
    public static func unavailableReason() -> String? {
        let ctx = LAContext()
        var err: NSError?
        if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err) { return nil }
        switch (err.map { LAError.Code(rawValue: $0.code) }) ?? nil {
        case .biometryNotEnrolled: return "Set up Face ID or Touch ID in system settings first."
        case .biometryNotAvailable: return "This device has no biometric sensor."
        case .biometryLockout: return "Biometrics are locked. Unlock the device with its passcode first."
        default: return "Biometric authentication is not available."
        }
    }

    public static func authenticate(reason: String) async throws -> LAContext {
        let ctx = LAContext()
        ctx.localizedCancelTitle = "Cancel"
        ctx.touchIDAuthenticationAllowableReuseDuration = 0
        do {
            guard try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else { throw Cancelled() }
            return ctx
        } catch let e as LAError {
            switch e.code {
            case .userCancel, .systemCancel, .appCancel: throw Cancelled()
            default: throw KeySecurityError("Authentication failed: \(e.localizedDescription)")
            }
        }
    }
}

/// `A`: signs script approvals. Needs a fresh biometric for every signature and dies if biometrics are re-enrolled.
public enum ApprovalKey {
    private static let account = "approval-key"

    private static func access() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let a = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else {
            throw KeySecurityError("This device cannot bind a key to biometrics.")
        }
        return a
    }

    public static func delete() { try? Keychain.delete(account) }

    /// SPKI DER of the public key, creating the key first if needed.
    public static func spki() throws -> Data {
        if let blob = try Keychain.read(account) {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob).publicKey.derRepresentation
        }
        guard SecureEnclave.isAvailable else { throw KeySecurityError("This device cannot enforce biometric key use in secure hardware.") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access())
        try Keychain.write(account, key.dataRepresentation, access: nil)
        return key.publicKey.derRepresentation
    }

    /// `context` comes from `Biometrics.authenticate`. Throws `KeySecurityError` when biometrics changed since creation.
    public static func sign(_ message: Data, context: LAContext) throws -> Data {
        guard let blob = try Keychain.read(account) else { throw KeySecurityError("The approval key is gone.") }
        do {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
            return try key.signature(for: message).derRepresentation
        } catch {
            throw KeySecurityError("Biometrics changed, so the approval key can no longer be used. On the server run: sudo handsctl reset-approval-key <device-id>, then try again.")
        }
    }
}
