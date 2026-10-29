import CryptoKit
import Foundation
import LocalAuthentication

/// `0x01 || nonce[12] || AES-256-GCM(Seal plaintext format) || tag[16]`, AAD = `lp("hands/v1/vault", SHA-256(server key))`
/// so a blob cannot be moved between servers. The plaintext reuses the wire format: entries ascending by UUID,
/// zero padded to 256 bytes (the blob does not reveal how many drives or how long the passphrases are).
public enum VaultFormat {
    public static let version: UInt8 = 1

    static func aad(serverPub: Data) -> Data { Codec.lp(Data("hands/v1/vault".utf8), Codec.sha256(serverPub)) }

    /// Entries are NOT wiped here.
    public static func seal(key: SymmetricKey, serverPub: Data, entries: [PasswordEntry]) throws -> Data {
        var plain = try Seal.encodePlaintext(entries.sorted { Codec.compareUnsigned($0.uuid, $1.uuid) < 0 })
        defer { plain.wipe() }
        guard let combined = try AES.GCM.seal(plain, using: key, authenticating: aad(serverPub: serverPub)).combined else { throw ProtocolError() }
        return Data([version]) + combined
    }

    /// The caller wipes the returned entries.
    public static func open(key: SymmetricKey, serverPub: Data, blob: Data) throws -> [PasswordEntry] {
        guard blob.count >= 1 + 12 + 16, blob.first == version else { throw ProtocolError() }
        var plain: Data
        do {
            plain = try AES.GCM.open(AES.GCM.SealedBox(combined: blob.dropFirst()), using: key, authenticating: aad(serverPub: serverPub))
        } catch {
            throw ProtocolError()
        }
        defer { plain.wipe() }
        return try Seal.decodePlaintext(plain)
    }
}

/// The biometrics changed (or the Keychain item is otherwise gone), so the vault key no longer exists.
public struct VaultInvalidated: Error { public init() {} }

/// The vault key: 32 random bytes in a Keychain item that needs a fresh strong biometric to be read and is destroyed
/// when biometrics are re-enrolled. Each use asks for the biometric again.
public enum VaultKey {
    private static let account = "vault-key"

    public static var exists: Bool {
        let noUI = LAContext()
        noUI.interactionNotAllowed = true
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Keychain.service,
            kSecAttrAccount as String: account, kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: noUI,
        ]
        let status = SecItemCopyMatching(q as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    public static func delete() { try? Keychain.delete(account) }

    /// Creates the key if there is none (no prompt), then returns it after a biometric check.
    public static func get(reason: String, createIfMissing: Bool) async throws -> SymmetricKey {
        if createIfMissing, !exists {
            var err: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &err) else {
                throw KeySecurityError("This device cannot bind a key to biometrics.")
            }
            var bytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw ProtocolError() }
            var raw = Data(bytes)
            bytes = [UInt8](repeating: 0, count: 32)
            defer { raw.wipe() }
            try Keychain.write(account, raw, access: access)
        }
        let ctx = try await Biometrics.authenticate(reason: reason)
        do {
            guard let raw = try Keychain.read(account, context: ctx) else { throw VaultInvalidated() }
            return SymmetricKey(data: raw)
        } catch let e as KeychainError where e.status == errSecItemNotFound || e.status == errSecAuthFailed {
            delete()
            throw VaultInvalidated()
        }
    }
}
