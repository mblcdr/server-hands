---
title: "iPhone, iPad and Mac app"
description: "Build, sign and run the SwiftUI app for iOS, iPadOS and macOS."
slug: "apple-app"
weight: 35
toc: true
---

One SwiftUI app, one target, three platforms: iPhone and iPad (iOS 16+) and Mac (macOS 13+, native, not Catalyst). It does the same as the Android app: pair by QR or pasted link, show the machine and drives, unlock with a biometric, run scripts, send Wake-on-LAN. The protocol is the same ([protocol.md](../protocol/)); the code is a Swift port (HPKE is implemented on CryptoKit primitives because CryptoKit's own HPKE needs iOS 17), tested against the same vectors and against the real Rust daemon.

## Layout

```
app/apple/
  project.yml        XcodeGen spec; the .xcodeproj is generated and not committed
  Kit/               Swift package ServerHandsKit: codec, HPKE seal, signatures, pinned TLS client, vault, keys, storage
  App/               SwiftUI app (model, views, QR scanner on iOS)
```

## Build

You need Xcode 15.3 or later and [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).

```sh
cd app/apple
xcodegen generate
open ServerHands.xcodeproj
```

Pick an iPhone, iPad or "My Mac" destination. For a device or a signed Mac build set your team once:

```sh
echo 'DEVELOPMENT_TEAM = ABCDE12345' > Signing.local.xcconfig   # untracked
```

The Keychain and Secure Enclave need a signed build. An unsigned Mac build starts, but pairing fails with a Keychain entitlement error.

Tests for the package (no Xcode project needed):

```sh
cd app/apple/Kit
swift test
```

This runs `protocol/vectors/v1.json` (positive and negative, including the ciphertext sealed by Rust and the one sealed by Kotlin). If `server/target/debug/examples/fake_server` exists (`cargo build -p handsd --example fake_server` in `server/`), it also pairs, lists, approves and runs scripts against the real daemon over pinned TLS 1.3, and checks that a wrong pin, an unpaired device and a wrong server identity are refused.

## Keys on Apple platforms

| Android | Apple |
|---|---|
| Device key `D` in the Keystore (StrongBox if present) | ECDSA P-256 in the **Secure Enclave**, stored as an opaque blob in the Keychain, `WhenUnlockedThisDeviceOnly` |
| Approval key `A`, per-use strong biometric | Secure Enclave P-256 with `.biometryCurrentSet`; every signature follows a fresh Face ID / Touch ID check |
| Vault key (AES-256-GCM, per-use biometric) | 32 random bytes in a Keychain item with `.biometryCurrentSet`, read only after a fresh biometric; CryptoKit AES-GCM with the same vault format |
| Pinned TLS | `URLSession` delegate that accepts only a leaf certificate whose SPKI hashes to the pin; TLS 1.3 minimum; no proxy |

Enrolling a new fingerprint or face invalidates the vault key and the approval key, like on Android. Debug builds accept software-backed device keys so the simulator works; release builds refuse them. The biometric-protected scripts need a real Secure Enclave, so they do not work in the simulator.

## Known limits

- **Wake-on-LAN on iOS** broadcasts a UDP packet. Apple requires the *Multicast Networking* entitlement (`com.apple.developer.networking.multicast`, granted on request) for broadcast on iOS. Without it the send can be refused on a device. It works on the Mac. The entitlement is not in the project because an unapproved one breaks signing.
- **QR scanning** is iOS and iPadOS only. On the Mac, paste the `hands://` link printed by `handsctl pair`.
- Passphrases are typed into a SwiftUI `SecureField`, which is a `String`. The app converts it to bytes and clears the field at once, but unlike the Android app it cannot avoid the string entirely.
- No App Store or TestFlight pipeline yet; builds are from source.
