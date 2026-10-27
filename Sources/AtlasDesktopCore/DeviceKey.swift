import Foundation
import CryptoKit
import Security

public struct JWK: Codable, Equatable {
    public var kty = "EC"
    public var crv = "P-256"
    public var x: String
    public var y: String
    init(x963: Data) {
        x = Data(x963[1..<33]).b64u
        y = Data(x963[33..<65]).b64u
    }
}

public protocol DeviceKey {
    var publicJWK: JWK { get }
    /// ES256, IEEE P1363 (r||s), base64url without padding.
    func sign(_ message: Data) throws -> String
    /// ECDH with an uncompressed peer point (65 bytes); returns the 32-byte X coordinate.
    func ecdh(peerPoint: Data) throws -> Data
}

extension DeviceKey {
    func sign(_ message: String) throws -> String { try sign(Data(message.utf8)) }
}

/// CryptoKit key. Used by tests and as the Keychain-backed fallback when there is no Secure Enclave.
public struct SoftwareDeviceKey: DeviceKey {
    let signing: P256.Signing.PrivateKey
    let agreement: P256.KeyAgreement.PrivateKey

    public init(rawD: Data) throws {
        do {
            signing = try P256.Signing.PrivateKey(rawRepresentation: rawD)
            agreement = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawD)
        } catch { throw DesktopError.crypto("bad private key") }
    }
    public static func generate() -> SoftwareDeviceKey { try! SoftwareDeviceKey(rawD: P256.Signing.PrivateKey().rawRepresentation) }
    public init(privateJWKD d: String) throws {
        guard let raw = Data(b64u: d) else { throw DesktopError.crypto("bad jwk") }
        try self.init(rawD: raw)
    }
    var rawD: Data { signing.rawRepresentation }
    public var publicJWK: JWK { JWK(x963: signing.publicKey.x963Representation) }
    public func sign(_ message: Data) throws -> String {
        try signing.signature(for: message).rawRepresentation.b64u
    }
    public func ecdh(peerPoint: Data) throws -> Data {
        do {
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: peerPoint)
            return try agreement.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        } catch { throw DesktopError.crypto("ecdh failed") }
    }
}

/// Non-exportable Secure Enclave key (SecKey). Signing and ECDH on the same key.
public final class SecureEnclaveDeviceKey: DeviceKey {
    let priv: SecKey
    let pubPoint: Data

    init(priv: SecKey) throws {
        self.priv = priv
        guard let pub = SecKeyCopyPublicKey(priv),
              let ext = SecKeyCopyExternalRepresentation(pub, nil) as Data?, ext.count == 65
        else { throw DesktopError.crypto("no public key") }
        pubPoint = ext
    }

    public var publicJWK: JWK { JWK(x963: pubPoint) }

    public func sign(_ message: Data) throws -> String {
        var err: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(priv, .ecdsaSignatureMessageX962SHA256, message as CFData, &err) as Data?
        else { throw DesktopError.crypto("sign failed") }
        return try DER.toP1363(der).b64u
    }

    public func ecdh(peerPoint: Data) throws -> Data {
        var err: Unmanaged<CFError>?
        let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPublic]
        guard peerPoint.count == 65, let peer = SecKeyCreateWithData(peerPoint as CFData, attrs as CFDictionary, &err),
              let out = SecKeyCopyKeyExchangeResult(priv, .ecdhKeyExchangeStandard, peer, [:] as CFDictionary, &err) as Data?
        else { throw DesktopError.crypto("ecdh failed") }
        return out
    }

    static func tag(_ label: String) -> Data { Data(("net.atlasauth.desktop.key." + label).utf8) }

    static func load(label: String) -> SecureEnclaveDeviceKey? {
        let q: [CFString: Any] = [
            kSecClass: kSecClassKey, kSecAttrApplicationTag: tag(label), kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave, kSecReturnRef: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, let ref = item else { return nil }
        return try? SecureEnclaveDeviceKey(priv: ref as! SecKey)
    }

    static func create(label: String) -> SecureEnclaveDeviceKey? {
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, nil) else { return nil }
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag(label), kSecAttrAccessControl: ac] as [CFString: Any],
        ]
        var err: Unmanaged<CFError>?
        guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else { return nil }
        return try? SecureEnclaveDeviceKey(priv: k)
    }
}

public enum DeviceKeyFactory {
    static func softwareName(_ label: String) -> String { "devkey:" + label }

    /// Existing key (Secure Enclave first, then the Keychain-stored software key), else create one if asked.
    /// The software fallback is used only when there is no Secure Enclave.
    public static func open(label: String, secrets: SecretStore, create: Bool) -> DeviceKey? {
        if let k = SecureEnclaveDeviceKey.load(label: label) { return k }
        if let raw = secrets.get(softwareName(label)), let k = try? SoftwareDeviceKey(rawD: raw) { return k }
        guard create else { return nil }
        if let k = SecureEnclaveDeviceKey.create(label: label) { return k }
        let k = SoftwareDeviceKey.generate()
        guard (try? secrets.set(softwareName(label), k.rawD)) != nil else { return nil }
        return k
    }
}

enum DER {
    /// ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }) to 64-byte r||s.
    static func toP1363(_ der: Data) throws -> Data {
        let b = [UInt8](der)
        var i = 0
        func len() throws -> Int {
            guard i < b.count else { throw DesktopError.crypto("der") }
            let l = Int(b[i]); i += 1
            if l < 0x80 { return l }
            guard l == 0x81, i < b.count else { throw DesktopError.crypto("der") }
            let v = Int(b[i]); i += 1; return v
        }
        func int() throws -> [UInt8] {
            guard i < b.count, b[i] == 0x02 else { throw DesktopError.crypto("der") }
            i += 1
            let n = try len()
            guard i + n <= b.count else { throw DesktopError.crypto("der") }
            var v = Array(b[i..<(i + n)]); i += n
            while v.count > 32, v.first == 0 { v.removeFirst() }
            guard v.count <= 32 else { throw DesktopError.crypto("der") }
            return [UInt8](repeating: 0, count: 32 - v.count) + v
        }
        guard !b.isEmpty, b[0] == 0x30 else { throw DesktopError.crypto("der") }
        i = 1; _ = try len()
        let r = try int(), s = try int()
        return Data(r + s)
    }
}

// MARK: - Keychain secret store

public final class KeychainSecretStore: SecretStore {
    let service: String
    let useSystemKeychain: Bool
    public init(service: String = "net.atlasauth.desktop", useSystemKeychain: Bool = true) {
        self.service = service; self.useSystemKeychain = useSystemKeychain
    }

    @available(macOS, deprecated: 10.10)
    private func systemKeychain() -> SecKeychain? {
        guard useSystemKeychain else { return nil }
        var domain: SecKeychain?
        guard SecKeychainCopyDomainDefault(.system, &domain) == errSecSuccess else { return nil }
        return domain
    }

    private func base(_ key: String) -> [CFString: Any] {
        var q: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: key]
        if let kc = systemKeychain() { q[kSecUseKeychain] = kc; q[kSecMatchSearchList] = [kc] }
        return q
    }

    public func get(_ key: String) -> Data? {
        var q = base(key); q[kSecReturnData] = true; q[kSecMatchLimit] = kSecMatchLimitOne
        var out: CFTypeRef?
        return SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess ? out as? Data : nil
    }

    public func set(_ key: String, _ value: Data) throws {
        delete(key)
        var q = base(key)
        q[kSecValueData] = value
        q[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        // nil trusted list: any process may read, so the (unprivileged) login window agent can use items created by the root daemon.
        var access: SecAccess?
        if SecAccessCreate("Atlas desktop MFA" as CFString, nil, &access) == errSecSuccess, let a = access { q[kSecAttrAccess] = a }
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw DesktopError.storage("keychain add \(st)") }
    }

    public func delete(_ key: String) { SecItemDelete(base(key) as CFDictionary) }
}
