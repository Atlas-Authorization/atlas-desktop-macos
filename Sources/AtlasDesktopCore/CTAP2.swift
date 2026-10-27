import CommonCrypto
import CryptoKit
import Foundation

// CTAP2 over CTAPHID for a USB security key: getInfo, PIN/UV auth protocols one and two, getAssertion and makeCredential.
// Written against FIDO CTAP 2.1 (https://fidoalliance.org/specs/fido-v2.1-ps-20210615/): command bytes (6.1-6.5), the PIN/UV auth
// protocols (6.5.6, 6.5.7), status codes (8.2). Verified against a software authenticator in the unit tests; not yet against hardware.

enum CTAP2 {
    static let cmdMakeCredential: UInt8 = 0x01, cmdGetAssertion: UInt8 = 0x02, cmdGetInfo: UInt8 = 0x04, cmdClientPIN: UInt8 = 0x06
    static let ok: UInt8 = 0x00, noCredentials: UInt8 = 0x2E, operationDenied: UInt8 = 0x27, keepaliveCancel: UInt8 = 0x2D, userActionTimeout: UInt8 = 0x2F
    static let pinInvalid: UInt8 = 0x31, pinBlocked: UInt8 = 0x32, pinAuthInvalid: UInt8 = 0x33, pinAuthBlocked: UInt8 = 0x34, pinNotSet: UInt8 = 0x35
    static let puatRequired: UInt8 = 0x36, credentialExcluded: UInt8 = 0x19, unsupportedAlgorithm: UInt8 = 0x26
    static let permMakeCredential: Int64 = 0x01, permGetAssertion: Int64 = 0x02
}

enum CTAP2Error: Error, Equatable {
    case status(UInt8)
    case malformed(String)
    case pinRequired
    case pinInvalid(retriesLeft: Int?)
    case pinBlocked
    case noUserVerification
    case unsupported(String)
    case noKey
}

// MARK: - PIN/UV auth protocols

/// Protocol one (AES-256-CBC with a zero IV, SHA-256 key derivation, 16-byte MACs) and two (HKDF keys, random IV, 32-byte MACs).
struct PinUvProtocol {
    let version: Int
    private let hmacKey: Data, aesKey: Data

    /// ECDH with the authenticator's key agreement key. Returns the protocol state and our public key as a COSE_Key.
    static func negotiate(version: Int, authenticatorKey: CBOR) throws -> (PinUvProtocol, CBOR) {
        guard version == 1 || version == 2 else { throw CTAP2Error.unsupported("pinUvAuthProtocol \(version)") }
        guard let x = authenticatorKey[-2]?.dataValue, let y = authenticatorKey[-3]?.dataValue, x.count == 32, y.count == 32,
              let peer = try? P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y) else { throw CTAP2Error.malformed("keyAgreement") }
        let mine = P256.KeyAgreement.PrivateKey()
        let z = try mine.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }   // the 32-byte x coordinate
        let proto: PinUvProtocol
        if version == 1 {
            let k = Data(SHA256.hash(data: z)); proto = PinUvProtocol(version: 1, hmacKey: k, aesKey: k)
        } else {
            func derive(_ info: String) -> Data {
                HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: z), salt: Data(repeating: 0, count: 32), info: Data(info.utf8), outputByteCount: 32).withUnsafeBytes { Data($0) }
            }
            proto = PinUvProtocol(version: 2, hmacKey: derive("CTAP2 HMAC key"), aesKey: derive("CTAP2 AES key"))
        }
        let raw = mine.publicKey.x963Representation
        let cose = CBOR.map([(.int(1), .int(2)), (.int(3), .int(-25)), (.int(-1), .int(1)), (.int(-2), .bytes(raw.subdata(in: 1..<33))), (.int(-3), .bytes(raw.subdata(in: 33..<65)))])
        return (proto, cose)
    }

    private func cbc(_ op: Int, _ key: Data, _ iv: Data, _ input: Data) throws -> Data {
        guard input.count % 16 == 0 else { throw CTAP2Error.malformed("block size") }
        var out = Data(count: input.count + 16), n = 0
        let outLen = out.count
        let rc = out.withUnsafeMutableBytes { o in input.withUnsafeBytes { i in key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
            CCCrypt(CCOperation(op), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, key.count, v.baseAddress, i.baseAddress, input.count, o.baseAddress, outLen, &n)
        } } } }
        guard rc == kCCSuccess else { throw CTAP2Error.malformed("aes") }
        return out.prefix(n)
    }

    func encrypt(_ data: Data) throws -> Data {
        if version == 1 { return try cbc(kCCEncrypt, aesKey, Data(repeating: 0, count: 16), data) }
        let iv = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        return iv + (try cbc(kCCEncrypt, aesKey, iv, data))
    }
    func decrypt(_ data: Data) throws -> Data {
        if version == 1 { return try cbc(kCCDecrypt, aesKey, Data(repeating: 0, count: 16), data) }
        guard data.count > 16 else { throw CTAP2Error.malformed("short ciphertext") }
        return try cbc(kCCDecrypt, aesKey, data.prefix(16), data.dropFirst(16))
    }
    /// authenticate(key, message): HMAC-SHA-256, truncated to 16 bytes in protocol one.
    static func authenticate(version: Int, key: Data, message: Data) -> Data {
        let mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key.prefix(32))))
        return version == 1 ? mac.prefix(16) : mac
    }
    func authenticate(message: Data) -> Data { Self.authenticate(version: version, key: hmacKey, message: message) }
}

// MARK: - info

struct CTAP2Info {
    var versions: [String] = [], protocols: [Int] = []
    var options: [String: Bool] = [:]
    var aaguid = Data()
    var pinSet: Bool? { options["clientPin"] }              // nil: no PIN support; false: supported, not set
    var supportsPinUvAuthToken: Bool { options["pinUvAuthToken"] == true }
    var hasBuiltInUV: Bool { options["uv"] == true }

    init(_ c: CBOR) {
        versions = c[1]?.arrayValue?.compactMap { $0.textValue } ?? []
        aaguid = c[3]?.dataValue ?? Data()
        if case .map(let m)? = c[4] { for (k, v) in m { if let k = k.textValue, let b = v.boolValue { options[k] = b } } }
        protocols = c[6]?.arrayValue?.compactMap { $0.intValue.map(Int.init) } ?? [1]
    }
}

// MARK: - the client

/// Talks CTAP2 to one key on one channel. Calls block: run them off the main thread.
final class CTAP2Client {
    let channel: CTAPHIDChannel
    private(set) var info = CTAP2Info(.map([]))
    var onKeepalive: (UInt8) -> Void = { _ in }
    var shouldCancel: () -> Bool = { false }

    init(channel: CTAPHIDChannel) { self.channel = channel }

    func command(_ cmd: UInt8, _ params: CBOR?, timeout: TimeInterval) throws -> CBOR? {
        let body = params.map { $0.encode() } ?? Data()
        let r = try channel.cbor(Data([cmd]) + body, timeout: timeout, keepalive: onKeepalive, shouldCancel: shouldCancel)
        guard let status = r.first else { throw CTAP2Error.malformed("empty response") }
        guard status == CTAP2.ok else { throw CTAP2Error.status(status) }
        if r.count == 1 { return nil }
        do { return try CBOR.decode(r.dropFirst()) } catch { throw CTAP2Error.malformed("cbor: \(error)") }
    }

    func loadInfo() throws {
        info = CTAP2Info(try command(CTAP2.cmdGetInfo, nil, timeout: 5) ?? .map([]))
        guard info.versions.contains(where: { $0.hasPrefix("FIDO_2") }) else { throw CTAP2Error.unsupported("not a CTAP2 key") }
    }

    /// PIN normalisation and limits from CTAP 6.5.1: NFC, UTF-8, at least 4 code points, at most 63 bytes.
    static func pinBytes(_ pin: String) throws -> Data {
        let n = pin.precomposedStringWithCanonicalMapping
        guard n.unicodeScalars.count >= 4, n.utf8.count <= 63 else { throw CTAP2Error.pinInvalid(retriesLeft: nil) }
        return Data(n.utf8)
    }

    /// A pinUvAuthToken for `permissions` (and `rpId`) obtained with the PIN.
    func token(pin: String, permissions: Int64, rpId: String) throws -> (token: Data, version: Int) {
        let version = info.protocols.contains(2) ? 2 : 1
        let ka = try command(CTAP2.cmdClientPIN, .map([(.int(1), .int(Int64(version))), (.int(2), .int(2))]), timeout: 10)
        guard let key = ka?[1] else { throw CTAP2Error.malformed("keyAgreement") }
        let (proto, platformKey) = try PinUvProtocol.negotiate(version: version, authenticatorKey: key)
        let hash = Data(SHA256.hash(data: try Self.pinBytes(pin))).prefix(16)
        let pinHashEnc = try proto.encrypt(Data(hash))
        var req: [(CBOR, CBOR)] = [(.int(1), .int(Int64(version))), (.int(3), platformKey), (.int(6), .bytes(pinHashEnc))]
        if info.supportsPinUvAuthToken { req += [(.int(2), .int(9)), (.int(9), .int(permissions)), (.int(10), .text(rpId))] }
        else { req += [(.int(2), .int(5))] }   // legacy getPinToken: permissions are mc + ga
        let resp: CBOR?
        do { resp = try command(CTAP2.cmdClientPIN, .map(req), timeout: 15) }
        catch CTAP2Error.status(let s) where s == CTAP2.pinInvalid { throw CTAP2Error.pinInvalid(retriesLeft: retries()) }
        catch CTAP2Error.status(let s) where s == CTAP2.pinBlocked || s == CTAP2.pinAuthBlocked { throw CTAP2Error.pinBlocked }
        guard let enc = resp?[2]?.dataValue else { throw CTAP2Error.malformed("pinUvAuthToken") }
        let token = try proto.decrypt(enc)
        guard token.count == 16 || token.count == 32, version == 1 || token.count == 32 else { throw CTAP2Error.malformed("token length") }
        return (token, version)
    }

    func retries() -> Int? {
        guard let r = try? command(CTAP2.cmdClientPIN, .map([(.int(2), .int(1))]), timeout: 5), let n = r?[3]?.intValue else { return nil }
        return Int(n)
    }

    private static func descriptor(_ id: Data) -> CBOR { .map([(.text("type"), .text("public-key")), (.text("id"), .bytes(id))]) }

    /// How to satisfy the user-verification request: a PIN token, built-in UV, or nothing.
    enum VerificationPlan { case pin, builtIn, none }
    func plan(userVerification: String) throws -> VerificationPlan {
        switch userVerification {
        case "required":
            if info.pinSet == true { return .pin }
            if info.hasBuiltInUV { return .builtIn }
            throw CTAP2Error.noUserVerification   // the key has no PIN set and no biometric: it cannot verify the user
        case "preferred": return info.pinSet == true ? .pin : (info.hasBuiltInUV ? .builtIn : .none)
        default: return .none
        }
    }

    func getAssertion(rpId: String, clientDataHash: Data, allow: [Data], pin: String?, builtInUV: Bool = false, timeout: TimeInterval) throws -> (credentialId: Data, authData: Data, signature: Data) {
        var req: [(CBOR, CBOR)] = [(.int(1), .text(rpId)), (.int(2), .bytes(clientDataHash))]
        if !allow.isEmpty { req.append((.int(3), .array(allow.map(Self.descriptor)))) }
        if builtInUV { req.append((.int(5), .map([(.text("uv"), .bool(true))]))) }   // the key's own biometric (deprecated in 2.1 but understood by 2.0 and 2.1 keys)
        if let pin = pin {
            let t = try token(pin: pin, permissions: CTAP2.permGetAssertion, rpId: rpId)
            req += [(.int(6), .bytes(PinUvProtocol.authenticate(version: t.version, key: t.token, message: clientDataHash))), (.int(7), .int(Int64(t.version)))]
        }
        guard let r = try command(CTAP2.cmdGetAssertion, .map(req), timeout: timeout),
              let authData = r[2]?.dataValue, let sig = r[3]?.dataValue else { throw CTAP2Error.malformed("assertion") }
        // The credential field may be left out when the allow list names a single credential.
        guard let id = r[1]?["id"]?.dataValue ?? (allow.count == 1 ? allow[0] : nil) else { throw CTAP2Error.malformed("credential") }
        return (id, authData, sig)
    }

    func makeCredential(clientDataHash: Data, rpId: String, rpName: String, user: PasskeyCreation, pin: String?, timeout: TimeInterval) throws -> (credentialId: Data, attestationObject: Data) {
        var req: [(CBOR, CBOR)] = [
            (.int(1), .bytes(clientDataHash)),
            (.int(2), .map([(.text("id"), .text(rpId)), (.text("name"), .text(rpName))])),
            (.int(3), .map([(.text("id"), .bytes(user.userId)), (.text("name"), .text(user.userName)), (.text("displayName"), .text(user.userDisplayName))])),
            (.int(4), .array(user.algorithms.map { .map([(.text("alg"), .int(Int64($0))), (.text("type"), .text("public-key"))]) })),
        ]
        if !user.exclude.isEmpty { req.append((.int(5), .array(user.exclude.map(Self.descriptor)))) }
        if info.options["rk"] == true { req.append((.int(7), .map([(.text("rk"), .bool(true))]))) }
        if let pin = pin {
            let t = try token(pin: pin, permissions: CTAP2.permMakeCredential, rpId: rpId)
            req += [(.int(8), .bytes(PinUvProtocol.authenticate(version: t.version, key: t.token, message: clientDataHash))), (.int(9), .int(Int64(t.version)))]
        }
        guard let r = try command(CTAP2.cmdMakeCredential, .map(req), timeout: timeout), let authData = r[2]?.dataValue else { throw CTAP2Error.malformed("attestation") }
        guard let id = Self.credentialId(authData) else { throw CTAP2Error.malformed("authenticator data") }
        // The server only needs the credential and its AAGUID, so the attestation statement is dropped (fmt "none").
        let object = CBOR.map([(.text("fmt"), .text("none")), (.text("attStmt"), .map([])), (.text("authData"), .bytes(authData))]).encode()
        return (id, object)
    }

    /// Credential id from attested credential data: rpIdHash(32) flags(1) counter(4) aaguid(16) idLen(2) id.
    static func credentialId(_ authData: Data) -> Data? {
        let b = [UInt8](authData)
        guard b.count >= 55, b[32] & 0x40 != 0 else { return nil }
        let n = Int(b[53]) << 8 | Int(b[54])
        guard b.count >= 55 + n else { return nil }
        return Data(b[55..<55 + n])
    }
}

// MARK: - the PasskeyAuthenticator

/// A USB security key through CTAP2 over HID. Works where AuthenticationServices cannot: in the login window and in
/// authorization plugins. `openDevices` yields the transports of the keys currently plugged in.
public final class CTAP2Authenticator: PasskeyAuthenticator {
    let openDevices: () throws -> [CTAPHIDTransport]
    let askPIN: (_ retriesLeft: Int?) async -> String?
    let status: (String) -> Void
    let pollInterval: TimeInterval

    init(openDevices: @escaping () throws -> [CTAPHIDTransport], pin: @escaping (_ retriesLeft: Int?) async -> String?, status: @escaping (String) -> Void = { _ in }, pollInterval: TimeInterval = 0.5) {
        self.openDevices = openDevices; self.askPIN = pin; self.status = status; self.pollInterval = pollInterval
    }

    public var available: Bool { true }

    /// Waits for a key (up to `timeout`), asking the person to plug one in.
    private func clients(timeout: TimeInterval) async throws -> [CTAP2Client] {
        let deadline = Date().addingTimeInterval(timeout)
        var told = false
        while Date() < deadline {
            if Task.isCancelled { throw PasskeyError.cancelled }
            let found = (try? openDevices()) ?? []
            var out: [CTAP2Client] = []
            for t in found {
                let ch = CTAPHIDChannel(t)
                let c = CTAP2Client(channel: ch)
                if (try? ch.open()) != nil, (try? c.loadInfo()) != nil { out.append(c) } else { t.close() }
            }
            if !out.isEmpty { return out }
            if !told { status("Insert your security key."); told = true }
            try? await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
        }
        throw PasskeyError.failed("no security key found")
    }

    private func run<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, Error>) in
            DispatchQueue.global(qos: .userInitiated).async { c.resume(with: Result { try work() }) }
        }
    }

    private func map(_ e: Error) -> Error {
        switch e {
        case CTAP2Error.status(let s) where s == CTAP2.operationDenied || s == CTAP2.keepaliveCancel || s == CTAP2.userActionTimeout: return PasskeyError.cancelled
        case CTAP2Error.pinBlocked: return PasskeyError.failed("PIN blocked on the key")
        case CTAP2Error.noUserVerification: return PasskeyError.failed("this key has no PIN or biometric to verify you")
        case CTAPHIDError.cancelled: return PasskeyError.cancelled
        default: return e is PasskeyError ? e : PasskeyError.failed("security key: \(e)")
        }
    }

    public func assertion(_ request: PasskeyRequest, clientData: Data) async throws -> RawAssertion {
        let hash = Data(SHA256.hash(data: clientData))
        let allow = request.allow.map { $0.id }
        let timeout = TimeInterval(request.timeoutMs) / 1000
        let devices = try await clients(timeout: timeout)
        defer { devices.forEach { $0.channel.transport.close() } }
        var lastError: Error = PasskeyError.failed("no matching key")
        for dev in devices {
            dev.shouldCancel = { Task.isCancelled }
            dev.onKeepalive = { [status] s in if s == CTAPHID.keepaliveUPNeeded { status("Touch your security key.") } }
            do {
                let plan = try dev.plan(userVerification: request.userVerification)
                var pin: String?
                var attempts = 0
                while true {
                    if plan == .pin, pin == nil {
                        guard let p = await askPIN(nil) else { throw PasskeyError.cancelled }
                        pin = p
                    }
                    do {
                        let usePin = pin
                        let bio = plan == .builtIn
                        let r = try await run { try dev.getAssertion(rpId: request.rpId, clientDataHash: hash, allow: allow, pin: usePin, builtInUV: bio, timeout: timeout) }
                        return RawAssertion(credentialId: r.credentialId, authenticatorData: r.authData, signature: r.signature, clientDataJSON: clientData)
                    } catch CTAP2Error.pinInvalid(let left) {
                        attempts += 1
                        guard attempts < 3, left != 0, let p = await askPIN(left) else { throw PasskeyError.failed("wrong PIN") }
                        pin = p
                    }
                }
            } catch CTAP2Error.status(let s) where s == CTAP2.noCredentials {
                lastError = PasskeyError.failed("this key does not hold a registered passkey")
            } catch { lastError = map(error); if lastError as? PasskeyError == .cancelled { throw lastError } }
        }
        throw lastError
    }

    public func registration(_ creation: PasskeyCreation, clientData: Data) async throws -> RawAttestation {
        let hash = Data(SHA256.hash(data: clientData))
        let timeout = TimeInterval(creation.timeoutMs) / 1000
        let devices = try await clients(timeout: timeout)
        defer { devices.forEach { $0.channel.transport.close() } }
        guard let dev = devices.first else { throw PasskeyError.failed("no security key found") }
        dev.shouldCancel = { Task.isCancelled }
        dev.onKeepalive = { [status] s in if s == CTAPHID.keepaliveUPNeeded { status("Touch your security key.") } }
        do {
            let plan = try dev.plan(userVerification: creation.userVerification)
            var pin: String?
            if plan == .pin { guard let p = await askPIN(nil) else { throw PasskeyError.cancelled }; pin = p }
            var attempts = 0
            while true {
                do {
                    let usePin = pin
                    let r = try await run { try dev.makeCredential(clientDataHash: hash, rpId: creation.rpId, rpName: creation.rpName, user: creation, pin: usePin, timeout: timeout) }
                    return RawAttestation(credentialId: r.credentialId, attestationObject: r.attestationObject, clientDataJSON: clientData, transports: ["usb"])
                } catch CTAP2Error.pinInvalid(let left) {
                    attempts += 1
                    guard attempts < 3, left != 0, let p = await askPIN(left) else { throw PasskeyError.failed("wrong PIN") }
                    pin = p
                }
            }
        } catch CTAP2Error.status(let s) where s == CTAP2.credentialExcluded {
            throw PasskeyError.failed("this key is already registered")
        } catch { throw map(error) }
    }
}
