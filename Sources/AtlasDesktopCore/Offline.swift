import Foundation
import CryptoKit

public struct OfflineBundle: Codable, Equatable {
    public var bundleId: String
    public var generation: Int64
    public var issuedAt: Int64
    public var expiresAt: Int64
    public var sealed: String
    public var mac: String
    enum CodingKeys: String, CodingKey {
        case bundleId = "bundle_id", generation, issuedAt = "issued_at", expiresAt = "expires_at", sealed, mac
    }

    /// base64url(HMAC-SHA256(mac key, "atlas-desktop-bundle:v1:" + device + ":" + bundle + ":" + generation + ":" + expires_at + ":" + sealed)), constant time.
    public func macValid(macKey: Data, deviceId: String) -> Bool {
        guard let tag = Data(b64u: mac) else { return false }
        let msg = "atlas-desktop-bundle:v1:\(deviceId):\(bundleId):\(generation):\(expiresAt):\(sealed)"
        return HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: Data(msg.utf8), using: SymmetricKey(data: macKey))
    }

    public func open(with key: DeviceKey) throws -> BundlePlaintext {
        guard let raw = Data(b64u: sealed), raw.count >= 1 + 65 + 12 + 16, raw[raw.startIndex] == 0x01 else {
            throw DesktopError.malformed("sealed")
        }
        let eph = Data(raw[(raw.startIndex + 1)..<(raw.startIndex + 66)])
        let iv = Data(raw[(raw.startIndex + 66)..<(raw.startIndex + 78)])
        let ct = Data(raw[(raw.startIndex + 78)..<(raw.endIndex - 16)])
        let tag = Data(raw[(raw.endIndex - 16)...])
        let secret = try key.ecdh(peerPoint: eph)
        let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: eph,
                                       info: Data("atlas-desktop-offline-bundle-v1".utf8), outputByteCount: 32)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
            let plain = try AES.GCM.open(box, using: k)
            let p = try JSONDecoder().decode(BundlePlaintext.self, from: plain)
            guard p.v == 1 else { throw DesktopError.malformed("version") }
            return p
        } catch { throw DesktopError.crypto("bundle open failed") }
    }
}

public struct ScryptVerifier: Codable, Equatable {
    public var alg: String, N: Int, r: Int, p: Int, salt: String, hash: String
    public func verify(_ pin: String) -> Bool {
        guard alg == "scrypt", let s = Data(b64u: salt), let h = Data(b64u: hash), h.count == 32,
              let d = try? Scrypt.derive(password: Data(pin.utf8), salt: s, N: N, r: r, p: p, length: 32) else { return false }
        return constantTimeEqual(d, h)
    }
}

func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var d: UInt8 = 0
    for (x, y) in zip(a, b) { d |= x ^ y }
    return d == 0
}

public struct TOTPSeed: Codable, Equatable {
    public var secret: String, digits: Int, period: Int, algorithm: String
}

public struct BundlePlaintext: Codable, Equatable {
    public var v: Int
    public var bundleId: String, deviceId: String, userId: String
    public var generation: Int64, issuedAt: Int64, expiresAt: Int64
    public var pinRequired: Bool
    public var pin: ScryptVerifier?
    public var totp: TOTPSeed
    enum CodingKeys: String, CodingKey {
        case v, bundleId = "bundle_id", deviceId = "device_id", userId = "user_id", generation
        case issuedAt = "issued_at", expiresAt = "expires_at", pinRequired = "pin_required", pin, totp
    }
}

enum TOTP {
    static func base32Decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, acc = 0; var out = [UInt8]()
        for ch in s.uppercased() where ch != "=" && ch != " " {
            guard let v = alphabet.firstIndex(of: ch) else { return nil }
            acc = (acc << 5) | v; bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((acc >> bits) & 0xff)) }
        }
        return Data(out)
    }

    static func code(secret: Data, step: Int64, digits: Int = 6) -> String {
        var counter = UInt64(step).bigEndian
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: Data(bytes: &counter, count: 8), using: SymmetricKey(data: secret)))
        let o = Int(mac[19] & 0x0f)
        let bin = (UInt32(mac[o] & 0x7f) << 24) | (UInt32(mac[o + 1]) << 16) | (UInt32(mac[o + 2]) << 8) | UInt32(mac[o + 3])
        var m: UInt32 = 1; for _ in 0..<digits { m *= 10 }
        return String(format: "%0\(digits)u", bin % m)
    }

    /// Accepts the current step +/- 1 that is greater than `lastStep`; returns the accepted step.
    static func verify(_ input: String, seed: TOTPSeed, nowMs: Int64, lastStep: Int64) -> Int64? {
        guard seed.algorithm.uppercased() == "SHA1", seed.digits == 6, seed.period > 0,
              input.count == 6, input.allSatisfy({ $0.isASCII && $0.isNumber }),
              let secret = base32Decode(seed.secret) else { return nil }
        let cur = nowMs / 1000 / Int64(seed.period)
        var hit: Int64?
        for step in [cur - 1, cur, cur + 1] where step > lastStep {
            if constantTimeEqual(Data(code(secret: secret, step: step).utf8), Data(input.utf8)) { hit = step }
        }
        return hit
    }
}

public struct OfflineEvent: Codable, Equatable {
    public var at: Int64
    public var outcome: String
    public var bundleId: String?
    public var reason: String?
    enum CodingKeys: String, CodingKey { case at, outcome, bundleId = "bundle_id", reason }
}

struct OfflineState: Codable {
    var highWaterMs: Int64 = 0
    var lastTotpStep: Int64 = -1
    var failures = 0
    var lockedUntilMs: Int64 = 0
    var queue: [OfflineEvent] = []
}

public enum OfflineResult: Equatable {
    case allowed, wrongPIN, wrongCode, locked(untilMs: Int64), expired, clockTampered, invalid
}

public final class OfflineUnlock {
    static let key = "offline_state"
    static let maxFailures = 5
    static let lockMs: Int64 = 15 * 60_000
    static let skewMs: Int64 = 5 * 60_000
    let store: SecretStore, clock: Clock

    public init(store: SecretStore, clock: Clock) { self.store = store; self.clock = clock }

    func state() -> OfflineState { store.load(OfflineState.self, Self.key) ?? OfflineState() }
    func save(_ s: OfflineState) throws { try store.save(s, Self.key) }

    public var queue: [OfflineEvent] { state().queue }
    func removeQueued(_ n: Int) { var s = state(); s.queue.removeFirst(min(n, s.queue.count)); try? save(s) }
    func record(_ at: Int64, _ outcome: String, _ bundle: String?, _ reason: String?) {
        var s = state()
        s.queue.append(OfflineEvent(at: at, outcome: outcome, bundleId: bundle, reason: reason))
        if s.queue.count > 1000 { s.queue.removeFirst(s.queue.count - 1000) }
        try? save(s)
    }

    /// Never allows unless the state change was persisted first (fail closed).
    public func attempt(plain: BundlePlaintext, pin: String?, code: String) -> OfflineResult {
        let now = clock.nowMs
        var s = state()
        func fail(_ r: OfflineResult, _ reason: String) -> OfflineResult { record(now, "failure", plain.bundleId, reason); return r }
        if s.lockedUntilMs > now { return fail(.locked(untilMs: s.lockedUntilMs), "locked") }
        if s.lockedUntilMs != 0 { s.lockedUntilMs = 0; s.failures = 0 }
        if now < max(s.highWaterMs, plain.issuedAt) - Self.skewMs { return fail(.clockTampered, "clock") }
        s.highWaterMs = max(s.highWaterMs, now)
        if now >= plain.expiresAt { try? save(s); return fail(.expired, "expired") }

        let pinOK = !plain.pinRequired || (pin.map { plain.pin?.verify($0) ?? false } ?? false)
        let step = TOTP.verify(code, seed: plain.totp, nowMs: now, lastStep: s.lastTotpStep)
        if pinOK, let step = step {
            s.lastTotpStep = step; s.failures = 0
            s.queue.append(OfflineEvent(at: now, outcome: "success", bundleId: plain.bundleId, reason: nil))
            do { try save(s) } catch { return .invalid }
            return .allowed
        }
        s.failures += 1
        var result: OfflineResult = pinOK ? .wrongCode : .wrongPIN
        if s.failures >= Self.maxFailures { s.lockedUntilMs = now + Self.lockMs; s.failures = 0; result = .locked(untilMs: s.lockedUntilMs) }
        s.queue.append(OfflineEvent(at: now, outcome: "failure", bundleId: plain.bundleId, reason: pinOK ? "code" : "pin"))
        do { try save(s) } catch { return .invalid }
        return result
    }
}
