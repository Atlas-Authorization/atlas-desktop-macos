import Foundation
import CryptoKit

extension Data {
    /// Decodes unpadded (or padded) base64url.
    init?(b64u s: String) {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        self.init(base64Encoded: t)
    }
    var b64u: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

public enum DesktopError: Error, Equatable {
    case network(String)
    case api(status: Int, code: String?, deviceStatus: String?)
    case revoked
    case malformed(String)
    case notEnrolled
    case insecureURL
    case crypto(String)
    case storage(String)
}

public protocol Clock { var nowMs: Int64 { get } }
public struct SystemClock: Clock {
    public init() {}
    public var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
}

/// Device-bound secret storage (Keychain in production).
public protocol SecretStore {
    func get(_ key: String) -> Data?
    func set(_ key: String, _ value: Data) throws
    func delete(_ key: String)
}

public final class InMemorySecretStore: SecretStore {
    var items: [String: Data] = [:]
    public init() {}
    public func get(_ key: String) -> Data? { items[key] }
    public func set(_ key: String, _ value: Data) throws { items[key] = value }
    public func delete(_ key: String) { items[key] = nil }
}

extension SecretStore {
    func load<T: Decodable>(_ type: T.Type, _ key: String) -> T? {
        guard let d = get(key) else { return nil }
        return try? JSONDecoder().decode(T.self, from: d)
    }
    func save<T: Encodable>(_ value: T, _ key: String) throws {
        try set(key, try JSONEncoder().encode(value))
    }
}

enum SignedMessage {
    static func build(purpose: String, instanceId: String, keyId: String, nonce: String, extra: String? = nil) -> String {
        var m = "atlas-desktop:v1:\(purpose):\(instanceId):\(keyId):\(nonce)"
        if let e = extra { m += ":" + e }
        return m
    }
    static func sha256b64u(_ s: String) -> String { Data(SHA256.hash(data: Data(s.utf8))).b64u }
}

// MARK: - scrypt (RFC 7914) over CryptoKit HMAC-SHA256

enum Scrypt {
    static func derive(password: Data, salt: Data, N: Int, r: Int, p: Int, length: Int) throws -> Data {
        guard N > 1, N & (N - 1) == 0, r > 0, p > 0, N * r <= (1 << 18), p * r <= 64, length > 0 else {
            throw DesktopError.crypto("scrypt parameters rejected")
        }
        var b = pbkdf2One(password, salt, p * 128 * r)
        let words = 32 * r
        var v = [UInt32](repeating: 0, count: N * words)
        var x = [UInt32](repeating: 0, count: words)
        var y = [UInt32](repeating: 0, count: words)
        var scratch = [UInt32](repeating: 0, count: 32)
        for chunk in 0..<p {
            let base = chunk * 128 * r
            for i in 0..<words {
                let o = base + i * 4
                x[i] = UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
            }
            v.withUnsafeMutableBufferPointer { vp in
                x.withUnsafeMutableBufferPointer { xp in
                    y.withUnsafeMutableBufferPointer { yp in
                        scratch.withUnsafeMutableBufferPointer { sp in
                            for i in 0..<N {
                                (vp.baseAddress! + i * words).update(from: xp.baseAddress!, count: words)
                                blockMix(xp.baseAddress!, yp.baseAddress!, r, sp.baseAddress!)
                            }
                            for _ in 0..<N {
                                let j = Int(xp[(2 * r - 1) * 16]) & (N - 1)
                                for k in 0..<words { xp[k] ^= vp[j * words + k] }
                                blockMix(xp.baseAddress!, yp.baseAddress!, r, sp.baseAddress!)
                            }
                        }
                    }
                }
            }
            for i in 0..<words {
                let o = base + i * 4
                b[o] = UInt8(truncatingIfNeeded: x[i]); b[o + 1] = UInt8(truncatingIfNeeded: x[i] >> 8)
                b[o + 2] = UInt8(truncatingIfNeeded: x[i] >> 16); b[o + 3] = UInt8(truncatingIfNeeded: x[i] >> 24)
            }
        }
        return Data(pbkdf2One(password, Data(b), length))
    }

    /// PBKDF2-HMAC-SHA256 with a single iteration (all scrypt needs).
    static func pbkdf2One(_ pw: Data, _ salt: Data, _ len: Int) -> [UInt8] {
        let key = SymmetricKey(data: pw)
        var out = [UInt8](); var i: UInt32 = 1
        while out.count < len {
            var m = salt; m.append(contentsOf: withUnsafeBytes(of: i.bigEndian) { Array($0) })
            out += Array(HMAC<SHA256>.authenticationCode(for: m, using: key))
            i += 1
        }
        return Array(out.prefix(len))
    }

    /// x: 32r words in/out. y: scratch 32r words.
    static func blockMix(_ x: UnsafeMutablePointer<UInt32>, _ y: UnsafeMutablePointer<UInt32>, _ r: Int, _ s: UnsafeMutablePointer<UInt32>) {
        let t = s + 16
        for k in 0..<16 { t[k] = x[(2 * r - 1) * 16 + k] }
        for i in 0..<(2 * r) {
            for k in 0..<16 { t[k] ^= x[i * 16 + k] }
            salsa8(t, s)
            let dst = (i % 2 == 0) ? (i / 2) : (r + i / 2)
            for k in 0..<16 { y[dst * 16 + k] = t[k] }
        }
        for k in 0..<(32 * r) { x[k] = y[k] }
    }

    @inline(__always) static func rotl(_ a: UInt32, _ b: UInt32) -> UInt32 { (a << b) | (a >> (32 - b)) }

    static func salsa8(_ b: UnsafeMutablePointer<UInt32>, _ x: UnsafeMutablePointer<UInt32>) {
        for i in 0..<16 { x[i] = b[i] }
        for _ in 0..<4 {
            x[4] ^= rotl(x[0] &+ x[12], 7); x[8] ^= rotl(x[4] &+ x[0], 9)
            x[12] ^= rotl(x[8] &+ x[4], 13); x[0] ^= rotl(x[12] &+ x[8], 18)
            x[9] ^= rotl(x[5] &+ x[1], 7); x[13] ^= rotl(x[9] &+ x[5], 9)
            x[1] ^= rotl(x[13] &+ x[9], 13); x[5] ^= rotl(x[1] &+ x[13], 18)
            x[14] ^= rotl(x[10] &+ x[6], 7); x[2] ^= rotl(x[14] &+ x[10], 9)
            x[6] ^= rotl(x[2] &+ x[14], 13); x[10] ^= rotl(x[6] &+ x[2], 18)
            x[3] ^= rotl(x[15] &+ x[11], 7); x[7] ^= rotl(x[3] &+ x[15], 9)
            x[11] ^= rotl(x[7] &+ x[3], 13); x[15] ^= rotl(x[11] &+ x[7], 18)
            x[1] ^= rotl(x[0] &+ x[3], 7); x[2] ^= rotl(x[1] &+ x[0], 9)
            x[3] ^= rotl(x[2] &+ x[1], 13); x[0] ^= rotl(x[3] &+ x[2], 18)
            x[6] ^= rotl(x[5] &+ x[4], 7); x[7] ^= rotl(x[6] &+ x[5], 9)
            x[4] ^= rotl(x[7] &+ x[6], 13); x[5] ^= rotl(x[4] &+ x[7], 18)
            x[11] ^= rotl(x[10] &+ x[9], 7); x[8] ^= rotl(x[11] &+ x[10], 9)
            x[9] ^= rotl(x[8] &+ x[11], 13); x[10] ^= rotl(x[9] &+ x[8], 18)
            x[12] ^= rotl(x[15] &+ x[14], 7); x[13] ^= rotl(x[12] &+ x[15], 9)
            x[14] ^= rotl(x[13] &+ x[12], 13); x[15] ^= rotl(x[14] &+ x[13], 18)
        }
        for i in 0..<16 { b[i] = b[i] &+ x[i] }
    }
}
