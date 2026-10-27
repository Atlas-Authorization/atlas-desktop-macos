import Foundation

/// The subset of CBOR (RFC 8949) CTAP2 uses: integers, byte and text strings, arrays, maps, booleans, null. Definite lengths only,
/// shortest integer form, and maps encoded with keys sorted by (encoded length, bytes) as CTAP2's canonical form requires.
enum CBOR: Equatable {
    case int(Int64)
    case bytes(Data)
    case text(String)
    case array([CBOR])
    case map([(CBOR, CBOR)])
    case bool(Bool)
    case null

    static func == (a: CBOR, b: CBOR) -> Bool {
        switch (a, b) {
        case (.int(let x), .int(let y)): return x == y
        case (.bytes(let x), .bytes(let y)): return x == y
        case (.text(let x), .text(let y)): return x == y
        case (.array(let x), .array(let y)): return x == y
        case (.map(let x), .map(let y)): return x.count == y.count && zip(x, y).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
        case (.bool(let x), .bool(let y)): return x == y
        case (.null, .null): return true
        default: return false
        }
    }

    // MARK: encode

    private static func head(_ major: UInt8, _ n: UInt64) -> Data {
        let m = major << 5
        switch n {
        case 0..<24: return Data([m | UInt8(n)])
        case 24..<0x100: return Data([m | 24, UInt8(n)])
        case 0x100..<0x10000: return Data([m | 25, UInt8(n >> 8), UInt8(n & 0xff)])
        case 0x10000..<0x1_0000_0000: return Data([m | 26] + (0..<4).map { UInt8((n >> UInt64(8 * (3 - $0))) & 0xff) })
        default: return Data([m | 27] + (0..<8).map { UInt8((n >> UInt64(8 * (7 - $0))) & 0xff) })
        }
    }

    func encode() -> Data {
        switch self {
        case .int(let v): return v >= 0 ? Self.head(0, UInt64(v)) : Self.head(1, UInt64(-1 - v))
        case .bytes(let d): return Self.head(2, UInt64(d.count)) + d
        case .text(let s): let u = Data(s.utf8); return Self.head(3, UInt64(u.count)) + u
        case .array(let a): return a.reduce(Self.head(4, UInt64(a.count))) { $0 + $1.encode() }
        case .map(let m):
            let pairs = m.map { ($0.0.encode(), $0.1.encode()) }.sorted { l, r in
                l.0.count != r.0.count ? l.0.count < r.0.count : l.0.lexicographicallyPrecedes(r.0)
            }
            return pairs.reduce(Self.head(5, UInt64(pairs.count))) { $0 + $1.0 + $1.1 }
        case .bool(let b): return Data([b ? 0xf5 : 0xf4])
        case .null: return Data([0xf6])
        }
    }

    // MARK: decode

    enum DecodeError: Error, Equatable { case truncated, unsupported(UInt8), tooDeep, tooLarge, trailing }

    /// Decodes exactly one item and requires the input to end there.
    static func decode(_ data: Data) throws -> CBOR {
        var i = data.startIndex
        let v = try item(data, &i, depth: 0)
        guard i == data.endIndex else { throw DecodeError.trailing }
        return v
    }

    private static func arg(_ d: Data, _ i: inout Data.Index, _ info: UInt8) throws -> UInt64 {
        func take(_ n: Int) throws -> UInt64 {
            guard d.distance(from: i, to: d.endIndex) >= n else { throw DecodeError.truncated }
            var v: UInt64 = 0
            for _ in 0..<n { v = (v << 8) | UInt64(d[i]); i = d.index(after: i) }
            return v
        }
        switch info {
        case 0..<24: return UInt64(info)
        case 24: return try take(1)
        case 25: return try take(2)
        case 26: return try take(4)
        case 27: return try take(8)
        default: throw DecodeError.unsupported(info) // 28-30 reserved, 31 = indefinite length (CTAP2 forbids it)
        }
    }

    private static func item(_ d: Data, _ i: inout Data.Index, depth: Int) throws -> CBOR {
        guard depth < 16 else { throw DecodeError.tooDeep }
        guard i < d.endIndex else { throw DecodeError.truncated }
        let b = d[i]; i = d.index(after: i)
        let major = b >> 5, info = b & 0x1f
        switch major {
        case 0:
            let n = try arg(d, &i, info); guard n <= UInt64(Int64.max) else { throw DecodeError.tooLarge }
            return .int(Int64(n))
        case 1:
            let n = try arg(d, &i, info); guard n <= UInt64(Int64.max) else { throw DecodeError.tooLarge }
            return .int(-1 - Int64(n))
        case 2, 3:
            let n = try arg(d, &i, info)
            guard n <= 1 << 20, d.distance(from: i, to: d.endIndex) >= Int(n) else { throw DecodeError.truncated }
            let end = d.index(i, offsetBy: Int(n)); let slice = Data(d[i..<end]); i = end
            if major == 2 { return .bytes(slice) }
            guard let s = String(data: slice, encoding: .utf8) else { throw DecodeError.unsupported(b) }
            return .text(s)
        case 4:
            let n = try arg(d, &i, info); guard n <= 1024 else { throw DecodeError.tooLarge }
            return .array(try (0..<Int(n)).map { _ in try item(d, &i, depth: depth + 1) })
        case 5:
            let n = try arg(d, &i, info); guard n <= 1024 else { throw DecodeError.tooLarge }
            return .map(try (0..<Int(n)).map { _ in (try item(d, &i, depth: depth + 1), try item(d, &i, depth: depth + 1)) })
        case 7:
            switch info { case 20: return .bool(false); case 21: return .bool(true); case 22: return .null; default: throw DecodeError.unsupported(b) }
        default: throw DecodeError.unsupported(b)
        }
    }

    // MARK: access

    subscript(key: Int64) -> CBOR? {
        guard case .map(let m) = self else { return nil }
        return m.first { if case .int(let k) = $0.0 { return k == key } else { return false } }?.1
    }
    subscript(key: String) -> CBOR? {
        guard case .map(let m) = self else { return nil }
        return m.first { if case .text(let k) = $0.0 { return k == key } else { return false } }?.1
    }
    var dataValue: Data? { if case .bytes(let d) = self { return d } else { return nil } }
    var intValue: Int64? { if case .int(let v) = self { return v } else { return nil } }
    var textValue: String? { if case .text(let s) = self { return s } else { return nil } }
    var boolValue: Bool? { if case .bool(let b) = self { return b } else { return nil } }
    var arrayValue: [CBOR]? { if case .array(let a) = self { return a } else { return nil } }
}
