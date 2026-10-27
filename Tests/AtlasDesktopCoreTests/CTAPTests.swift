import CommonCrypto
import CryptoKit
import XCTest
@testable import AtlasDesktopCore

// MARK: - CBOR (RFC 8949 appendix A vectors)

final class CBORTests: XCTestCase {
    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
    func unhex(_ s: String) -> Data { Data(stride(from: 0, to: s.count, by: 2).map { UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)! }) }

    func testEncodeVectors() {
        let v: [(CBOR, String)] = [
            (.int(0), "00"), (.int(1), "01"), (.int(10), "0a"), (.int(23), "17"), (.int(24), "1818"), (.int(25), "1819"), (.int(100), "1864"),
            (.int(1000), "1903e8"), (.int(1_000_000), "1a000f4240"), (.int(1_000_000_000_000), "1b000000e8d4a51000"),
            (.int(-1), "20"), (.int(-10), "29"), (.int(-100), "3863"), (.int(-1000), "3903e7"),
            (.bytes(Data()), "40"), (.bytes(Data([1, 2, 3, 4])), "4401020304"), (.text(""), "60"), (.text("a"), "6161"), (.text("IETF"), "6449455446"),
            (.array([]), "80"), (.array([.int(1), .int(2), .int(3)]), "83010203"),
            (.map([]), "a0"), (.map([(.int(1), .int(2)), (.int(3), .int(4))]), "a201020304"),
            (.bool(false), "f4"), (.bool(true), "f5"), (.null, "f6"),
        ]
        for (c, h) in v { XCTAssertEqual(hex(c.encode()), h) }
        for (c, h) in v { XCTAssertEqual(try CBOR.decode(unhex(h)), c, h) }
    }

    func testMapsAreEncodedCanonically() {
        let m = CBOR.map([(.text("type"), .text("public-key")), (.text("id"), .bytes(Data([1]))), (.int(-1), .int(1)), (.int(2), .int(0)), (.int(1), .int(0))])
        // integers first by value (positive before negative), then shorter text before longer
        XCTAssertEqual(hex(m.encode()), "a5" + "0100" + "0200" + "2001" + "626964" + "4101" + "6474797065" + "6a" + hex(Data("public-key".utf8)))
    }

    func testDecodeRefusesWhatCTAPForbidsOrWeCannotBound() {
        XCTAssertThrowsError(try CBOR.decode(unhex("9f01ff")))          // indefinite length
        XCTAssertThrowsError(try CBOR.decode(unhex("1a0000")))          // truncated
        XCTAssertThrowsError(try CBOR.decode(unhex("0100")))            // trailing byte
        XCTAssertThrowsError(try CBOR.decode(unhex("fb3ff0000000000000"))) // float
        XCTAssertThrowsError(try CBOR.decode(unhex("c074323031332d30332d32315432303a30343a30305a"))) // tag
        XCTAssertThrowsError(try CBOR.decode(unhex("6261")))            // string shorter than its length
        XCTAssertThrowsError(try CBOR.decode(Data(repeating: 0x81, count: 40) + Data([0])))  // nesting
        XCTAssertThrowsError(try CBOR.decode(unhex("5a7fffffff")))      // absurd length
        XCTAssertThrowsError(try CBOR.decode(Data()))
    }

    func testAccessors() throws {
        let c = try CBOR.decode(CBOR.map([(.int(1), .text("x")), (.text("k"), .bytes(Data([9])))]).encode())
        XCTAssertEqual(c[1]?.textValue, "x"); XCTAssertEqual(c["k"]?.dataValue, Data([9])); XCTAssertNil(c[2]); XCTAssertNil(CBOR.int(1)[1])
    }
}

// MARK: - CTAPHID framing

final class CTAPHIDTests: XCTestCase {
    func roundTrip(_ n: Int) throws {
        let payload = Data((0..<n).map { UInt8($0 & 0xff) })
        let packets = CTAPHID.split(cid: 0x01020304, cmd: CTAPHID.cmdCBOR, payload: payload)
        XCTAssertTrue(packets.allSatisfy { $0.count == 64 })
        XCTAssertEqual(packets.count, n <= 57 ? 1 : 1 + (n - 57 + 58) / 59)
        var r = CTAPHIDReassembler(cid: 0x01020304); var got: CTAPHIDMessage?
        for p in packets { got = try r.feed(p) }
        XCTAssertEqual(got, CTAPHIDMessage(cid: 0x01020304, cmd: CTAPHID.cmdCBOR, payload: payload), "size \(n)")
    }
    func testSplitAndReassemble() throws { for n in [0, 1, 56, 57, 58, 115, 116, 117, 1000, CTAPHID.maxPayload] { try roundTrip(n) } }

    func testLayout() {
        let p = CTAPHID.split(cid: 0xAABBCCDD, cmd: 0x10, payload: Data(repeating: 7, count: 60))
        XCTAssertEqual(Array(p[0].prefix(7)), [0xAA, 0xBB, 0xCC, 0xDD, 0x90, 0x00, 0x3C])      // CMD with bit 7 set, BCNT = 60
        XCTAssertEqual(Array(p[1].prefix(5)), [0xAA, 0xBB, 0xCC, 0xDD, 0x00])                    // SEQ 0
        XCTAssertEqual(CTAPHID.maxPayload, 7609)
    }

    func testReassemblerRejectsBrokenStreamsAndIgnoresOtherChannels() throws {
        let packets = CTAPHID.split(cid: 1, cmd: 0x10, payload: Data(repeating: 1, count: 200))
        var r = CTAPHIDReassembler(cid: 1)
        XCTAssertNil(try r.feed(packets[0]))
        XCTAssertNil(try r.feed(CTAPHID.split(cid: 2, cmd: 0x10, payload: Data([1]))[0]))   // someone else's message
        XCTAssertThrowsError(try r.feed(packets[2]))                                          // sequence gap
        var r2 = CTAPHIDReassembler(cid: 1)
        XCTAssertThrowsError(try r2.feed(packets[1]))                                         // continuation first
        var r3 = CTAPHIDReassembler(cid: 1); _ = try r3.feed(packets[0])
        XCTAssertThrowsError(try r3.feed(packets[0]))                                         // restart mid message
        XCTAssertThrowsError(try r3.feed(Data(count: 10)))                                    // wrong size
        var r4 = CTAPHIDReassembler(cid: 1)
        var big = packets[0]; big[big.startIndex + 5] = 0xFF; big[big.startIndex + 6] = 0xFF
        XCTAssertThrowsError(try r4.feed(big))                                                // length beyond the maximum
    }
}

// MARK: - a software security key

final class SoftKey: CTAPHIDTransport {
    var cid: UInt32 = 0x0A0B0C0D
    var pin: String? = "1234"
    var pinRetries = 8
    var protocols = [2, 1]
    var tokenCommand = true            // supports pinUvAuthToken (subcommand 9)
    var builtInUV = false
    var requirePUAT = false
    var failWith: UInt8?               // force a CTAP status on get/makeCredential
    var keepalives = true
    let credKey = P256.Signing.PrivateKey()
    let credId = Data((1...32).map { UInt8($0) })
    let aaguid = Data((0..<16).map { UInt8(0xA0 + $0) })
    var token: Data?, tokenPerms: Int64 = 0, tokenRp: String?
    var cancelSeen = false, closed = false
    var lastGetAssertion: CBOR?, lastMake: CBOR?
    private var outbox: [Data] = []
    private var rx: CTAPHIDReassembler?
    private let agreement = P256.KeyAgreement.PrivateKey()

    func close() { closed = true }
    func write(_ packet: Data) throws {
        let c = CTAPHID.cid(packet)
        if c == CTAPHID.broadcastCID {
            let nonce = packet.subdata(in: 7..<15)
            var payload = nonce; payload.append(contentsOf: CTAPHID.cidBytes(cid)); payload.append(contentsOf: [2, 1, 0, 0, CTAPHID.capCBOR])
            outbox += CTAPHID.split(cid: CTAPHID.broadcastCID, cmd: CTAPHID.cmdInit, payload: payload)
            return
        }
        guard c == cid else { return }
        if rx == nil { rx = CTAPHIDReassembler(cid: cid) }
        guard let m = try rx!.feed(packet) else { return }
        rx = nil
        if m.cmd == CTAPHID.cmdCancel { cancelSeen = true; return }
        if m.cmd == CTAPHID.cmdCBOR { respond(m.payload) }
    }
    func read(timeout: TimeInterval) throws -> Data {
        if outbox.isEmpty { Thread.sleep(forTimeInterval: min(timeout, 0.01)); throw CTAPHIDError.timeout }
        return outbox.removeFirst()
    }

    private var needsTouch = false   // a real key waits for a touch only while it runs getAssertion / makeCredential
    private func send(_ status: UInt8, _ body: CBOR? = nil) {
        defer { needsTouch = false }
        if keepalives && needsTouch { outbox += CTAPHID.split(cid: cid, cmd: CTAPHID.cmdKeepalive, payload: Data([CTAPHID.keepaliveUPNeeded])) }
        outbox += CTAPHID.split(cid: cid, cmd: CTAPHID.cmdCBOR, payload: Data([status]) + (body?.encode() ?? Data()))
    }

    // The device's half of the PIN/UV auth protocols, written separately from the client's.
    private func secret(_ version: Int, _ platform: CBOR) throws -> (hmac: Data, aes: Data) {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + platform[-2]!.dataValue! + platform[-3]!.dataValue!)
        let z = try agreement.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        if version == 1 { let k = Data(SHA256.hash(data: z)); return (k, k) }
        func d(_ i: String) -> Data { HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: z), salt: Data(repeating: 0, count: 32), info: Data(i.utf8), outputByteCount: 32).withUnsafeBytes { Data($0) } }
        return (d("CTAP2 HMAC key"), d("CTAP2 AES key"))
    }
    private func aes(_ op: Int, _ key: Data, _ iv: Data, _ input: Data) -> Data {
        var out = Data(count: input.count + 16); var n = 0; let cap = out.count
        _ = out.withUnsafeMutableBytes { o in input.withUnsafeBytes { i in key.withUnsafeBytes { k in iv.withUnsafeBytes { v in
            CCCrypt(CCOperation(op), CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, key.count, v.baseAddress, i.baseAddress, input.count, o.baseAddress, cap, &n) } } } }
        return out.prefix(n)
    }
    private func mac(_ version: Int, _ key: Data, _ msg: Data) -> Data {
        let m = Data(HMAC<SHA256>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
        return version == 1 ? m.prefix(16) : m
    }

    private func verifyUV(_ p: CBOR, hash: Data, paramKey: Int64, protoKey: Int64) -> UInt8? {   // nil = ok / not given
        guard let param = p[paramKey]?.dataValue, let v = p[protoKey]?.intValue else { return pin != nil && requirePUAT ? CTAP2.puatRequired : nil }
        guard let t = token, mac(Int(v), t, hash) == param else { return CTAP2.pinAuthInvalid }
        return nil
    }

    private func authData(rp: String, flags: UInt8, attested: Bool) -> Data {
        var d = Data(SHA256.hash(data: Data(rp.utf8))); d.append(flags); d.append(contentsOf: [0, 0, 0, 1])
        if attested {
            d.append(aaguid); d.append(contentsOf: [0, UInt8(credId.count)]); d.append(credId)
            let raw = credKey.publicKey.x963Representation
            d.append(CBOR.map([(.int(1), .int(2)), (.int(3), .int(-7)), (.int(-1), .int(1)), (.int(-2), .bytes(raw.subdata(in: 1..<33))), (.int(-3), .bytes(raw.subdata(in: 33..<65)))]).encode())
        }
        return d
    }

    private func respond(_ payload: Data) {
        let cmd = payload[payload.startIndex]
        needsTouch = cmd == CTAP2.cmdGetAssertion || cmd == CTAP2.cmdMakeCredential
        let body = payload.count > 1 ? (try? CBOR.decode(payload.dropFirst())) : nil
        if let f = failWith, cmd == CTAP2.cmdGetAssertion || cmd == CTAP2.cmdMakeCredential { send(f); return }
        switch cmd {
        case CTAP2.cmdGetInfo:
            var opts: [(CBOR, CBOR)] = [(.text("rk"), .bool(true))]
            opts.append((.text("clientPin"), .bool(pin != nil)))
            if tokenCommand { opts.append((.text("pinUvAuthToken"), .bool(true))) }
            if builtInUV { opts.append((.text("uv"), .bool(true))) }
            send(CTAP2.ok, .map([(.int(1), .array([.text("U2F_V2"), .text("FIDO_2_1")])), (.int(3), .bytes(aaguid)), (.int(4), .map(opts)), (.int(6), .array(protocols.map { .int(Int64($0)) }))]))
        case CTAP2.cmdClientPIN:
            guard let b = body, let sub = b[2]?.intValue else { send(0x14); return }
            let version = Int(b[1]?.intValue ?? 1)
            switch sub {
            case 1: send(CTAP2.ok, .map([(.int(3), .int(Int64(pinRetries)))]))
            case 2:
                let raw = agreement.publicKey.x963Representation
                send(CTAP2.ok, .map([(.int(1), .map([(.int(1), .int(2)), (.int(3), .int(-25)), (.int(-1), .int(1)), (.int(-2), .bytes(raw.subdata(in: 1..<33))), (.int(-3), .bytes(raw.subdata(in: 33..<65)))]))]))
            case 5, 9:
                guard let pin = pin, let platform = b[3], let enc = b[6]?.dataValue, protocols.contains(version), (sub == 5 || tokenCommand) else { send(0x14); return }
                if pinRetries == 0 { send(CTAP2.pinBlocked); return }
                guard let s = try? secret(version, platform) else { send(0x14); return }
                let plain = version == 1 ? aes(kCCDecrypt, s.aes, Data(repeating: 0, count: 16), enc) : aes(kCCDecrypt, s.aes, enc.prefix(16), enc.dropFirst(16))
                guard plain == Data(SHA256.hash(data: Data(pin.utf8))).prefix(16) else { pinRetries -= 1; send(CTAP2.pinInvalid); return }
                let t = Data((0..<32).map { _ in UInt8.random(in: 0...255) }); token = t
                tokenPerms = sub == 9 ? (b[9]?.intValue ?? 0) : 3; tokenRp = sub == 9 ? b[10]?.textValue : nil
                let ct = version == 1 ? aes(kCCEncrypt, s.aes, Data(repeating: 0, count: 16), t) : { let iv = Data(repeating: 7, count: 16); return iv + aes(kCCEncrypt, s.aes, iv, t) }()
                // protocol one keeps the key-derived MAC key == AES key; the MAC key for a token is the token itself
                send(CTAP2.ok, .map([(.int(2), .bytes(ct))]))
            default: send(0x2B)
            }
        case CTAP2.cmdGetAssertion:
            lastGetAssertion = body
            guard let b = body, let rp = b[1]?.textValue, let hash = b[2]?.dataValue else { send(0x14); return }
            if let e = verifyUV(b, hash: hash, paramKey: 6, protoKey: 7) { send(e); return }
            let uv = b[6] != nil
            if b[6] != nil && (tokenPerms & CTAP2.permGetAssertion == 0 || (tokenRp != nil && tokenRp != rp)) { send(CTAP2.pinAuthInvalid); return }
            let allow = b[3]?.arrayValue?.compactMap { $0["id"]?.dataValue } ?? []
            guard allow.contains(credId) else { send(CTAP2.noCredentials); return }
            let uvAsked = b[5]?["uv"]?.boolValue == true
            let ad = authData(rp: rp, flags: uv || (builtInUV && uvAsked) ? 0x05 : 0x01, attested: false)
            let sig = try! credKey.signature(for: ad + hash).derRepresentation
            var resp: [(CBOR, CBOR)] = [(.int(2), .bytes(ad)), (.int(3), .bytes(sig))]
            if allow.count != 1 { resp.insert((.int(1), .map([(.text("id"), .bytes(credId)), (.text("type"), .text("public-key"))])), at: 0) }
            send(CTAP2.ok, .map(resp))
        case CTAP2.cmdMakeCredential:
            lastMake = body
            guard let b = body, let hash = b[1]?.dataValue, let rp = b[2]?["id"]?.textValue else { send(0x14); return }
            if let e = verifyUV(b, hash: hash, paramKey: 8, protoKey: 9) { send(e); return }
            if b[5]?.arrayValue?.contains(where: { $0["id"]?.dataValue == credId }) == true { send(CTAP2.credentialExcluded); return }
            let ad = authData(rp: rp, flags: b[8] != nil ? 0x45 : 0x41, attested: true)
            send(CTAP2.ok, .map([(.int(1), .text("packed")), (.int(2), .bytes(ad)), (.int(3), .map([(.text("alg"), .int(-7)), (.text("sig"), .bytes(Data([1, 2, 3])))]))]))
        default: send(0x01)
        }
    }
}

// MARK: - CTAP2 end to end against the software key

final class CTAP2Tests: XCTestCase {
    let cdJSON = Passkey.clientDataJSON(type: "webauthn.get", challenge: goodChallenge, origin: "https://auth.example.com")

    final class Log { var statuses: [String] = []; var asked: [Int?] = [] }
    func auth(_ key: SoftKey, pins: [String?] = ["1234"], log: Log? = nil) -> CTAP2Authenticator {
        var queue = pins
        return CTAP2Authenticator(openDevices: { [key] }, pin: { left in log?.asked.append(left); return queue.isEmpty ? nil : queue.removeFirst() },
                                  status: { log?.statuses.append($0) }, pollInterval: 0.01)
    }
    func request(uv: String = "required", timeoutMs: Int = 3000, allow: [Data]? = nil, key: SoftKey) -> PasskeyRequest {
        PasskeyRequest(challenge: goodChallenge, rpId: "auth.example.com", origin: "https://auth.example.com", userVerification: uv,
                       allow: (allow ?? [key.credId]).map { PasskeyCredentialDescriptor(id: $0, transports: ["usb"]) }, timeoutMs: timeoutMs)
    }
    func verifySignature(_ a: RawAssertion, _ key: SoftKey) throws {
        let hash = Data(SHA256.hash(data: a.clientDataJSON))
        XCTAssertTrue(key.credKey.publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: a.signature), for: a.authenticatorData + hash))
        XCTAssertEqual(a.authenticatorData.prefix(32), Data(SHA256.hash(data: Data("auth.example.com".utf8))))
    }

    func testChannelOpensAndCarriesKeepalivesAndCancel() throws {
        let key = SoftKey(); let ch = CTAPHIDChannel(key)
        try ch.open()
        XCTAssertEqual(ch.cid, 0x0A0B0C0D)
        var seen: [UInt8] = []
        let r = try ch.cbor(Data([CTAP2.cmdGetInfo]), timeout: 2, keepalive: { seen.append($0) })
        XCTAssertEqual(r.first, 0); XCTAssertEqual(seen, [])   // getInfo needs no touch
        // A cancel request reaches the key
        key.failWith = CTAP2.keepaliveCancel
        let c = try ch.cbor(Data([CTAP2.cmdGetAssertion]) + CBOR.map([]).encode(), timeout: 2, keepalive: { seen.append($0) }, shouldCancel: { true })
        XCTAssertTrue(key.cancelSeen); XCTAssertEqual(c.first, CTAP2.keepaliveCancel); XCTAssertEqual(seen, [CTAPHID.keepaliveUPNeeded])
        // A key that never answers: a timeout, not a hang
        final class Silent: CTAPHIDTransport { func write(_ p: Data) throws {}; func read(timeout: TimeInterval) throws -> Data { Thread.sleep(forTimeInterval: 0.01); throw CTAPHIDError.timeout }; func close() {} }
        XCTAssertThrowsError(try CTAPHIDChannel(Silent()).open(timeout: 0.05))
    }

    func testProtocolsAgree() throws {
        for v in [1, 2] {
            let key = SoftKey(); key.protocols = [v]; let ch = CTAPHIDChannel(key); try ch.open()
            let c = CTAP2Client(channel: ch); try c.loadInfo()
            XCTAssertEqual(c.info.pinSet, true); XCTAssertTrue(c.info.supportsPinUvAuthToken); XCTAssertEqual(c.info.aaguid, key.aaguid)
            let t = try c.token(pin: "1234", permissions: CTAP2.permGetAssertion, rpId: "auth.example.com")
            XCTAssertEqual(t.version, v); XCTAssertEqual(t.token, key.token)
            XCTAssertEqual(PinUvProtocol.authenticate(version: 1, key: t.token, message: Data([1])).count, 16)
            XCTAssertEqual(PinUvProtocol.authenticate(version: 2, key: t.token, message: Data([1])).count, 32)
        }
    }

    func testAssertionWithPin() async throws {
        let key = SoftKey(); let log = Log()
        let a = try await auth(key, log: log).assertion(request(key: key), clientData: cdJSON)
        try verifySignature(a, key)
        XCTAssertEqual(a.credentialId, key.credId); XCTAssertEqual(a.clientDataJSON, cdJSON)
        XCTAssertEqual(a.authenticatorData[32] & 0x05, 0x05)      // user present and verified
        XCTAssertEqual(log.statuses, ["Touch your security key."])
        XCTAssertEqual(key.tokenPerms, CTAP2.permGetAssertion); XCTAssertEqual(key.tokenRp, "auth.example.com")
        XCTAssertTrue(key.closed)
    }

    func testLegacyAndProtocolOneKeys() async throws {
        let key = SoftKey(); key.protocols = [1]; key.tokenCommand = false
        let a = try await auth(key).assertion(request(key: key), clientData: cdJSON)
        try verifySignature(a, key)
        XCTAssertEqual(key.tokenPerms, 3)       // getPinToken: mc + ga
    }

    func testSingleAllowedCredentialMayBeOmittedFromTheResponse() async throws {
        let key = SoftKey()
        let a = try await auth(key).assertion(request(key: key), clientData: cdJSON)
        XCTAssertEqual(a.credentialId, key.credId)
        let two = try await auth(key).assertion(request(allow: [key.credId, Data([9, 9])], key: key), clientData: cdJSON)
        XCTAssertEqual(two.credentialId, key.credId)
    }

    func testWrongPinThenRight() async throws {
        let key = SoftKey(); let log = Log()
        let a = try await auth(key, pins: ["0000", "1234"], log: log).assertion(request(key: key), clientData: cdJSON)
        try verifySignature(a, key)
        XCTAssertEqual(log.asked.count, 2); XCTAssertEqual(log.asked[1], 7)       // told how many tries are left
    }

    func testPinCancelledBlockedAndExhausted() async throws {
        let key = SoftKey()
        do { _ = try await auth(key, pins: []).assertion(request(key: key), clientData: cdJSON); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .cancelled) }
        do { _ = try await auth(key, pins: ["1", "2", "3", "4"]).assertion(request(key: key), clientData: cdJSON); XCTFail() } catch {}
        let blocked = SoftKey(); blocked.pinRetries = 0
        do { _ = try await auth(blocked).assertion(request(key: blocked), clientData: cdJSON); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .failed("PIN blocked on the key")) }
    }

    func testUserVerificationPlans() async throws {
        let none = SoftKey(); none.pin = nil
        do { _ = try await auth(none).assertion(request(uv: "required", key: none), clientData: cdJSON); XCTFail() } catch {
            XCTAssertEqual(error as? PasskeyError, .failed("this key has no PIN or biometric to verify you")) }
        let up = try await auth(none).assertion(request(uv: "preferred", key: none), clientData: cdJSON)   // presence only is fine when allowed
        XCTAssertEqual(up.authenticatorData[32] & 0x04, 0)
        let bio = SoftKey(); bio.pin = nil; bio.builtInUV = true
        let b = try await auth(bio).assertion(request(uv: "required", key: bio), clientData: cdJSON)
        XCTAssertEqual(b.authenticatorData[32] & 0x04, 0x04)
        let pinned = SoftKey()
        let d = try await auth(pinned, pins: []).assertion(request(uv: "discouraged", key: pinned), clientData: cdJSON)   // no PIN prompt
        XCTAssertEqual(d.authenticatorData[32] & 0x04, 0)
    }

    func testKeyWithoutTheCredentialAndCancellation() async throws {
        let key = SoftKey()
        do { _ = try await auth(key).assertion(request(allow: [Data([1, 1])], key: key), clientData: cdJSON); XCTFail() } catch {
            XCTAssertEqual(error as? PasskeyError, .failed("this key does not hold a registered passkey")) }
        let denied = SoftKey(); denied.failWith = CTAP2.operationDenied
        do { _ = try await auth(denied).assertion(request(key: denied), clientData: cdJSON); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .cancelled) }
        let none = CTAP2Authenticator(openDevices: { [] }, pin: { _ in nil }, pollInterval: 0.01)
        var told: [String] = []
        let withStatus = CTAP2Authenticator(openDevices: { [] }, pin: { _ in nil }, status: { told.append($0) }, pollInterval: 0.01)
        do { _ = try await none.assertion(request(timeoutMs: 100, key: key), clientData: cdJSON); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .failed("no security key found")) }
        do { _ = try await withStatus.assertion(request(timeoutMs: 100, key: key), clientData: cdJSON); XCTFail() } catch {}
        XCTAssertEqual(told, ["Insert your security key."])
    }

    func testRegistrationDropsTheAttestationAndKeepsTheAaguid() async throws {
        let key = SoftKey()
        let c = try Passkey.parseCreation(goodCreation())
        let cd = Passkey.clientDataJSON(type: "webauthn.create", challenge: c.challenge, origin: c.origin)
        let r = try await auth(key).registration(c, clientData: cd)
        XCTAssertEqual(r.credentialId, key.credId); XCTAssertEqual(r.transports, ["usb"]); XCTAssertEqual(r.clientDataJSON, cd)
        let obj = try CBOR.decode(r.attestationObject)
        XCTAssertEqual(obj["fmt"]?.textValue, "none"); XCTAssertEqual(obj["attStmt"], .map([]))
        let ad = obj["authData"]!.dataValue!
        XCTAssertEqual(ad.subdata(in: 37..<53), key.aaguid); XCTAssertEqual(ad[32] & 0x45, 0x45)    // UP, UV, attested credential data
        XCTAssertEqual(key.lastMake?[2]?["id"]?.textValue, "auth.example.com")
        XCTAssertEqual(key.lastMake?[7]?["rk"]?.boolValue, true)
        XCTAssertEqual(key.tokenPerms, CTAP2.permMakeCredential)
        // the same key again is refused by the exclude list
        var again = c; again.exclude = [key.credId]
        do { _ = try await auth(key).registration(again, clientData: cd); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .failed("this key is already registered")) }
    }

    func testProviderEndToEndWithTheGate() async throws {
        let key = SoftKey()
        var o = goodOptions(); o["allowCredentials"] = [["type": "public-key", "id": key.credId.b64u, "transports": ["usb"]]]
        let body = try await Passkey.provider(for: auth(key))(o)
        XCTAssertEqual(body["credential_id"], key.credId.b64u)
        let cd = Data(b64u: body["client_data_json"]!)!
        XCTAssertNoThrow(try Passkey.checkClientData(cd, type: "webauthn.get", challenge: goodChallenge, origin: "https://auth.example.com"))
        let sig = try P256.Signing.ECDSASignature(derRepresentation: Data(b64u: body["signature"]!)!)
        XCTAssertTrue(key.credKey.publicKey.isValidSignature(sig, for: Data(b64u: body["authenticator_data"]!)! + Data(SHA256.hash(data: cd))))
    }

    func testPinRules() {
        XCTAssertThrowsError(try CTAP2Client.pinBytes("123"))
        XCTAssertThrowsError(try CTAP2Client.pinBytes(String(repeating: "a", count: 64)))
        XCTAssertEqual(try CTAP2Client.pinBytes("Cafe\u{301}"), Data("Caf\u{e9}".utf8))     // NFC
        XCTAssertNoThrow(try CTAP2Client.pinBytes("1234"))
    }
}
