import XCTest
import CryptoKit
@testable import AtlasDesktopCore

final class CryptoVectorTests: XCTestCase {
    func testScryptPinVector() throws {
        let v = try Vectors.load()
        let ver = try JSONDecoder().decode(ScryptVerifier.self, from: JSONSerialization.data(withJSONObject: v.pin["verifier"]!))
        XCTAssertTrue(ver.verify(v.pin["value"] as! String))
        XCTAssertFalse(ver.verify(v.pin["wrong"] as! String))
    }

    func testScryptRFC7914() throws {
        // RFC 7914 section 12 vector 1 (empty password/salt, N=16, r=1, p=1).
        let d = try Scrypt.derive(password: Data(), salt: Data(), N: 16, r: 1, p: 1, length: 64)
        XCTAssertEqual(d.map { String(format: "%02x", $0) }.joined(),
                       "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
    }

    func testScryptRejectsHugeParams() {
        XCTAssertThrowsError(try Scrypt.derive(password: Data(), salt: Data(), N: 1 << 22, r: 8, p: 1, length: 32))
    }

    func testBundleMacAndOpen() throws {
        let v = try Vectors.load()
        let b = v.bundle
        XCTAssertTrue(b.macValid(macKey: v.macKey, deviceId: v.deviceId))
        var bad = b; bad.generation += 1
        XCTAssertFalse(bad.macValid(macKey: v.macKey, deviceId: v.deviceId))
        XCTAssertFalse(b.macValid(macKey: v.macKey, deviceId: "ddv_OTHER"))
        let p = try b.open(with: v.key)
        let expected = v.bundleJ["plaintext"] as! [String: Any]
        let want = try JSONDecoder().decode(BundlePlaintext.self, from: JSONSerialization.data(withJSONObject: expected))
        XCTAssertEqual(p, want)
        XCTAssertEqual(p.totp.secret, "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
    }

    func testOpenFailsWithWrongKeyOrTamper() throws {
        let v = try Vectors.load()
        XCTAssertThrowsError(try v.bundle.open(with: SoftwareDeviceKey.generate()))
        var t = v.bundle
        var raw = Data(b64u: t.sealed)!; raw[100] ^= 1; t.sealed = raw.b64u
        XCTAssertThrowsError(try t.open(with: v.key))
    }

    func testTOTPVectors() throws {
        let v = try Vectors.load()
        let t = v.j["totp"] as! [String: Any]
        let secret = TOTP.base32Decode(t["secret"] as! String)!
        for e in t["times"] as! [[String: Any]] {
            let unix = (e["unix"] as! NSNumber).int64Value
            XCTAssertEqual(TOTP.code(secret: secret, step: unix / 30), e["code"] as? String)
        }
    }

    func testTOTPWindowAndReplay() {
        let seed = TOTPSeed(secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", digits: 6, period: 30, algorithm: "SHA1")
        let secret = TOTP.base32Decode(seed.secret)!
        let now: Int64 = 1_800_000_000_000
        let cur = now / 30000
        XCTAssertEqual(TOTP.verify(TOTP.code(secret: secret, step: cur - 1), seed: seed, nowMs: now, lastStep: -1), cur - 1)
        XCTAssertEqual(TOTP.verify(TOTP.code(secret: secret, step: cur + 1), seed: seed, nowMs: now, lastStep: -1), cur + 1)
        XCTAssertNil(TOTP.verify(TOTP.code(secret: secret, step: cur + 2), seed: seed, nowMs: now, lastStep: -1))
        XCTAssertNil(TOTP.verify(TOTP.code(secret: secret, step: cur), seed: seed, nowMs: now, lastStep: cur))
        XCTAssertNil(TOTP.verify("12345", seed: seed, nowMs: now, lastStep: -1))
    }

    func testSignedMessageVector() throws {
        let v = try Vectors.load()
        let s = v.j["signed_message"] as! [String: Any]
        let msg = SignedMessage.build(purpose: s["purpose"] as! String, instanceId: s["instance_id"] as! String,
                                      keyId: s["key_id"] as! String, nonce: s["nonce"] as! String)
        XCTAssertEqual(msg, s["message"] as? String)
        // The server's reference signature verifies under the device public key (P1363).
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: v.key.publicJWK.x)! + Data(b64u: v.key.publicJWK.y)!)
        let ref = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: s["signature_p1363_b64u"] as! String)!)
        XCTAssertTrue(pub.isValidSignature(ref, for: Data(msg.utf8)))
        // Our own signature is 64 bytes P1363 and verifies too.
        let mine = try v.key.sign(msg)
        XCTAssertEqual(Data(b64u: mine)!.count, 64)
        XCTAssertTrue(pub.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: mine)!), for: Data(msg.utf8)))
        XCTAssertEqual(v.key.publicJWK.x, (v.j["device_public_jwk"] as! [String: Any])["x"] as? String)
        XCTAssertEqual(SignedMessage.build(purpose: "sync", instanceId: "i", keyId: "k", nonce: "n", extra: "-"), "atlas-desktop:v1:sync:i:k:n:-")
    }

    func testDERConversion() throws {
        let sig = try P256.Signing.PrivateKey().signature(for: Data("x".utf8))
        XCTAssertEqual(try DER.toP1363(sig.derRepresentation), sig.rawRepresentation)
    }
}

final class OfflineUnlockTests: XCTestCase {
    func setup() throws -> (Vectors, BundlePlaintext, TestClock, InMemorySecretStore, OfflineUnlock) {
        let v = try Vectors.load()
        let p = try v.bundle.open(with: v.key)
        let clock = TestClock(1_800_000_000_000)
        let store = InMemorySecretStore()
        return (v, p, clock, store, OfflineUnlock(store: store, clock: clock))
    }
    func code(_ p: BundlePlaintext, _ ms: Int64) -> String { TOTP.code(secret: TOTP.base32Decode(p.totp.secret)!, step: ms / 30000) }

    func testAllowThenReplayRefused() throws {
        let (v, p, clock, _, u) = try setup()
        let pin = v.pin["value"] as! String
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .allowed)
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .wrongCode)
        clock.nowMs += 30_000
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .allowed)
        XCTAssertEqual(u.queue.filter { $0.outcome == "success" }.count, 2)
    }

    func testWrongPinAndMissingPin() throws {
        let (v, p, clock, _, u) = try setup()
        XCTAssertEqual(u.attempt(plain: p, pin: v.pin["wrong"] as? String, code: code(p, clock.nowMs)), .wrongPIN)
        XCTAssertEqual(u.attempt(plain: p, pin: nil, code: code(p, clock.nowMs)), .wrongPIN)
    }

    func testFiveWrongLocksFifteenMinutesPersisted() throws {
        let (v, p, clock, store, u) = try setup()
        let pin = v.pin["value"] as! String
        for _ in 0..<4 { XCTAssertEqual(u.attempt(plain: p, pin: pin, code: "000000"), .wrongCode) }
        guard case .locked(let until) = u.attempt(plain: p, pin: pin, code: "000000") else { return XCTFail("expected lock") }
        XCTAssertEqual(until, clock.nowMs + 15 * 60_000)
        // New instance over the same store (a reboot) is still locked, even with the right code.
        let u2 = OfflineUnlock(store: store, clock: clock)
        XCTAssertEqual(u2.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .locked(untilMs: until))
        clock.nowMs = until + 1
        XCTAssertEqual(u2.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .allowed)
    }

    func testExpiryAndClockRollback() throws {
        let (v, p, clock, _, u) = try setup()
        let pin = v.pin["value"] as! String
        clock.nowMs = p.expiresAt
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .expired)
        clock.nowMs = p.expiresAt - 60_000
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .allowed)
        clock.nowMs -= 6 * 60_000   // moved back more than 5 minutes
        XCTAssertEqual(u.attempt(plain: p, pin: pin, code: code(p, clock.nowMs)), .clockTampered)
        let (_, _, c2, _, fresh) = try setup()
        c2.nowMs = p.issuedAt - 10 * 60_000  // before issuance
        XCTAssertEqual(fresh.attempt(plain: p, pin: pin, code: code(p, c2.nowMs)), .clockTampered)
    }
}

final class ConfigTests: XCTestCase {
    func testParseValid() throws {
        let j = #"{"instance_url":"https://auth.example.com","publishable_key":"pk","instance_id":"ins_1","device_id":"","device_key_id":"","enrolled":false}"#
        let c = try AgentConfig.parse(Data(j.utf8))
        XCTAssertFalse(c.enrolled); XCTAssertTrue(c.appliesTo(user: "anyone"))
    }
    func testRejectsHTTPAndIncomplete() {
        XCTAssertThrowsError(try AgentConfig.parse(Data(#"{"instance_url":"http://x.com","publishable_key":"pk","instance_id":"i","device_id":"","device_key_id":"","enrolled":false}"#.utf8)))
        XCTAssertThrowsError(try AgentConfig.parse(Data(#"{"instance_url":"https://x.com","publishable_key":"pk","instance_id":"i","device_id":"","device_key_id":"","enrolled":true}"#.utf8)))
        XCTAssertThrowsError(try AgentConfig.parse(Data("nope".utf8)))
    }
    func testEnrolledUsers() {
        var c = testConfig(); c.enrolledUsers = ["alice"]
        XCTAssertTrue(c.appliesTo(user: "alice")); XCTAssertFalse(c.appliesTo(user: "bob"))
    }
}

final class ProtocolClientTests: XCTestCase {
    func testSyncSendsSignedMessageAndHeader() async throws {
        let v = try Vectors.load()
        let http = MockHTTP()
        http.routes["nonce"] = (200, ["nonce": "n1"])
        http.routes["sync"] = (200, syncBody(required: true))
        let c = ProtocolClient(config: testConfig(), key: v.key, http: http)
        let r = try await c.sync(heldBundleId: nil)
        XCTAssertTrue(r.required)
        let call = http.calls.last!
        XCTAssertEqual(call.headers["X-Publishable-Key"], "pk_test")
        XCTAssertEqual(call.body["device_id"] as? String, "ddv_TESTVECTOR")
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: call.body["signature"] as! String)!)
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: v.key.publicJWK.x)! + Data(b64u: v.key.publicJWK.y)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: Data("atlas-desktop:v1:sync:ins_TESTVECTOR:ddv_TESTVECTOR:n1:-".utf8)))
    }

    func testRevokedAndErrors() async throws {
        let v = try Vectors.load()
        let http = MockHTTP()
        http.routes["nonce"] = (200, ["nonce": "n1"])
        http.routes["sync"] = (403, ["errors": [["code": "forbidden", "meta": ["device_status": "revoked"]]]])
        let c = ProtocolClient(config: testConfig(), key: v.key, http: http)
        do { _ = try await c.sync(heldBundleId: "ddb_1"); XCTFail() } catch { XCTAssertEqual(error as? DesktopError, .revoked) }
        http.routes["challenges/c1/verify"] = (422, ["errors": [["code": "invalid_code"]]])
        do { _ = try await c.verify(challengeId: "c1", code: "123456"); XCTFail() }
        catch { XCTAssertEqual(error as? DesktopError, .api(status: 422, code: "invalid_code", deviceStatus: nil)) }
    }

    func testEnrollBodyAndReport() async throws {
        let v = try Vectors.load()
        let http = MockHTTP()
        http.routes["enroll"] = (201, ["device": ["id": "ddv_new"], "bundle_mac_key": "abc", "offline_otp_uri": "otpauth://x"])
        http.routes["nonce"] = (200, ["nonce": "n2"]); http.routes["report"] = (200, [:])
        var cfg = testConfig(); cfg.deviceId = ""
        let c = ProtocolClient(config: cfg, key: v.key, http: http)
        let r = try await c.enroll(code: "CODE123", pin: "12345678", hostname: "mac", agentVersion: "0.1.0")
        XCTAssertEqual(r.device.id, "ddv_new")
        let b = http.calls.last!.body
        XCTAssertEqual(b["platform"] as? String, "macos"); XCTAssertEqual(b["pin"] as? String, "12345678")
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: v.key.publicJWK.x)! + Data(b64u: v.key.publicJWK.y)!)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: b["signature"] as! String)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: Data("atlas-desktop:v1:enroll:ins_TESTVECTOR:\(v.key.publicJWK.x):CODE123".utf8)))
        let c2 = ProtocolClient(config: testConfig(), key: v.key, http: http)
        try await c2.report([OfflineEvent(at: 1, outcome: "success", bundleId: "b", reason: nil)])
        let rb = http.calls.last!.body
        let payload = rb["payload"] as! String
        let rs = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: rb["signature"] as! String)!)
        XCTAssertTrue(pub.isValidSignature(rs, for: Data("atlas-desktop:v1:report:ins_TESTVECTOR:ddv_TESTVECTOR:n2:\(SignedMessage.sha256b64u(payload))".utf8)))
    }

    func testInsecureURLRefusedByHTTPClient() async {
        do { _ = try await URLSessionHTTPClient().post(URL(string: "http://example.com/x")!, headers: [:], body: Data()); XCTFail() }
        catch { XCTAssertEqual(error as? DesktopError, .insecureURL) }
    }
}

final class LoginGateTests: XCTestCase {
    func testUnverifiedPasswordMakesNoNetworkCall() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true))
        let store = InMemorySecretStore()
        let d = await gate(v, http, store).begin(user: "alice", passwordVerified: false)
        XCTAssertEqual(d, .deny("password not verified"))
        XCTAssertTrue(http.calls.isEmpty)
        // also for a break-glass or not-enrolled account: unverified is always a deny
        var cfg = testConfig(); cfg.breakGlassAccounts = ["root2"]; cfg.enrolledUsers = ["alice"]
        let g = gate(v, http, store, cfg: cfg)
        let a = await g.begin(user: "root2", passwordVerified: false), b = await g.begin(user: "bob", passwordVerified: false)
        XCTAssertEqual(a, .deny("password not verified")); XCTAssertEqual(b, .deny("password not verified"))
        XCTAssertTrue(http.calls.isEmpty)
    }

    func testBreakGlassSkipsOnlyListedAccountsAndQueuesEvent() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true))
        var cfg = testConfig(); cfg.breakGlassAccounts = ["breakglass"]
        let store = InMemorySecretStore()
        let g = gate(v, http, store, cfg: cfg)
        let d = await g.begin(user: "breakglass", passwordVerified: true)
        XCTAssertEqual(d, .allow("break-glass account")); XCTAssertTrue(http.calls.isEmpty)
        let q = OfflineUnlock(store: store, clock: TestClock(0)).queue
        XCTAssertEqual(q.last?.reason, "break_glass:breakglass")
        guard case .challenge = await g.begin(user: "alice", passwordVerified: true) else { return XCTFail("other accounts stay gated") }
    }

    func testBreakGlassConfigParses() throws {
        let j = #"{"instance_url":"https://a.com","publishable_key":"pk","instance_id":"i","device_id":"","device_key_id":"","enrolled":false,"break_glass_accounts":["bg"]}"#
        XCTAssertEqual(try AgentConfig.parse(Data(j.utf8)).breakGlassAccounts, ["bg"])
    }

    func gate(_ v: Vectors, _ http: MockHTTP, _ store: SecretStore, clock: Clock = TestClock(1_800_000_000_000), cfg: AgentConfig? = nil,
              passkey: PasskeyProvider? = nil) -> LoginGate {
        try? store.set(StateSync.macKeyName, Data(v.macKey.b64u.utf8))
        return LoginGate(config: cfg ?? testConfig(), key: v.key, http: http, secrets: store, clock: clock, passkey: passkey, sleep: { _ in try? await Task.sleep(nanoseconds: 10_000_000) })
    }
    func online(_ http: MockHTTP, _ body: [String: Any]) { http.routes["nonce"] = (200, ["nonce": "n"]); http.routes["sync"] = (200, body) }

    func testNotRequiredAllows() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: false))
        let d = await gate(v, http, InMemorySecretStore()).begin(user: "alice", passwordVerified: true)
        XCTAssertEqual(d, .allow("MFA not required"))
    }

    func testOtherAccountNotEnrolledAllows() async throws {
        let v = try Vectors.load(); var cfg = testConfig(); cfg.enrolledUsers = ["alice"]
        let d = await gate(v, MockHTTP(), InMemorySecretStore(), cfg: cfg).begin(user: "bob", passwordVerified: true)
        XCTAssertEqual(d, .allow("account not enrolled"))
    }

    func testRequiredPushVerified() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "push", "expires_at": 1, "number_match": "42"])
        let g = gate(v, http, InMemorySecretStore())
        guard case .challenge(let p) = await g.begin(user: "alice", passwordVerified: true) else { return XCTFail() }
        XCTAssertTrue(p.online); XCTAssertEqual(p.factors, ["push", "totp"])
        http.routes["challenges/c1/verify"] = (200, ["status": "pending"])
        var shown: String?
        let task = Task { await g.runPush(onNumber: { shown = $0 }) }
        try await Task.sleep(nanoseconds: 100_000_000)
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let out = await task.value
        XCTAssertEqual(out, .allowed); XCTAssertEqual(shown, "42")
    }

    func testPushFailedAndTotpRetry() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "push", "number_match": "7"])
        http.routes["challenges/c1/verify"] = (200, ["status": "failed"])
        let g = gate(v, http, InMemorySecretStore()); _ = await g.begin(user: "a", passwordVerified: true)
        let out = await g.runPush(onNumber: { _ in }); XCTAssertEqual(out, .rejected("denied on phone"))
        http.routes["challenges/c1/verify"] = (422, ["errors": [["code": "invalid_code"]]])
        let r1 = await g.verifyCode("123456"); XCTAssertEqual(r1, .retry("incorrect code"))
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let r2 = await g.verifyCode("123456"); XCTAssertEqual(r2, .allowed)
        let r3 = await g.verifyCode("12"); XCTAssertEqual(r3, .retry("enter the 6-digit code"))
    }

    func testPasskeyUnsupportedWithoutProviderAndInjected() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, factors: ["passkey"]))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "passkey", "passkey_options": ["challenge": "x"]])
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let g1 = gate(v, http, InMemorySecretStore()); _ = await g1.begin(user: "a", passwordVerified: true)
        let u = await g1.runPasskey(); XCTAssertEqual(u, .unsupported)
        let g2 = gate(v, http, InMemorySecretStore(), passkey: { _ in ["challenge": "x", "credential_id": "c", "authenticator_data": "a", "client_data_json": "j", "signature": "s"] })
        _ = await g2.begin(user: "a", passwordVerified: true)
        let ok = await g2.runPasskey(); XCTAssertEqual(ok, .allowed)
        XCTAssertNotNil((http.calls.last!.body["assertion"] as? [String: String])?["credential_id"])
    }

    func testRevokedDenies() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); http.routes["nonce"] = (200, ["nonce": "n"])
        http.routes["sync"] = (403, ["errors": [["code": "x", "meta": ["device_status": "revoked"]]]])
        let store = InMemorySecretStore()
        let dd1 = await gate(v, http, store).begin(user: "a", passwordVerified: true); XCTAssertEqual(dd1, .deny("device revoked"))
        // Stays denied offline afterwards.
        http.down = true
        let d = await gate(v, http, store).begin(user: "a", passwordVerified: true)
        if case .allow = d { XCTFail("revoked device must not allow") }
    }

    func testNeverSyncedAndUnreachableFailsClosed() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); http.down = true
        let dd2 = await gate(v, http, InMemorySecretStore()).begin(user: "a", passwordVerified: true); XCTAssertEqual(dd2, .deny("MFA state unknown"))
        var cfg = testConfig(); cfg.failOpenWhenNeverSynced = true
        guard case .allow = await gate(v, http, InMemorySecretStore(), cfg: cfg).begin(user: "a", passwordVerified: true) else { return XCTFail() }
    }

    func testNotEnrolledFailsClosed() async throws {
        let v = try Vectors.load(); var cfg = testConfig(); cfg.enrolled = false; cfg.deviceId = ""
        let dd3 = await gate(v, MockHTTP(), InMemorySecretStore(), cfg: cfg).begin(user: "a", passwordVerified: true); XCTAssertEqual(dd3, .deny("device not enrolled"))
    }

    func testOfflineRequiredNoBundleDenied() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, bundle: nil))
        let store = InMemorySecretStore()
        _ = await gate(v, http, store).begin(user: "a", passwordVerified: true)   // caches required = true, no bundle
        http.down = true
        let dd4 = await gate(v, http, store).begin(user: "a", passwordVerified: true); XCTAssertEqual(dd4, .deny("offline and no valid offline bundle"))
    }

    func testOfflineUnlockWithBundle() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, bundle: v.bundle))
        let store = InMemorySecretStore(); let clock = TestClock(1_800_000_000_000)
        let g1 = gate(v, http, store, clock: clock); _ = await g1.begin(user: "a", passwordVerified: true)
        XCTAssertNotNil(store.load(GateState.self, GateState.key)?.bundle)
        http.down = true
        let g = gate(v, http, store, clock: clock)
        guard case .challenge(let p) = await g.begin(user: "a", passwordVerified: true) else { return XCTFail() }
        XCTAssertFalse(p.online); XCTAssertTrue(p.offlineAvailable); XCTAssertTrue(p.factors.isEmpty)
        let pin = v.pin["value"] as! String
        let secret = TOTP.base32Decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")!
        let good = TOTP.code(secret: secret, step: clock.nowMs / 30000)
        XCTAssertEqual(g.offline(pin: v.pin["wrong"] as? String, code: good), .retry("incorrect PIN or code"))
        XCTAssertEqual(g.offline(pin: pin, code: good), .allowed)
        XCTAssertEqual(g.offline(pin: pin, code: good), .retry("incorrect PIN or code"))  // replay
        // Events were queued and are uploaded on the next successful sync.
        http.down = false; http.routes["report"] = (200, [:])
        let g3 = gate(v, http, store, clock: clock); _ = await g3.begin(user: "a", passwordVerified: true)
        XCTAssertTrue(http.calls.contains { $0.path == "report" })
        XCTAssertTrue(OfflineUnlock(store: store, clock: clock).queue.isEmpty)
    }

    func testOfflineRefusedWhileOnlineAndTamperedBundle() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, bundle: v.bundle))
        let store = InMemorySecretStore()
        let g = gate(v, http, store); _ = await g.begin(user: "a", passwordVerified: true)
        XCTAssertEqual(g.offline(pin: "24681357", code: "000000"), .rejected("offline unlock unavailable"))
        var st = store.load(GateState.self, GateState.key)!; st.bundle!.generation += 1
        try store.save(st, GateState.key); http.down = true
        let d = await gate(v, http, store).begin(user: "a", passwordVerified: true)
        XCTAssertEqual(d, .deny("offline and no valid offline bundle"))
    }

    func testKeepCacheFalseWipesBundle() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, bundle: v.bundle))
        let store = InMemorySecretStore(); _ = await gate(v, http, store).begin(user: "a", passwordVerified: true)
        online(http, syncBody(required: true, bundle: nil, keep: false))
        _ = await gate(v, http, store).begin(user: "a", passwordVerified: true)
        XCTAssertNil(store.load(GateState.self, GateState.key)?.bundle)
    }

    func testForgedBundleMacIgnored() async throws {
        let v = try Vectors.load(); var b = v.bundle; b.mac = Data(repeating: 1, count: 32).b64u
        let http = MockHTTP(); online(http, syncBody(required: true, bundle: b))
        let store = InMemorySecretStore(); _ = await gate(v, http, store).begin(user: "a", passwordVerified: true)
        XCTAssertNil(store.load(GateState.self, GateState.key)?.bundle)
    }
}

// MARK: - pam_atlas helper protocol

final class PamHelperTests: XCTestCase {
    func make(_ http: MockHTTP, cfg: AgentConfig? = nil, store: SecretStore = InMemorySecretStore(), clock: Clock = TestClock(1_800_000_000_000), keyless: Bool = false) throws -> PamHelper {
        let v = try Vectors.load()
        try? store.set(StateSync.macKeyName, Data(v.macKey.b64u.utf8))
        let c = cfg ?? testConfig()
        let g: LoginGate? = keyless ? nil : LoginGate(config: c, key: v.key, http: http, secrets: store, clock: clock, sleep: { _ in try? await Task.sleep(nanoseconds: 5_000_000) })
        return PamHelper(config: c, gate: g)
    }
    func online(_ http: MockHTTP, _ body: [String: Any]) { http.routes["nonce"] = (200, ["nonce": "n"]); http.routes["sync"] = (200, body) }
    func run(_ h: PamHelper, _ line: String) async -> (lines: [String], more: Bool) {
        var out: [String] = []
        let more = await h.handle(line, out: { out.append($0) })
        return (out, more)
    }

    func testChallengeAllowDenyAndBreakGlass() async throws {
        let http = MockHTTP(); online(http, syncBody(required: true, factors: ["push", "totp", "passkey"]))
        let r = await run(try make(http), "BEGIN alice sudo")
        XCTAssertEqual(r.lines, ["CHALLENGE online=1 push=1 totp=1 offline=0 pin=1"]); XCTAssertTrue(r.more)   // passkey is not offered to a terminal

        let off = MockHTTP(); online(off, syncBody(required: false))
        let a = await run(try make(off), "BEGIN alice sshd"); XCTAssertEqual(a.lines, ["ALLOW MFA not required"]); XCTAssertTrue(a.more)

        var cfg = testConfig(); cfg.breakGlassAccounts = ["atlas-breakglass"]
        let bg = MockHTTP()
        let b = await run(try make(bg, cfg: cfg), "BEGIN atlas-breakglass screensharing")
        XCTAssertEqual(b.lines, ["ALLOW break-glass account"]); XCTAssertTrue(bg.calls.isEmpty)       // no network for a break-glass login

        let rev = MockHTTP(); rev.routes["nonce"] = (200, ["nonce": "n"]); rev.routes["sync"] = (403, ["errors": [["code": "forbidden", "meta": ["device_status": "revoked"]]]])
        let d = await run(try make(rev), "BEGIN alice su"); XCTAssertEqual(d.lines, ["DENY device revoked"]); XCTAssertFalse(d.more)
    }

    func testPasskeyOnlyPolicyIsRefusedWithoutOfflineBundle() async throws {
        let http = MockHTTP(); online(http, syncBody(required: true, factors: ["passkey"], enabled: false))
        let r = await run(try make(http), "BEGIN alice sudo")
        XCTAssertEqual(r.lines, ["DENY no usable factor for this service"]); XCTAssertFalse(r.more)
    }

    func testBadRequestsNeverReachTheGate() async throws {
        let http = MockHTTP(); online(http, syncBody(required: false))
        for line in ["BEGIN al\u{0}ice sudo", "BEGIN alice", "BEGIN a b c", "BEGIN -rf sudo", "BEGIN alice sudo;x", "BEGIN alice\tsudo", "BEGIN  alice sudo", ""] {
            let h = try make(http); let r = await run(h, line)
            XCTAssertEqual(r.lines.count, 1, line); XCTAssertTrue(r.lines[0].hasPrefix("DENY") || r.lines[0].hasPrefix("REJECT"), line); XCTAssertFalse(r.more, line)
        }
        XCTAssertTrue(http.calls.isEmpty)
        // A second BEGIN, or a command before BEGIN, is refused.
        let h = try make(http)
        let early = await run(h, "CODE 123456"); XCTAssertEqual(early.lines.first?.hasPrefix("REJECT"), true)
        _ = await run(h, "BEGIN alice sudo")
        let again = await run(h, "BEGIN alice sudo"); XCTAssertEqual(again.lines.first?.hasPrefix("DENY"), true)
        let unknown = await run(h, "SUDO"); XCTAssertFalse(unknown.more)
    }

    func testCodeFlow() async throws {
        let http = MockHTTP(); online(http, syncBody(required: true))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "totp", "expires_at": 1])
        let h = try make(http)
        _ = await run(h, "BEGIN alice sudo")
        http.routes["challenges/c1/verify"] = (422, ["errors": [["code": "invalid_code"]]])
        let wrong = await run(h, "CODE 000000"); XCTAssertEqual(wrong.lines, ["RETRY incorrect code"])
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let ok = await run(h, "CODE 123456"); XCTAssertEqual(ok.lines, ["OK"])
        // Malformed codes never go out.
        let n = http.calls.count
        for bad in ["CODE 12345", "CODE 1234567", "CODE abcdef", "CODE", "CODE 123456 x"] { let r = await run(h, bad); XCTAssertEqual(r.lines.first?.hasPrefix("REJECT"), true, bad) }
        XCTAssertEqual(http.calls.count, n)
    }

    func testPushFlowReportsTheNumberThenTheOutcome() async throws {
        let http = MockHTTP(); online(http, syncBody(required: true))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "push", "number_match": "42"])
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let h = try make(http); _ = await run(h, "BEGIN alice sudo")
        let r = await run(h, "PUSH"); XCTAssertEqual(r.lines, ["NUMBER 42", "OK"])
        let http2 = MockHTTP(); online(http2, syncBody(required: true))
        http2.routes["challenges"] = (201, ["id": "c2", "factor": "push", "number_match": "7"]); http2.routes["challenges/c2/verify"] = (200, ["status": "failed"])
        let h2 = try make(http2); _ = await run(h2, "BEGIN alice sudo")
        let d = await run(h2, "PUSH"); XCTAssertEqual(d.lines, ["NUMBER 7", "REJECT denied on phone"])
        // push is refused when the policy does not allow it
        let http3 = MockHTTP(); online(http3, syncBody(required: true, factors: ["totp"]))
        let h3 = try make(http3); _ = await run(h3, "BEGIN alice sudo")
        let n = await run(h3, "PUSH"); XCTAssertEqual(n.lines, ["REJECT push unavailable"])
    }

    func testOfflineFlowAndUnreachableFallback() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); online(http, syncBody(required: true, bundle: v.bundle))
        let store = InMemorySecretStore(); let clock = TestClock(1_800_000_000_000)
        _ = await run(try make(http, store: store, clock: clock), "BEGIN a sshd")   // caches the bundle
        http.down = true
        let h = try make(http, store: store, clock: clock)
        let c = await run(h, "BEGIN a sshd"); XCTAssertEqual(c.lines, ["CHALLENGE online=0 push=0 totp=0 offline=1 pin=1"])
        let pin = v.pin["value"] as! String
        let secret = TOTP.base32Decode("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")!
        let good = TOTP.code(secret: secret, step: clock.nowMs / 30000)
        let wrong = await run(h, "OFFLINE \(pin) 000000"); XCTAssertEqual(wrong.lines.first?.hasPrefix("RETRY"), true)
        let ok = await run(h, "OFFLINE \(pin) \(good)"); XCTAssertEqual(ok.lines, ["OK"])
        let replay = await run(h, "OFFLINE \(pin) \(good)"); XCTAssertEqual(replay.lines.first?.hasPrefix("RETRY"), true)
        let bad = await run(h, "OFFLINE 12 \(good)"); XCTAssertEqual(bad.lines.first?.hasPrefix("REJECT"), true)
    }

    func testNoDeviceKeyOnlyBreakGlassAndUncoveredAccountsPass() async throws {
        var cfg = testConfig(); cfg.enrolledUsers = ["alice"]; cfg.breakGlassAccounts = ["bg"]
        let http = MockHTTP()
        let a = await run(try make(http, cfg: cfg, keyless: true), "BEGIN alice sudo"); XCTAssertEqual(a.lines, ["DENY this Mac is not enrolled"])
        let b = await run(try make(http, cfg: cfg, keyless: true), "BEGIN bob sudo"); XCTAssertEqual(b.lines, ["ALLOW account not enrolled"])
        let c = await run(try make(http, cfg: cfg, keyless: true), "BEGIN bg sudo"); XCTAssertEqual(c.lines, ["ALLOW break-glass account"])
        XCTAssertTrue(http.calls.isEmpty)
    }
}
