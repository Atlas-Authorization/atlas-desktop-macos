import XCTest
import CryptoKit
@testable import AtlasDesktopCore

/// Stands in for the platform back end. Echoes the client data it was given unless told to sign something else.
final class FakeAuthenticator: PasskeyAuthenticator {
    var available = true
    var clientDataOverride: Data?
    var empty = false
    var cancel = false
    var assertions = 0, registrations = 0
    var lastRequest: PasskeyRequest?
    func assertion(_ request: PasskeyRequest, clientData: Data) async throws -> RawAssertion {
        assertions += 1; lastRequest = request
        if cancel { throw PasskeyError.cancelled }
        return RawAssertion(credentialId: empty ? Data() : Data([1, 2, 3]), authenticatorData: Data([4, 5, 6]), signature: Data([7, 8, 9]), clientDataJSON: clientDataOverride ?? clientData)
    }
    func registration(_ creation: PasskeyCreation, clientData: Data) async throws -> RawAttestation {
        registrations += 1
        return RawAttestation(credentialId: Data([1, 2, 3]), attestationObject: Data([0xa1, 0x00]), clientDataJSON: clientDataOverride ?? clientData, transports: ["usb"])
    }
}

let goodChallenge = "QUJDREVGR0hJSktMTU5PUA"   // 16 bytes
func goodOptions() -> [String: Any] {
    ["challenge": goodChallenge, "rpId": "auth.example.com", "origin": "https://auth.example.com", "userVerification": "required",
     "allowCredentials": [["type": "public-key", "id": "AQID", "transports": ["usb"]]], "timeout": 60000]
}
func goodCreation() -> [String: Any] {
    ["challenge": goodChallenge, "rp": ["id": "auth.example.com", "name": "Atlas"], "origin": "https://auth.example.com",
     "user": ["id": "dXNyXzE", "name": "u", "displayName": "U"], "pubKeyCredParams": [["type": "public-key", "alg": -7], ["type": "public-key", "alg": -257]],
     "excludeCredentials": [["type": "public-key", "id": "AQID"]], "authenticatorSelection": ["userVerification": "required"], "timeout": 5]
}

final class PasskeyParsingTests: XCTestCase {
    func testAcceptsTheServersOptions() throws {
        let r = try Passkey.parseRequest(goodOptions())
        XCTAssertEqual(r.rpId, "auth.example.com"); XCTAssertEqual(r.userVerification, "required"); XCTAssertEqual(r.timeoutMs, 60000)
        XCTAssertEqual(r.allow, [PasskeyCredentialDescriptor(id: Data([1, 2, 3]), transports: ["usb"])])
        XCTAssertEqual(r.challengeBytes.count, 16)
    }

    func testOriginMustBeExactlyHttpsRpId() {
        for bad in ["http://auth.example.com", "https://auth.example.com:8443", "https://evil.example", "https://x.auth.example.com", "https://auth.example.com/", "", "auth.example.com"] {
            var o = goodOptions(); o["origin"] = bad
            XCTAssertThrowsError(try Passkey.parseRequest(o), bad)
        }
        var o = goodOptions(); o["rpId"] = ""; o["origin"] = "https://"
        XCTAssertThrowsError(try Passkey.parseRequest(o))
    }

    func testRejectsMalformedFieldsAndClampsTimeout() throws {
        func bad(_ k: String, _ v: Any, line: UInt = #line) {
            var o = goodOptions(); o[k] = v
            XCTAssertThrowsError(try Passkey.parseRequest(o), k, line: line)
        }
        bad("challenge", "AAAA"); bad("challenge", "QUJD=REVGR0hJSktMTU5PUA"); bad("challenge", 5); bad("userVerification", "sometimes")
        bad("allowCredentials", "x"); bad("allowCredentials", [["id": "!!"]]); bad("allowCredentials", [["type": "public-key"]])
        var o = goodOptions(); o["timeout"] = 1; XCTAssertEqual(try Passkey.parseRequest(o).timeoutMs, 10_000)
        o["timeout"] = 99_999_999; XCTAssertEqual(try Passkey.parseRequest(o).timeoutMs, 120_000)
        o.removeValue(forKey: "timeout"); XCTAssertEqual(try Passkey.parseRequest(o).timeoutMs, 60_000)
        o.removeValue(forKey: "allowCredentials"); XCTAssertTrue(try Passkey.parseRequest(o).allow.isEmpty)
    }

    func testCreationOptions() throws {
        let c = try Passkey.parseCreation(goodCreation())
        XCTAssertEqual(c.rpId, "auth.example.com"); XCTAssertEqual(c.userId, Data("usr_1".utf8)); XCTAssertEqual(c.algorithms, [-7, -257])
        XCTAssertEqual(c.exclude, [Data([1, 2, 3])]); XCTAssertEqual(c.userVerification, "required"); XCTAssertEqual(c.timeoutMs, 10_000)
        func bad(_ mutate: (inout [String: Any]) -> Void, line: UInt = #line) { var o = goodCreation(); mutate(&o); XCTAssertThrowsError(try Passkey.parseCreation(o), line: line) }
        bad { $0["origin"] = "https://evil.example" }
        bad { $0["pubKeyCredParams"] = [[String: Any]]() }
        bad { $0.removeValue(forKey: "rp") }
        bad { $0["user"] = ["id": "dXNyXzE", "name": ""] }
        bad { $0["challenge"] = "short" }
    }

    func testClientDataIsStableJSONAndChecked() throws {
        let cd = Passkey.clientDataJSON(type: "webauthn.get", challenge: goodChallenge, origin: "https://auth.example.com")
        XCTAssertEqual(String(decoding: cd, as: UTF8.self), "{\"type\":\"webauthn.get\",\"challenge\":\"\(goodChallenge)\",\"origin\":\"https://auth.example.com\",\"crossOrigin\":false}")
        XCTAssertNoThrow(try Passkey.checkClientData(cd, type: "webauthn.get", challenge: goodChallenge, origin: "https://auth.example.com"))
        XCTAssertThrowsError(try Passkey.checkClientData(cd, type: "webauthn.create", challenge: goodChallenge, origin: "https://auth.example.com"))
        XCTAssertThrowsError(try Passkey.checkClientData(cd, type: "webauthn.get", challenge: "other", origin: "https://auth.example.com"))
        XCTAssertThrowsError(try Passkey.checkClientData(cd, type: "webauthn.get", challenge: goodChallenge, origin: "https://evil.example"))
        XCTAssertThrowsError(try Passkey.checkClientData(Data("nope".utf8), type: "webauthn.get", challenge: goodChallenge, origin: "https://auth.example.com"))
        // Quotes in a value cannot break the document.
        let tricky = Passkey.clientDataJSON(type: "webauthn.get", challenge: "a\"b", origin: "https://x")
        XCTAssertEqual((try JSONSerialization.jsonObject(with: tricky) as? [String: Any])?["challenge"] as? String, "a\"b")
    }
}

final class PasskeyProviderTests: XCTestCase {
    func testProviderBuildsTheAssertionTheServerVerifies() async throws {
        let fa = FakeAuthenticator()
        let body = try await Passkey.provider(for: fa)(goodOptions())
        XCTAssertEqual(body["challenge"], goodChallenge); XCTAssertEqual(body["credential_id"], "AQID")
        XCTAssertEqual(body["authenticator_data"], "BAUG"); XCTAssertEqual(body["signature"], "BwgJ")
        let cd = try JSONSerialization.jsonObject(with: Data(b64u: body["client_data_json"]!)!) as! [String: Any]
        XCTAssertEqual(cd["type"] as? String, "webauthn.get"); XCTAssertEqual(cd["origin"] as? String, "https://auth.example.com")
        XCTAssertEqual(fa.lastRequest?.userVerification, "required")
    }

    func testProviderRefusesBadOptionsAndBadClientData() async {
        let fa = FakeAuthenticator()
        var o = goodOptions(); o["origin"] = "https://evil.example"
        do { _ = try await Passkey.provider(for: fa)(o); XCTFail() } catch {}
        XCTAssertEqual(fa.assertions, 0)                       // never reached the authenticator
        fa.available = false
        do { _ = try await Passkey.provider(for: fa)(goodOptions()); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .unavailable) }
        fa.available = true
        fa.clientDataOverride = Passkey.clientDataJSON(type: "webauthn.get", challenge: goodChallenge, origin: "https://evil.example")
        do { _ = try await Passkey.provider(for: fa)(goodOptions()); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .clientDataMismatch("origin")) }
        fa.clientDataOverride = Passkey.clientDataJSON(type: "webauthn.get", challenge: "AAAAAAAAAAAAAAAAAAAAAA", origin: "https://auth.example.com")
        do { _ = try await Passkey.provider(for: fa)(goodOptions()); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .clientDataMismatch("challenge")) }
        fa.clientDataOverride = nil; fa.empty = true
        do { _ = try await Passkey.provider(for: fa)(goodOptions()); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .failed("empty assertion")) }
    }

    func gate(_ v: Vectors, _ http: MockHTTP, _ fa: FakeAuthenticator) -> LoginGate {
        let store = InMemorySecretStore(); try? store.set(StateSync.macKeyName, Data(v.macKey.b64u.utf8))
        return LoginGate(config: testConfig(), key: v.key, http: http, secrets: store, clock: TestClock(1_800_000_000_000), passkey: Passkey.provider(for: fa), sleep: { _ in })
    }

    func testGatePasskeyEndToEnd() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); let fa = FakeAuthenticator()
        http.routes["nonce"] = (200, ["nonce": "n"]); http.routes["sync"] = (200, syncBody(required: true, factors: ["passkey"]))
        http.routes["challenges"] = (201, ["id": "c1", "factor": "passkey", "passkey_options": goodOptions()])
        http.routes["challenges/c1/verify"] = (200, ["status": "verified"])
        let g = gate(v, http, fa); _ = await g.begin(user: "a", passwordVerified: true)
        let out = await g.runPasskey(); XCTAssertEqual(out, .allowed)
        let sent = http.calls.last!.body["assertion"] as? [String: String]
        XCTAssertEqual(sent?["credential_id"], "AQID"); XCTAssertEqual(sent?["challenge"], goodChallenge)

        // The server refusing the assertion is a refusal, not a retry of the same challenge.
        http.routes["challenges/c1/verify"] = (422, ["errors": [["code": "verification_failed"]]])
        let g2 = gate(v, http, fa); _ = await g2.begin(user: "a", passwordVerified: true)
        let r = await g2.runPasskey(); XCTAssertEqual(r, .rejected("passkey rejected"))
        // Cancelled by the person.
        fa.cancel = true
        let g3 = gate(v, http, fa); _ = await g3.begin(user: "a", passwordVerified: true)
        let c = await g3.runPasskey(); XCTAssertEqual(c, .rejected("cancelled"))
        // No back end available: unsupported, and the server was not asked to start anything beyond the challenge.
        fa.cancel = false; fa.available = false
        let g4 = gate(v, http, fa); _ = await g4.begin(user: "a", passwordVerified: true)
        let u = await g4.runPasskey(); XCTAssertEqual(u, .unsupported)
    }

    func testEnrolFlowSignsAndShapesTheCredential() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); let fa = FakeAuthenticator()
        http.routes["nonce"] = (200, ["nonce": "n9"])
        http.routes["passkeys/options"] = (201, ["registration_id": "ddc_1", "passkey_options": goodCreation()])
        http.routes["passkeys/ddc_1/enrol"] = (201, ["object": "desktop_passkey", "id": "ddp_7"])
        let client = ProtocolClient(config: testConfig(), key: v.key, http: http)
        let id = try await Passkey.enroll(client: client, authenticator: fa, proofChallengeId: "ddc_1", name: "Desk key")
        XCTAssertEqual(id, "ddp_7"); XCTAssertEqual(fa.registrations, 1)

        func verifies(_ call: (path: String, body: [String: Any], headers: [String: String]), _ message: String) throws -> Bool {
            let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: call.body["signature"] as! String)!)
            let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: v.key.publicJWK.x)! + Data(b64u: v.key.publicJWK.y)!)
            return pub.isValidSignature(sig, for: Data(message.utf8))
        }
        let opts = http.calls.first { $0.path == "passkeys/options" }!
        XCTAssertTrue(try verifies(opts, "atlas-desktop:v1:passkey_options:ins_TESTVECTOR:ddv_TESTVECTOR:n9:ddc_1"))
        XCTAssertEqual(opts.body["proof_challenge_id"] as? String, "ddc_1")
        let fin = http.calls.last!
        XCTAssertTrue(try verifies(fin, "atlas-desktop:v1:passkey_enrol:ins_TESTVECTOR:ddv_TESTVECTOR:ddc_1"))
        let cred = fin.body["credential"] as! [String: String]
        XCTAssertEqual(cred["attestation_object"], "oQA"); XCTAssertEqual(cred["challenge"], goodChallenge)
        XCTAssertEqual(fin.body["name"] as? String, "Desk key"); XCTAssertEqual(fin.body["transports"] as? [String], ["usb"])
    }

    func testEnrolStopsBeforeTheAuthenticatorWhenTheServerRefuses() async throws {
        let v = try Vectors.load(); let http = MockHTTP(); let fa = FakeAuthenticator()
        http.routes["nonce"] = (200, ["nonce": "n"]); http.routes["passkeys/options"] = (403, ["errors": [["code": "verification_failed"]]])
        let client = ProtocolClient(config: testConfig(), key: v.key, http: http)
        do { _ = try await Passkey.enroll(client: client, authenticator: fa, proofChallengeId: "x", name: nil); XCTFail() } catch { XCTAssertEqual(fa.registrations, 0) }
        fa.available = false
        do { _ = try await Passkey.enroll(client: client, authenticator: fa, proofChallengeId: "x", name: nil); XCTFail() } catch { XCTAssertEqual(error as? PasskeyError, .unavailable) }
    }
}
