import XCTest
import CryptoKit
@testable import AtlasDesktopCore

private func hex(_ s: String) -> Data {
    var d = Data(); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); d.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return d
}

/// Answers the Platform SSO endpoints like the Atlas server does (desktop/DEVICE_SSO.md) and records what the client sent.
private final class PSSOServer: HTTPClient {
    var calls: [(path: String, body: [String: Any], headers: [String: String])] = []
    var configStatus = 200
    var config: [String: Any] = [
        "enabled": true, "instance_id": "ins_T", "issuer": "https://auth.example.com", "client_id": "pk_test", "audience": "https://auth.example.com",
        "token_endpoint": "https://auth.example.com/v1/client/device_sso/token", "nonce_endpoint": "https://auth.example.com/v1/client/device_sso/token",
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json", "protocol_version": 1, "session_minutes": 480, "refresh_days": 30,
    ]
    var reply: [String: (Int, [String: Any])] = [:]
    func get(_ url: URL, headers: [String: String]) async throws -> HTTPResponse {
        calls.append((url.lastPathComponent, [:], headers))
        return HTTPResponse(status: configStatus, data: try JSONSerialization.data(withJSONObject: config))
    }
    func post(_ url: URL, headers: [String: String], body: Data) async throws -> HTTPResponse {
        let path = url.lastPathComponent
        var parsed: [String: Any] = (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:]
        if parsed.isEmpty, let s = String(data: body, encoding: .utf8) {
            for pair in s.split(separator: "&") { let kv = pair.split(separator: "=", maxSplits: 1).map(String.init); if kv.count == 2 { parsed[kv[0]] = kv[1] } }
        }
        calls.append((path, parsed, headers))
        if path == "token", parsed["grant_type"] as? String == "srv_challenge" { return HTTPResponse(status: 200, data: try JSONSerialization.data(withJSONObject: ["Nonce": "srv-nonce-1"])) }
        let (s, o) = reply[path] ?? (404, ["errors": [["code": "not_found"]]])
        return HTTPResponse(status: s, data: try JSONSerialization.data(withJSONObject: o))
    }
}

final class PlatformSSOTests: XCTestCase {
    let regJSON: [String: Any] = ["id": "dsso_1", "user_id": "usr_1", "status": "active", "user_key_registered": false]

    func testConcatKDFReproducesApplesPublishedExample() {
        // https://developer.apple.com/documentation/authenticationservices/creating-a-json-web-encryption-jwe-login-response
        let z = hex("3491708C92422BB807EDF2B8183A42737C5DAA6C39BA9535321D51C836D7ADA1")
        let apu = hex("000000054150504C45000000410406414745842895EAB7F4BA651AA95C9AC11D9F0EB8C34C1B71B1C0123ACCE29C8DB3A85996E00C54C47CB6B53BFED9B89CB747C7765C0C340875942A624BB1B5")
        let apv = hex("000000054170706C65000000410499C272AF606A5101E5B1C686A164F0FF840DC4352A235951D75902440CCB26493FF98BB592A830C0B71BC3ED46578ACE6D5CE43D1A7CF657FFAD6CEF40B1EF920000002442374631464333322D393132312D344532412D394533322D383431374530333637354444")
        let key = PSSOJose.concatKDF(z: z, apu: apu, apv: apv)
        XCTAssertEqual(key.withUnsafeBytes { Data($0) }, hex("A146E4A23BDA2E53826C04D2F442BCFBD87BC2719D74B8A7DA00AF976267712E"))
    }

    /// The server's side of the response, written independently of the opener: ECDH-ES with an ephemeral key, Apple's PartyUInfo, A256GCM over the header.
    private func seal(_ payload: [String: Any], to device: SoftwareDeviceKey, apv: Data) throws -> String {
        let eph = P256.KeyAgreement.PrivateKey()
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + Data(b64u: device.publicJWK.x)! + Data(b64u: device.publicJWK.y)!)
        let z = try eph.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        let point = eph.publicKey.x963Representation
        func lp(_ d: Data) -> Data { var n = UInt32(d.count).bigEndian; return Data(bytes: &n, count: 4) + d }
        let apu = lp(Data("APPLE".utf8)) + lp(point)
        let key = PSSOJose.concatKDF(z: z, apu: apu, apv: apv)
        let header: [String: Any] = ["alg": "ECDH-ES", "enc": "A256GCM", "typ": "platformsso-login-response+jwt", "apu": apu.b64u, "apv": apv.b64u,
                                     "epk": ["kty": "EC", "crv": "P-256", "x": Data(point[1..<33]).b64u, "y": Data(point[33..<65]).b64u]]
        let h = try JSONSerialization.data(withJSONObject: header).b64u
        let box = try AES.GCM.seal(try JSONSerialization.data(withJSONObject: payload), using: key, nonce: AES.GCM.Nonce(), authenticating: Data(h.utf8))
        return [h, "", Data(box.nonce).b64u, box.ciphertext.b64u, box.tag.b64u].joined(separator: ".")
    }

    func testOpensALoginResponseAndRefusesTamperingAndTheWrongKey() throws {
        let device = SoftwareDeviceKey.generate()
        let jwe = try seal(["id_token": "a.b.c", "refresh_token": "dsrt_x", "expires_in": 28800], to: device, apv: Data("apv-from-device".utf8))
        let out = try PSSOJose.openLoginResponse(jwe, encryptionKey: device)
        XCTAssertEqual(out["refresh_token"] as? String, "dsrt_x")
        XCTAssertEqual(out["expires_in"] as? Int, 28800)
        XCTAssertThrowsError(try PSSOJose.openLoginResponse(jwe, encryptionKey: SoftwareDeviceKey.generate()))
        var parts = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var header = try JSONSerialization.jsonObject(with: Data(b64u: parts[0])!) as! [String: Any]
        header["typ"] = "JWT"
        parts[0] = try JSONSerialization.data(withJSONObject: header).b64u
        XCTAssertThrowsError(try PSSOJose.openLoginResponse(parts.joined(separator: "."), encryptionKey: device)) // header is authenticated data
        XCTAssertThrowsError(try PSSOJose.openLoginResponse("not.a.jwe", encryptionKey: device))
        parts = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        parts[3] = Data(b64u: parts[3])!.map { $0 ^ 1 }.reduce(into: Data()) { $0.append($1) }.b64u
        XCTAssertThrowsError(try PSSOJose.openLoginResponse(parts.joined(separator: "."), encryptionKey: device))
    }

    func testKidIsBase64OfTheSHA256OfTheX963Point() {
        let k = SoftwareDeviceKey.generate()
        let point = Data([4]) + Data(b64u: k.publicJWK.x)! + Data(b64u: k.publicJWK.y)!
        XCTAssertEqual(k.pssoKid, Data(SHA256.hash(data: point)).base64EncodedString())
        XCTAssertTrue(k.pssoKid.hasSuffix("="))
        XCTAssertEqual(k.pssoKid.count, 44)
    }

    func testConfigurationIsReadWithThePublishableKeyAndRefusesAnEndpointOffHTTPS() async throws {
        let s = PSSOServer()
        let c = PSSOClient(instanceURL: URL(string: "https://auth.example.com")!, publishableKey: "pk_test", http: s)
        let cfg = try await c.configuration()
        XCTAssertEqual(cfg.clientId, "pk_test")
        XCTAssertEqual(cfg.tokenEndpoint, "https://auth.example.com/v1/client/device_sso/token")
        XCTAssertEqual(s.calls.last?.headers["X-Publishable-Key"], "pk_test")
        s.config["token_endpoint"] = "http://evil.example.com/token"
        do { _ = try await c.configuration(); XCTFail("accepted a plaintext endpoint") } catch { XCTAssertEqual(error as? DesktopError, .insecureURL) }
        s.configStatus = 500
        do { _ = try await c.configuration(); XCTFail("accepted a failed response") } catch { XCTAssertEqual(error as? DesktopError, .api(status: 500, code: nil, deviceStatus: nil)) }
    }

    func testRegisterDeviceSignsTheTokenWithTheSigningKeyAndSendsBothPublicKeys() async throws {
        let s = PSSOServer(); s.reply["register_device"] = (201, regJSON)
        let c = PSSOClient(instanceURL: URL(string: "https://auth.example.com")!, publishableKey: "pk_test", http: s)
        let cfg = try await c.configuration()
        let sign = SoftwareDeviceKey.generate(), enc = SoftwareDeviceKey.generate()
        let reg = try await c.registerDevice(config: cfg, registrationToken: "dsk_code", signing: sign, encryption: enc, hostname: "MBP", agentVersion: "1.0.0")
        XCTAssertEqual(reg.id, "dsso_1")
        let sent = s.calls.last!.body
        XCTAssertEqual(sent["registration_token"] as? String, "dsk_code")
        XCTAssertEqual(sent["platform"] as? String, "macos")
        XCTAssertEqual((sent["signing_public_key"] as? [String: String])?["x"], sign.publicJWK.x)
        XCTAssertEqual((sent["encryption_public_key"] as? [String: String])?["x"], enc.publicJWK.x)
        // The signature verifies under the signing key over exactly the message the server rebuilds.
        let msg = "atlas-desktop:v1:sso_device:ins_T:\(sign.pssoKid):dsk_code"
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: sent["signature"] as! String)!)
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: sign.publicJWK.x)! + Data(b64u: sign.publicJWK.y)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: Data(msg.utf8)))
    }

    func testRegisterUserTakesAServerNonceAndNamesTheDeviceBySigningKeyId() async throws {
        let s = PSSOServer(); s.reply["register_user"] = (200, regJSON.merging(["user_key_registered": true]) { $1 })
        let c = PSSOClient(instanceURL: URL(string: "https://auth.example.com")!, publishableKey: "pk_test", http: s)
        let cfg = try await c.configuration()
        let sign = SoftwareDeviceKey.generate(), user = SoftwareDeviceKey.generate()
        let reg = try await c.registerUser(config: cfg, signing: sign, userKey: user, localUsername: "ann")
        XCTAssertTrue(reg.userKeyRegistered)
        XCTAssertEqual(s.calls.map { $0.path }, ["configuration", "token", "register_user"])
        let sent = s.calls.last!.body
        XCTAssertEqual(sent["signing_key_id"] as? String, sign.pssoKid)
        XCTAssertEqual(sent["method"] as? String, "user_secure_enclave_key")
        XCTAssertEqual(sent["local_username"] as? String, "ann")
        XCTAssertNil(sent["registration_id"])
        let msg = "atlas-desktop:v1:sso_user:ins_T:\(sign.pssoKid):srv-nonce-1:\(user.pssoKid)"
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: sent["signature"] as! String)!)
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: sign.publicJWK.x)! + Data(b64u: sign.publicJWK.y)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: Data(msg.utf8)))
    }

    func testWebSessionSignsTheRedirectAndSurfacesAServerRefusal() async throws {
        let s = PSSOServer()
        s.reply["web_session"] = (201, ["attempt_id": "sia_1", "status": "complete", "ticket": "t", "redirect_to": "https://app.example.com/home?__atlas_ticket=t"])
        let c = PSSOClient(instanceURL: URL(string: "https://auth.example.com")!, publishableKey: "pk_test", http: s)
        let cfg = try await c.configuration()
        let sign = SoftwareDeviceKey.generate()
        let w = try await c.webSession(config: cfg, signing: sign, redirectURL: "https://app.example.com/home")
        XCTAssertEqual(w.redirectTo, "https://app.example.com/home?__atlas_ticket=t")
        let sent = s.calls.last!.body
        let hash = Data(SHA256.hash(data: Data("https://app.example.com/home".utf8))).b64u
        let msg = "atlas-desktop:v1:sso_web:ins_T:\(sign.pssoKid):srv-nonce-1:\(hash)"
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: Data(b64u: sent["signature"] as! String)!)
        let pub = try P256.Signing.PublicKey(x963Representation: Data([4]) + Data(b64u: sign.publicJWK.x)! + Data(b64u: sign.publicJWK.y)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: Data(msg.utf8)))
        s.reply["web_session"] = (403, ["errors": [["code": "forbidden"]]])
        do { _ = try await c.webSession(config: cfg, signing: sign, redirectURL: nil); XCTFail("accepted a refusal") } catch { XCTAssertEqual(error as? DesktopError, .api(status: 403, code: "forbidden", deviceStatus: nil)) }
    }

    func testRefusesAPlainHTTPInstance() async {
        let c = PSSOClient(instanceURL: URL(string: "http://auth.example.com")!, publishableKey: "pk", http: PSSOServer())
        do { _ = try await c.configuration(); XCTFail("used http") } catch { XCTAssertEqual(error as? DesktopError, .insecureURL) }
    }
}
