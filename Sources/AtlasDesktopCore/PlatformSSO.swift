import Foundation
import CryptoKit
import Security

/// Atlas as the identity provider of Apple's Platform SSO (and of the Windows device-bound broker): the wire contract is
/// desktop/DEVICE_SSO.md; Apple's protocol is documented under "Authentication process" in the AuthenticationServices
/// documentation (https://developer.apple.com/documentation/authenticationservices/authentication-process).
///
/// This file holds everything that does not need the AuthenticationServices framework, so it is unit-tested on its own: the discovery
/// document, the two registration calls, and the JWE login-response opener. The extension (Sources/AtlasPlatformSSO) feeds it the
/// keys Platform SSO owns (device signing, device encryption, user Secure Enclave key) and the login manager's registration token.

public struct PSSOConfiguration: Decodable, Equatable {
    public var enabled: Bool
    public var instanceId: String
    public var issuer: String
    public var clientId: String
    public var audience: String
    public var tokenEndpoint: String
    public var nonceEndpoint: String
    public var jwksUri: String
    public var sessionMinutes: Int
    public var refreshDays: Int
    enum CodingKeys: String, CodingKey {
        case enabled, instanceId = "instance_id", issuer, clientId = "client_id", audience
        case tokenEndpoint = "token_endpoint", nonceEndpoint = "nonce_endpoint", jwksUri = "jwks_uri"
        case sessionMinutes = "session_minutes", refreshDays = "refresh_days"
    }
}

public struct PSSORegistration: Decodable, Equatable {
    public var id: String
    public var userId: String
    public var status: String
    public var userKeyRegistered: Bool
    enum CodingKeys: String, CodingKey { case id, userId = "user_id", status, userKeyRegistered = "user_key_registered" }
}

public struct PSSOWebSession: Decodable, Equatable {
    public var attemptId: String
    public var status: String
    public var ticket: String?
    public var redirectTo: String?
    enum CodingKeys: String, CodingKey { case attemptId = "attempt_id", status, ticket, redirectTo = "redirect_to" }
}

public enum PSSOJose {
    /// Apple's `kid`: base64 (standard alphabet, padded) of SHA-256 over the ANSI X9.63 point.
    public static func kid(x963 point: Data) -> String { Data(SHA256.hash(data: point)).base64EncodedString() }

    /// RFC 7518 4.6.2 / NIST SP 800-56A 5.8.1 Concat KDF for a 256-bit key; AlgorithmID is "A256GCM", SuppPrivInfo empty.
    public static func concatKDF(z: Data, apu: Data, apv: Data) -> SymmetricKey {
        func u32(_ n: Int) -> Data { var b = UInt32(n).bigEndian; return Data(bytes: &b, count: 4) }
        func lp(_ d: Data) -> Data { u32(d.count) + d }
        var input = u32(1)
        input += z + lp(Data("A256GCM".utf8)) + lp(apu) + lp(apv) + u32(256)
        return SymmetricKey(data: Data(SHA256.hash(data: input)))
    }

    /// Opens the login response JWE (ECDH-ES, A256GCM) with the device encryption key and returns its JSON payload.
    public static func openLoginResponse(_ jwe: String, encryptionKey: DeviceKey) throws -> [String: Any] {
        let parts = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5, parts[1].isEmpty, let headerData = Data(b64u: parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              header["alg"] as? String == "ECDH-ES", header["enc"] as? String == "A256GCM",
              let epk = header["epk"] as? [String: Any], epk["crv"] as? String == "P-256",
              let x = (epk["x"] as? String).flatMap({ Data(b64u: $0) }), let y = (epk["y"] as? String).flatMap({ Data(b64u: $0) }),
              x.count == 32, y.count == 32,
              let apu = (header["apu"] as? String).flatMap({ Data(b64u: $0) }),
              let iv = Data(b64u: parts[2]), let ct = Data(b64u: parts[3]), let tag = Data(b64u: parts[4]), iv.count == 12, tag.count == 16
        else { throw DesktopError.malformed("login response") }
        let apv = (header["apv"] as? String).flatMap { Data(b64u: $0) } ?? Data()
        let z = try encryptionKey.ecdh(peerPoint: Data([4]) + x + y)
        let key = concatKDF(z: z, apu: apu, apv: apv)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct, tag: tag)
            let plain = try AES.GCM.open(box, using: key, authenticating: Data(parts[0].utf8))
            guard let o = try JSONSerialization.jsonObject(with: plain) as? [String: Any] else { throw DesktopError.malformed("login response") }
            return o
        } catch let e as DesktopError { throw e } catch { throw DesktopError.crypto("login response did not open") }
    }
}

public extension DeviceKey {
    /// Apple's kid for this key.
    var pssoKid: String {
        let j = publicJWK
        return PSSOJose.kid(x963: Data([4]) + (Data(b64u: j.x) ?? Data()) + (Data(b64u: j.y) ?? Data()))
    }
}

/// A key owned by the system (the Platform SSO login manager hands out `SecKey`s): signing and ECDH go through Security.framework.
public func pssoDeviceKey(_ key: SecKey) throws -> DeviceKey { try SecureEnclaveDeviceKey(priv: key) }

public struct PSSOClient {
    public let instanceURL: URL
    public let publishableKey: String
    let http: HTTPClient

    public init(instanceURL: URL, publishableKey: String, http: HTTPClient = URLSessionHTTPClient()) {
        self.instanceURL = instanceURL; self.publishableKey = publishableKey; self.http = http
    }

    private func url(_ path: String) throws -> URL {
        let u = instanceURL.appendingPathComponent("v1/client/device_sso/" + path)
        guard u.scheme == "https" else { throw DesktopError.insecureURL }
        return u
    }
    private var headers: [String: String] { ["X-Publishable-Key": publishableKey, "Accept": "application/json"] }

    private static func fail(_ r: HTTPResponse) -> DesktopError {
        var code: String?
        if let o = try? JSONSerialization.jsonObject(with: r.data) as? [String: Any] {
            code = ((o["errors"] as? [[String: Any]])?.first?["code"] as? String) ?? (o["error"] as? String)
        }
        return .api(status: r.status, code: code, deviceStatus: nil)
    }

    public func configuration() async throws -> PSSOConfiguration {
        let r = try await http.get(try url("configuration"), headers: headers)
        guard (200..<300).contains(r.status) else { throw Self.fail(r) }
        guard let c = try? JSONDecoder().decode(PSSOConfiguration.self, from: r.data) else { throw DesktopError.malformed("configuration") }
        // The endpoints must stay on the instance's own https origin: a poisoned discovery document cannot redirect the device elsewhere.
        for s in [c.tokenEndpoint, c.nonceEndpoint, c.jwksUri, c.issuer] {
            guard let u = URL(string: s), u.scheme == "https", u.host?.isEmpty == false else { throw DesktopError.insecureURL }
        }
        return c
    }

    /// A server nonce from the Apple-shaped token endpoint (`grant_type=srv_challenge`, answered `{ "Nonce": ... }`).
    public func nonce() async throws -> String {
        let body = "grant_type=srv_challenge&publishable_key=" + (publishableKey.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "")
        let r = try await http.post(try url("token"), headers: headers.merging(["Content-Type": "application/x-www-form-urlencoded"]) { $1 }, body: Data(body.utf8))
        guard (200..<300).contains(r.status) else { throw Self.fail(r) }
        guard let o = try? JSONSerialization.jsonObject(with: r.data) as? [String: Any], let n = o["Nonce"] as? String, !n.isEmpty else { throw DesktopError.malformed("nonce") }
        return n
    }

    private func postJSON(_ path: String, _ body: [String: Any]) async throws -> Data {
        let r = try await http.post(try url(path), headers: headers.merging(["Content-Type": "application/json"]) { $1 }, body: try JSONSerialization.data(withJSONObject: body))
        guard (200..<300).contains(r.status) else { throw Self.fail(r) }
        return r.data
    }
    private func decodeRegistration(_ d: Data) throws -> PSSORegistration {
        guard let r = try? JSONDecoder().decode(PSSORegistration.self, from: d) else { throw DesktopError.malformed("registration") }
        return r
    }
    private static func jwk(_ j: JWK) -> [String: String] { ["kty": j.kty, "crv": j.crv, "x": j.x, "y": j.y] }

    /// Registers the device. `registrationToken` is the enrolment code (the MDM payload's RegistrationToken, or what the person typed).
    public func registerDevice(config: PSSOConfiguration, registrationToken: String, signing: DeviceKey, encryption: DeviceKey, hostname: String?, agentVersion: String) async throws -> PSSORegistration {
        let sig = try signing.sign(SignedMessage.build(purpose: "sso_device", instanceId: config.instanceId, keyId: signing.pssoKid, nonce: registrationToken))
        var body: [String: Any] = [
            "registration_token": registrationToken, "signing_public_key": Self.jwk(signing.publicJWK), "encryption_public_key": Self.jwk(encryption.publicJWK),
            "signature": sig, "platform": "macos", "agent_version": agentVersion,
        ]
        if let h = hostname { body["hostname"] = String(h.prefix(120)) }
        return try decodeRegistration(try await postJSON("register_device", body))
    }

    /// Registers the user's Secure Enclave key under the device key. The device is named by its signing key id, because the
    /// system registers the device and each user in separate sessions that do not share the registration id.
    public func registerUser(config: PSSOConfiguration, signing: DeviceKey, userKey: DeviceKey, localUsername: String) async throws -> PSSORegistration {
        let nonce = try await nonce()
        let kid = signing.pssoKid
        let sig = try signing.sign(SignedMessage.build(purpose: "sso_user", instanceId: config.instanceId, keyId: kid, nonce: nonce, extra: userKey.pssoKid))
        let body: [String: Any] = [
            "signing_key_id": kid, "nonce": nonce, "user_public_key": Self.jwk(userKey.publicJWK),
            "local_username": localUsername, "method": "user_secure_enclave_key", "signature": sig,
        ]
        return try decodeRegistration(try await postJSON("register_user", body))
    }

    /// Browser SSO: asks Atlas to sign the device's user in and (with `redirectURL`, an allowed origin of the application) return the
    /// URL to open. The device key signs the redirect too, so it cannot be swapped on the way.
    public func webSession(config: PSSOConfiguration, signing: DeviceKey, redirectURL: String?) async throws -> PSSOWebSession {
        let nonce = try await nonce()
        let kid = signing.pssoKid
        let sig = try signing.sign(SignedMessage.build(purpose: "sso_web", instanceId: config.instanceId, keyId: kid, nonce: nonce, extra: redirectURL.map { SignedMessage.sha256b64u($0) } ?? "-"))
        var body: [String: Any] = ["signing_key_id": kid, "nonce": nonce, "signature": sig]
        if let r = redirectURL { body["redirect_url"] = r }
        guard let w = try? JSONDecoder().decode(PSSOWebSession.self, from: try await postJSON("web_session", body)) else { throw DesktopError.malformed("web session") }
        return w
    }
}
