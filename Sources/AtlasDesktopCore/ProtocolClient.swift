import Foundation

struct EnrollResponse: Decodable {
    struct Device: Decodable { var id: String }
    var device: Device
    var bundleMacKey: String
    var offlineOtpUri: String?
    enum CodingKeys: String, CodingKey { case device, bundleMacKey = "bundle_mac_key", offlineOtpUri = "offline_otp_uri" }
}

struct SyncResponse: Decodable {
    struct Offline: Decodable {
        var enabled: Bool
        var graceHours: Int?
        var pinRequired: Bool
        var pinSet: Bool?
        var keepCache: Bool
        var bundleValid: Bool?
        var bundle: OfflineBundle?
        enum CodingKeys: String, CodingKey {
            case enabled, graceHours = "grace_hours", pinRequired = "pin_required", pinSet = "pin_set"
            case keepCache = "keep_cache", bundleValid = "bundle_valid", bundle
        }
    }
    var status: String?
    var required: Bool
    var allowedFactors: [String]
    var offline: Offline
    var serverTime: Int64?
    enum CodingKeys: String, CodingKey {
        case status, required, allowedFactors = "allowed_factors", offline, serverTime = "server_time"
    }
}

struct Challenge {
    var id: String
    var factor: String
    var numberMatch: String?
    var passkeyOptions: [String: Any]?
}

final class ProtocolClient {
    let config: AgentConfig, key: DeviceKey, http: HTTPClient
    init(config: AgentConfig, key: DeviceKey, http: HTTPClient) { self.config = config; self.key = key; self.http = http }

    private func post(_ path: String, _ body: [String: Any]) async throws -> Data {
        let url = config.baseURL.appendingPathComponent("v1/client/desktop_mfa/" + path)
        guard url.scheme == "https" else { throw DesktopError.insecureURL }
        let data = try JSONSerialization.data(withJSONObject: body)
        let r: HTTPResponse
        do { r = try await http.post(url, headers: ["X-Publishable-Key": config.publishableKey, "Content-Type": "application/json", "Accept": "application/json"], body: data) }
        catch let e as DesktopError { throw e } catch { throw DesktopError.network("request failed") }
        if (200..<300).contains(r.status) { return r.data }
        var code: String?, ds: String?
        if let o = try? JSONSerialization.jsonObject(with: r.data) as? [String: Any],
           let e = (o["errors"] as? [[String: Any]])?.first {
            code = e["code"] as? String
            ds = (e["meta"] as? [String: Any])?["device_status"] as? String
        }
        if r.status == 403 && ds == "revoked" { throw DesktopError.revoked }
        throw DesktopError.api(status: r.status, code: code, deviceStatus: ds)
    }

    private func nonce() async throws -> String {
        let d = try await post("nonce", ["device_id": config.deviceId])
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let n = o["nonce"] as? String, !n.isEmpty
        else { throw DesktopError.malformed("nonce") }
        return n
    }

    private func sig(_ purpose: String, _ nonce: String, _ extra: String? = nil) throws -> String {
        try key.sign(SignedMessage.build(purpose: purpose, instanceId: config.instanceId, keyId: config.deviceId, nonce: nonce, extra: extra))
    }

    func enroll(code: String, pin: String?, hostname: String, agentVersion: String) async throws -> EnrollResponse {
        let jwk = key.publicJWK
        let s = try key.sign(SignedMessage.build(purpose: "enroll", instanceId: config.instanceId, keyId: jwk.x, nonce: code))
        var body: [String: Any] = [
            "code": code, "public_key": ["kty": jwk.kty, "crv": jwk.crv, "x": jwk.x, "y": jwk.y], "signature": s,
            "hostname": hostname, "platform": "macos", "agent_version": agentVersion,
        ]
        if let pin = pin { body["pin"] = pin }
        return try decode(EnrollResponse.self, try await post("enroll", body))
    }

    func sync(heldBundleId: String?) async throws -> SyncResponse {
        let n = try await nonce()
        var body: [String: Any] = ["device_id": config.deviceId, "nonce": n, "signature": try sig("sync", n, heldBundleId ?? "-")]
        if let h = heldBundleId { body["held_bundle_id"] = h }
        return try decode(SyncResponse.self, try await post("sync", body))
    }

    func setPIN(_ pin: String) async throws {
        let n = try await nonce()
        _ = try await post("pin", ["device_id": config.deviceId, "nonce": n, "signature": try sig("pin", n, SignedMessage.sha256b64u(pin)), "pin": pin])
    }

    func startChallenge(factor: String) async throws -> Challenge {
        let n = try await nonce()
        let d = try await post("challenges", ["device_id": config.deviceId, "nonce": n, "signature": try sig("challenge", n, factor), "factor": factor])
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let id = o["id"] as? String
        else { throw DesktopError.malformed("challenge") }
        return Challenge(id: id, factor: factor, numberMatch: o["number_match"].map { "\($0)" }, passkeyOptions: o["passkey_options"] as? [String: Any])
    }

    /// Returns "pending" | "verified" | "failed". 422 (wrong code) surfaces as DesktopError.api(status: 422).
    func verify(challengeId: String, code: String? = nil, assertion: [String: String]? = nil) async throws -> String {
        var body: [String: Any] = ["device_id": config.deviceId, "signature": try sig("verify", challengeId)]
        if let c = code { body["code"] = c }
        if let a = assertion { body["assertion"] = a }
        let d = try await post("challenges/\(challengeId)/verify", body)
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let s = o["status"] as? String else { throw DesktopError.malformed("verify") }
        return s
    }

    /// Creation options for a passkey on this workstation. Needs a challenge of this device the person has just verified.
    func passkeyOptions(proofChallengeId: String) async throws -> (id: String, options: [String: Any]) {
        let n = try await nonce()
        let d = try await post("passkeys/options", ["device_id": config.deviceId, "nonce": n, "signature": try sig("passkey_options", n, proofChallengeId), "proof_challenge_id": proofChallengeId])
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let id = o["registration_id"] as? String, let opts = o["passkey_options"] as? [String: Any]
        else { throw DesktopError.malformed("passkey options") }
        return (id, opts)
    }

    /// Finishes the registration; the signature covers the (single-use) registration id. Returns the passkey id.
    func passkeyEnrol(registrationId: String, credential: [String: String], name: String?, transports: [String]) async throws -> String {
        var body: [String: Any] = ["device_id": config.deviceId, "signature": try sig("passkey_enrol", registrationId), "credential": credential, "transports": transports]
        if let name = name, !name.isEmpty { body["name"] = name }
        let d = try await post("passkeys/\(registrationId)/enrol", body)
        guard let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let id = o["id"] as? String else { throw DesktopError.malformed("passkey") }
        return id
    }

    func report(_ events: [OfflineEvent]) async throws {
        let payload = String(data: try JSONEncoder().encode(Array(events.prefix(200))), encoding: .utf8)!
        let n = try await nonce()
        _ = try await post("report", ["device_id": config.deviceId, "nonce": n, "signature": try sig("report", n, SignedMessage.sha256b64u(payload)), "payload": payload])
    }

    private func decode<T: Decodable>(_ t: T.Type, _ d: Data) throws -> T {
        do { return try JSONDecoder().decode(t, from: d) } catch { throw DesktopError.malformed("response") }
    }
}
