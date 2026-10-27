import Foundation

// WebAuthn pieces for the OS-login passkey factor: parsing and validating the server's options, the client data an authenticator
// signs over, the shapes the server verifies, and the authenticator abstraction the platform back ends implement.
// Portable on purpose: everything here is unit-tested; the back ends (AuthenticationServices in a user session, CTAP2 over USB HID
// at the login window) are separate.

public struct PasskeyCredentialDescriptor: Equatable {
    public var id: Data
    public var transports: [String]
}

public struct PasskeyRequest: Equatable {
    public var challenge: String          // base64url, as issued; also what clientDataJSON must carry
    public var rpId: String
    public var origin: String             // always "https://" + rpId
    public var userVerification: String   // required | preferred | discouraged
    public var allow: [PasskeyCredentialDescriptor]
    public var timeoutMs: Int
    public var challengeBytes: Data { Data(b64u: challenge) ?? Data() }
}

public struct PasskeyCreation: Equatable {
    public var challenge: String
    public var rpId: String
    public var rpName: String
    public var origin: String
    public var userVerification: String
    public var userId: Data
    public var userName: String
    public var userDisplayName: String
    public var algorithms: [Int]
    public var exclude: [Data]
    public var timeoutMs: Int
    public var challengeBytes: Data { Data(b64u: challenge) ?? Data() }
}

public struct RawAssertion {
    public var credentialId: Data, authenticatorData: Data, signature: Data
    /// The client data the authenticator signed over (the platform builds it; a direct CTAP back end echoes ours).
    public var clientDataJSON: Data
    public init(credentialId: Data, authenticatorData: Data, signature: Data, clientDataJSON: Data) {
        self.credentialId = credentialId; self.authenticatorData = authenticatorData; self.signature = signature; self.clientDataJSON = clientDataJSON
    }
}

public struct RawAttestation {
    public var credentialId: Data, attestationObject: Data, clientDataJSON: Data
    public var transports: [String]
    public init(credentialId: Data, attestationObject: Data, clientDataJSON: Data, transports: [String] = []) {
        self.credentialId = credentialId; self.attestationObject = attestationObject; self.clientDataJSON = clientDataJSON; self.transports = transports
    }
}

public enum PasskeyError: Error, Equatable {
    case invalidOptions(String)
    case unavailable
    case cancelled
    case failed(String)
    case clientDataMismatch(String)
}

public protocol PasskeyAuthenticator {
    var available: Bool { get }
    /// `clientData` is the exact JSON to sign over when the back end hashes it itself (CTAP); a platform API that builds its own
    /// client data from the challenge and relying party ignores it. The result carries whichever JSON was signed.
    func assertion(_ request: PasskeyRequest, clientData: Data) async throws -> RawAssertion
    func registration(_ creation: PasskeyCreation, clientData: Data) async throws -> RawAttestation
}

public enum Passkey {
    private static func validUV(_ s: String) -> Bool { s == "required" || s == "preferred" || s == "discouraged" }
    private static func wellFormedId(_ s: String, min: Int) -> Data? {
        guard !s.contains("="), let d = Data(b64u: s), d.count >= min, d.count <= 1024 else { return nil }
        return d
    }
    private static func timeout(_ o: [String: Any]) -> Int {
        guard let t = o["timeout"] as? Int else { return 60_000 }
        return Swift.min(Swift.max(t, 10_000), 120_000)
    }

    /// Fails closed: a missing field, an undecodable id, or an origin that is not exactly https://<rpId> is an error.
    public static func parseRequest(_ o: [String: Any]) throws -> PasskeyRequest {
        guard let challenge = o["challenge"] as? String, wellFormedId(challenge, min: 16) != nil else { throw PasskeyError.invalidOptions("challenge") }
        guard let rpId = o["rpId"] as? String, !rpId.isEmpty, let origin = o["origin"] as? String, origin == "https://" + rpId else { throw PasskeyError.invalidOptions("origin") }
        let uv = o["userVerification"] as? String ?? "preferred"
        guard validUV(uv) else { throw PasskeyError.invalidOptions("userVerification") }
        var allow: [PasskeyCredentialDescriptor] = []
        if let raw = o["allowCredentials"] {
            guard let arr = raw as? [[String: Any]] else { throw PasskeyError.invalidOptions("allowCredentials") }
            for c in arr {
                guard let id = c["id"] as? String, let d = wellFormedId(id, min: 1) else { throw PasskeyError.invalidOptions("credential id") }
                allow.append(PasskeyCredentialDescriptor(id: d, transports: (c["transports"] as? [String]) ?? []))
            }
        }
        return PasskeyRequest(challenge: challenge, rpId: rpId, origin: origin, userVerification: uv, allow: allow, timeoutMs: timeout(o))
    }

    public static func parseCreation(_ o: [String: Any]) throws -> PasskeyCreation {
        guard let challenge = o["challenge"] as? String, wellFormedId(challenge, min: 16) != nil else { throw PasskeyError.invalidOptions("challenge") }
        guard let rp = o["rp"] as? [String: Any], let rpId = rp["id"] as? String, !rpId.isEmpty else { throw PasskeyError.invalidOptions("rp") }
        guard let origin = o["origin"] as? String, origin == "https://" + rpId else { throw PasskeyError.invalidOptions("origin") }
        guard let user = o["user"] as? [String: Any], let uid = user["id"] as? String, let userId = wellFormedId(uid, min: 1),
              let name = user["name"] as? String, !name.isEmpty else { throw PasskeyError.invalidOptions("user") }
        var uv = "preferred"
        if let sel = o["authenticatorSelection"] as? [String: Any], let u = sel["userVerification"] as? String { uv = u }
        guard validUV(uv) else { throw PasskeyError.invalidOptions("userVerification") }
        let algs = ((o["pubKeyCredParams"] as? [[String: Any]]) ?? []).compactMap { p -> Int? in (p["type"] as? String) == "public-key" ? p["alg"] as? Int : nil }
        guard !algs.isEmpty else { throw PasskeyError.invalidOptions("pubKeyCredParams") }
        let exclude = ((o["excludeCredentials"] as? [[String: Any]]) ?? []).compactMap { ($0["id"] as? String).flatMap { wellFormedId($0, min: 1) } }
        return PasskeyCreation(challenge: challenge, rpId: rpId, rpName: rp["name"] as? String ?? "Atlas", origin: origin, userVerification: uv, userId: userId,
                               userName: name, userDisplayName: user["displayName"] as? String ?? name, algorithms: algs, exclude: exclude, timeoutMs: timeout(o))
    }

    /// {"type":...,"challenge":...,"origin":...,"crossOrigin":false} with a stable key order.
    public static func clientDataJSON(type: String, challenge: String, origin: String) -> Data {
        func esc(_ s: String) -> String { String(data: try! JSONSerialization.data(withJSONObject: [s], options: []), encoding: .utf8)!.dropFirst().dropLast().description }
        return Data("{\"type\":\(esc(type)),\"challenge\":\(esc(challenge)),\"origin\":\(esc(origin)),\"crossOrigin\":false}".utf8)
    }

    /// What the authenticator actually signed over must be the ceremony we asked for; a back end that builds its own client data
    /// (AuthenticationServices) is held to the same standard before anything is sent to the server.
    public static func checkClientData(_ data: Data, type: String, challenge: String, origin: String) throws {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw PasskeyError.clientDataMismatch("not JSON") }
        guard o["type"] as? String == type else { throw PasskeyError.clientDataMismatch("type") }
        guard o["challenge"] as? String == challenge else { throw PasskeyError.clientDataMismatch("challenge") }
        guard o["origin"] as? String == origin else { throw PasskeyError.clientDataMismatch("origin") }
    }

    public static func assertionBody(_ a: RawAssertion, challenge: String) -> [String: String] {
        ["challenge": challenge, "credential_id": a.credentialId.b64u, "authenticator_data": a.authenticatorData.b64u,
         "client_data_json": a.clientDataJSON.b64u, "signature": a.signature.b64u]
    }

    /// The `PasskeyProvider` the login gate takes: validates the options, runs the authenticator, checks what it signed.
    public static func provider(for auth: PasskeyAuthenticator) -> PasskeyProvider {
        return { options in
            guard auth.available else { throw PasskeyError.unavailable }
            let req = try parseRequest(options)
            let cd = clientDataJSON(type: "webauthn.get", challenge: req.challenge, origin: req.origin)
            let a = try await auth.assertion(req, clientData: cd)
            guard !a.credentialId.isEmpty, !a.authenticatorData.isEmpty, !a.signature.isEmpty else { throw PasskeyError.failed("empty assertion") }
            try checkClientData(a.clientDataJSON, type: "webauthn.get", challenge: req.challenge, origin: req.origin)
            return assertionBody(a, challenge: req.challenge)
        }
    }

    /// Registers a passkey through this workstation. `proofChallengeId` is a challenge the person has just verified (push or code).
    static func enroll(client: ProtocolClient, authenticator auth: PasskeyAuthenticator, proofChallengeId: String, name: String?) async throws -> String {
        guard auth.available else { throw PasskeyError.unavailable }
        let reg = try await client.passkeyOptions(proofChallengeId: proofChallengeId)
        let c = try parseCreation(reg.options)
        let cd = clientDataJSON(type: "webauthn.create", challenge: c.challenge, origin: c.origin)
        let att = try await auth.registration(c, clientData: cd)
        guard !att.credentialId.isEmpty, !att.attestationObject.isEmpty else { throw PasskeyError.failed("empty attestation") }
        try checkClientData(att.clientDataJSON, type: "webauthn.create", challenge: c.challenge, origin: c.origin)
        let credential = ["challenge": c.challenge, "attestation_object": att.attestationObject.b64u, "client_data_json": att.clientDataJSON.b64u]
        return try await client.passkeyEnrol(registrationId: reg.id, credential: credential, name: name, transports: att.transports)
    }
}
