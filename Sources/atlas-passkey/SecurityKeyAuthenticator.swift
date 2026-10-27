import AppKit
import AtlasDesktopCore
import AuthenticationServices

/// A security key through AuthenticationServices (ASAuthorizationSecurityKeyPublicKeyCredentialProvider).
///
/// Works only in a signed app with the associated-domains entitlement for the relying-party domain, in a user session. Apple's own
/// forum answer for the symptom: "The application identifier (and entitlements in general) are part of your application's code
/// signature" (developer.apple.com/forums/thread/737810). It cannot run inside the login window or an authorization plugin, which is
/// why the login-window step uses CTAP over USB HID instead.
///
/// AuthenticationServices builds clientDataJSON itself (origin https://<rp id>, the challenge base64url-encoded); the core checks
/// what came back before anything is sent to the server.
@MainActor
final class SecurityKeyAuthenticator: NSObject, PasskeyAuthenticator, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding {
    private var controller: ASAuthorizationController?
    private var assertionDone: CheckedContinuation<RawAssertion, Error>?
    private var registrationDone: CheckedContinuation<RawAttestation, Error>?
    private let anchor: NSWindow = {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1, height: 1), styleMask: [.borderless], backing: .buffered, defer: false)
        w.center()
        return w
    }()

    nonisolated var available: Bool { true }

    private static func uv(_ s: String) -> ASAuthorizationPublicKeyCredentialUserVerificationPreference {
        switch s {
        case "required": return .required
        case "discouraged": return .discouraged
        default: return .preferred
        }
    }

    nonisolated func assertion(_ request: PasskeyRequest, clientData: Data) async throws -> RawAssertion {
        await MainActor.run { self.anchor.makeKeyAndOrderFront(nil) }
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<RawAssertion, Error>) in
            Task { @MainActor in
                let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: request.rpId)
                let r = provider.createCredentialAssertionRequest(challenge: request.challengeBytes)
                r.userVerificationPreference = Self.uv(request.userVerification)
                r.allowedCredentials = request.allow.map { d in
                    ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: d.id, transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported)
                }
                self.assertionDone = c
                self.run(r)
            }
        }
    }

    nonisolated func registration(_ creation: PasskeyCreation, clientData: Data) async throws -> RawAttestation {
        await MainActor.run { self.anchor.makeKeyAndOrderFront(nil) }
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<RawAttestation, Error>) in
            Task { @MainActor in
                let provider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: creation.rpId)
                let r = provider.createCredentialRegistrationRequest(challenge: creation.challengeBytes, displayName: creation.userDisplayName, name: creation.userName, userID: creation.userId)
                r.credentialParameters = creation.algorithms.map { ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier(rawValue: $0)) }
                r.excludedCredentials = creation.exclude.map { ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(credentialID: $0, transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported) }
                r.userVerificationPreference = Self.uv(creation.userVerification)
                r.residentKeyPreference = .preferred
                r.attestationPreference = .none
                self.registrationDone = c
                self.run(r)
            }
        }
    }

    private func run(_ request: ASAuthorizationRequest) {
        let c = ASAuthorizationController(authorizationRequests: [request])
        c.delegate = self
        c.presentationContextProvider = self
        controller = c
        c.performRequests()
    }

    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor { anchor }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        defer { self.controller = nil }
        if let a = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialAssertion {
            assertionDone?.resume(returning: RawAssertion(credentialId: a.credentialID, authenticatorData: a.rawAuthenticatorData, signature: a.signature, clientDataJSON: a.rawClientDataJSON))
            assertionDone = nil
        } else if let r = authorization.credential as? ASAuthorizationSecurityKeyPublicKeyCredentialRegistration {
            var transports: [String] = []
            if #available(macOS 14.5, *) { transports = r.transports.map { $0.rawValue } }
            registrationDone?.resume(returning: RawAttestation(credentialId: r.credentialID, attestationObject: r.rawAttestationObject ?? Data(), clientDataJSON: r.rawClientDataJSON, transports: transports))
            registrationDone = nil
        } else {
            fail(PasskeyError.failed("unexpected credential type"))
        }
    }

    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        defer { self.controller = nil }
        let cancelled = (error as? ASAuthorizationError)?.code == .canceled
        fail(cancelled ? PasskeyError.cancelled : PasskeyError.failed((error as NSError).localizedDescription))
    }

    private func fail(_ e: Error) {
        assertionDone?.resume(throwing: e); assertionDone = nil
        registrationDone?.resume(throwing: e); registrationDone = nil
    }
}
