import AppKit
import AuthenticationServices
import AtlasDesktopCore

/// Atlas Platform SSO extension (macOS 13 and later; the jwt-bearer grant used for the Secure Enclave key method needs macOS 14).
///
/// Apple's contract: https://developer.apple.com/documentation/authenticationservices/creating-extensions-that-support-platform-sso
/// and https://developer.apple.com/documentation/authenticationservices/registering-devices-and-users
///
/// What it does: registers the Mac (device signing and encryption keys, owned by the system) and the person (their Secure Enclave
/// key) with Atlas, and hands the system the login configuration. The system itself then builds and signs the login requests and
/// decrypts the responses; Atlas answers them at /v1/client/device_sso/token (desktop/DEVICE_SSO.md). Browser sign-in: a request to
/// the Atlas sign-in page is answered with a redirect that Atlas minted for the device-bound session.
///
/// Delivered by MDM as an Extensible SSO payload (Type Redirect) with ExtensionData `instance_url` and `publishable_key`; the
/// payload's RegistrationToken is an Atlas enrolment code for silent registration. Without one, the person types a code.
@objc(AtlasPlatformSSOExtension)
@available(macOS 14.0, *)
final class AtlasPlatformSSOExtension: NSViewController, ASAuthorizationProviderExtensionAuthorizationRequestHandler, ASAuthorizationProviderExtensionRegistrationHandler {
    static let agentVersion = "1.0.0"

    private var pending: (manager: ASAuthorizationProviderExtensionLoginManager, completion: (ASAuthorizationProviderExtensionRegistrationResult) -> Void)?
    private let codeField = NSTextField()
    private let status = NSTextField(labelWithString: "")

    // MARK: Registration handler

    func supportedGrantTypes() -> ASAuthorizationProviderExtensionSupportedGrantTypes { [.jwtBearer] }
    func protocolVersion() -> ASAuthorizationProviderExtensionPlatformSSOProtocolVersion { .version1_0 }
    func registrationDidComplete() {}
    func registrationDidCancel() { finishPending(.failed) }

    private func client(_ m: ASAuthorizationProviderExtensionLoginManager) -> PSSOClient? {
        guard let d = m.extensionData as? [String: Any], let u = d["instance_url"] as? String, let url = URL(string: u), url.scheme == "https",
              let pk = d["publishable_key"] as? String, !pk.isEmpty else { return nil }
        return PSSOClient(instanceURL: url, publishableKey: pk)
    }

    func beginDeviceRegistration(loginManager: ASAuthorizationProviderExtensionLoginManager, options: ASAuthorizationProviderExtensionRequestOptions = [], completion: @escaping @Sendable (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {
        guard client(loginManager) != nil else { completion(.failedNoRetry); return } // no instance configured: retrying cannot help
        if let token = loginManager.registrationToken, !token.isEmpty {
            Task { @MainActor in completion(await self.register(loginManager, token: token)) }
        } else if options.contains(.userInteractionEnabled) {
            pending = (loginManager, completion)
            loginManager.presentRegistrationViewController { error in
                if error != nil { Task { @MainActor in self.finishPending(.failed) } }
            }
        } else {
            completion(.userInterfaceRequired)
        }
    }

    func beginUserRegistration(loginManager: ASAuthorizationProviderExtensionLoginManager, userName: String?, method: ASAuthorizationProviderExtensionAuthenticationMethod, options: ASAuthorizationProviderExtensionRequestOptions = [], completion: @escaping @Sendable (ASAuthorizationProviderExtensionRegistrationResult) -> Void) {
        // Atlas keeps no passwords on the device path: the person is the owner of a Secure Enclave key.
        guard method == .userSecureEnclaveKey else { completion(.failedNoRetry); return }
        guard let client = client(loginManager), let sign = loginManager.key(for: .currentDeviceSigning), let userSecKey = loginManager.key(for: .userSecureEnclaveKey) else { completion(.failed); return }
        let name = (userName?.isEmpty == false ? userName! : NSUserName())
        Task {
            do {
                let config = try await client.configuration()
                let reg = try await client.registerUser(config: config, signing: try pssoDeviceKey(sign), userKey: try pssoDeviceKey(userSecKey), localUsername: name)
                guard reg.userKeyRegistered else { completion(.failed); return }
                try loginManager.saveUserLoginConfiguration(ASAuthorizationProviderExtensionUserLoginConfiguration(loginUserName: name))
                completion(.success)
            } catch DesktopError.api(let status, _, _) where status == 401 || status == 403 {
                completion(.failedNoRetry) // the device was revoked or no longer matches: an administrator has to issue a new code
            } catch {
                completion(.failed) // the system retries in about ten minutes
            }
        }
    }

    private func register(_ m: ASAuthorizationProviderExtensionLoginManager, token: String) async -> ASAuthorizationProviderExtensionRegistrationResult {
        guard let client = client(m), let sign = m.key(for: .currentDeviceSigning), let enc = m.key(for: .currentDeviceEncryption) else { return .failed }
        do {
            let config = try await client.configuration()
            guard config.enabled else { return .failed }
            _ = try await client.registerDevice(config: config, registrationToken: token.trimmingCharacters(in: .whitespacesAndNewlines), signing: try pssoDeviceKey(sign), encryption: try pssoDeviceKey(enc), hostname: Host.current().localizedName, agentVersion: Self.agentVersion)
            try m.saveLoginConfiguration(Self.loginConfiguration(config))
            return .success
        } catch DesktopError.api(let status, _, _) where status == 401 || status == 403 {
            return .failedNoRetry // the code was wrong, spent or expired: retrying the same code cannot help
        } catch {
            return .failed
        }
    }

    /// The configuration the system uses to build login requests. Atlas takes `publishable_key` as a form field because the system's
    /// nonce, login and refresh requests carry no custom headers of ours.
    static func loginConfiguration(_ c: PSSOConfiguration) throws -> ASAuthorizationProviderExtensionLoginConfiguration {
        guard let token = URL(string: c.tokenEndpoint), let nonce = URL(string: c.nonceEndpoint), let jwks = URL(string: c.jwksUri) else { throw DesktopError.malformed("configuration") }
        let cfg = ASAuthorizationProviderExtensionLoginConfiguration(clientID: c.clientId, issuer: c.issuer, tokenEndpointURL: token, jwksEndpointURL: jwks, audience: c.audience)
        cfg.nonceEndpointURL = nonce
        cfg.refreshEndpointURL = token
        let pk = [URLQueryItem(name: "publishable_key", value: c.clientId)]
        cfg.customNonceRequestValues = pk
        cfg.customLoginRequestValues = pk
        cfg.customRefreshRequestValues = pk
        return cfg
    }

    private func finishPending(_ result: ASAuthorizationProviderExtensionRegistrationResult) {
        guard let p = pending else { return }
        pending = nil
        p.completion(result)
    }

    // MARK: Registration UI (shown only when no registration token came with the MDM payload)

    override func loadView() {
        let title = NSTextField(labelWithString: "Register this Mac with Atlas")
        title.font = .boldSystemFont(ofSize: 15)
        codeField.placeholderString = "Enrolment code"
        status.textColor = .secondaryLabelColor
        let go = NSButton(title: "Register", target: self, action: #selector(submit))
        go.keyEquivalent = "\r"
        let stack = NSStackView(views: [title, NSTextField(labelWithString: "Enter the one-time code your administrator gave you."), codeField, status, go])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        stack.widthAnchor.constraint(greaterThanOrEqualToConstant: 360).isActive = true
        view = stack
    }

    @objc private func submit() {
        guard let p = pending else { return }
        let code = codeField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else { status.stringValue = "Enter the code first."; return }
        status.stringValue = "Registering..."
        Task { @MainActor in
            let r = await self.register(p.manager, token: code)
            if r == .success { self.finishPending(.success) } else { self.status.stringValue = r == .failedNoRetry ? "That code did not work. Ask for a new one." : "Could not reach Atlas. Try again." }
        }
    }

    // MARK: Authorization requests (browser SSO)

    func beginAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {
        // Only a sign-in page navigation of the Atlas instance, and only while the person has a live Platform SSO login. Anything else
        // (or any failure) falls through to the normal Atlas sign-in page, which still works.
        guard let manager = request.loginManager, manager.ssoTokens != nil, let client = client(manager), let sign = manager.key(for: .currentDeviceSigning),
              request.url.host == client.instanceURL.host || request.url.host == URL(string: manager.loginConfiguration?.issuer ?? "")?.host,
              let redirect = URLComponents(url: request.url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "redirect_url" })?.value
        else { request.doNotHandle(); return }
        Task {
            do {
                let config = try await client.configuration()
                let w = try await client.webSession(config: config, signing: try pssoDeviceKey(sign), redirectURL: redirect)
                guard w.status == "complete", let to = w.redirectTo, let location = URL(string: to), location.scheme == "https",
                      let resp = HTTPURLResponse(url: request.url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": location.absoluteString, "Cache-Control": "no-store"])
                else { request.doNotHandle(); return }
                request.complete(httpResponse: resp, httpBody: nil)
            } catch {
                request.doNotHandle()
            }
        }
    }

    func cancelAuthorization(with request: ASAuthorizationProviderExtensionAuthorizationRequest) {}
}
