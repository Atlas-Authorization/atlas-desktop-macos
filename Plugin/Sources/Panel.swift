import AppKit
import OpenDirectory
import os

/// Small login-window panel: status, number match, code and PIN fields, factor buttons.
final class MFAPanel: NSObject {
    let window: NSWindow
    let status = NSTextField(labelWithString: "Checking sign-in policy...")
    let number = NSTextField(labelWithString: "")
    let code = NSTextField(frame: .zero)
    let pin = NSSecureTextField(frame: .zero)
    let pushB = NSButton(title: "Approve on phone", target: nil, action: nil)
    let codeB = NSButton(title: "Use code", target: nil, action: nil)
    let passkeyB = NSButton(title: "Security key", target: nil, action: nil)
    let offlineB = NSButton(title: "Offline code", target: nil, action: nil)
    let goB = NSButton(title: "Verify", target: nil, action: nil)
    let cancelB = NSButton(title: "Cancel", target: nil, action: nil)
    var onPush: () -> Void = {}, onCode: () -> Void = {}, onPasskey: () -> Void = {}, onOffline: () -> Void = {}
    var onSubmit: (String, String) -> Void = { _, _ in }, onCancel: () -> Void = {}
    var mode = "none"
    var pinContinuation: CheckedContinuation<String?, Never>?

    override init() {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 300), styleMask: [.titled], backing: .buffered, defer: false)
        super.init()
        window.title = "Atlas verification"
        window.level = NSWindow.Level(rawValue: Int(CGShieldingWindowLevel()) + 1)
        let v = window.contentView!
        status.frame = NSRect(x: 20, y: 250, width: 400, height: 34); status.maximumNumberOfLines = 2
        status.lineBreakMode = .byWordWrapping
        number.frame = NSRect(x: 20, y: 170, width: 400, height: 70); number.alignment = .center
        number.font = .monospacedDigitSystemFont(ofSize: 56, weight: .bold)
        code.frame = NSRect(x: 20, y: 135, width: 400, height: 24); code.placeholderString = "6-digit code"
        pin.frame = NSRect(x: 20, y: 100, width: 400, height: 24); pin.placeholderString = "Offline PIN"
        for (b, x, y, w, a) in [(pushB, 20, 62, 130, #selector(push)), (codeB, 155, 62, 90, #selector(codeTap)),
                                (passkeyB, 250, 62, 80, #selector(passkey)), (offlineB, 335, 62, 90, #selector(offline)),
                                (goB, 335, 16, 90, #selector(submit)), (cancelB, 20, 16, 90, #selector(cancel))] as [(NSButton, Int, Int, Int, Selector)] {
            b.frame = NSRect(x: x, y: y, width: w, height: 28); b.target = self; b.action = a; b.bezelStyle = .rounded; v.addSubview(b)
        }
        [status, number, code, pin].forEach { v.addSubview($0) }
        goB.keyEquivalent = "\r"
        show(mode: "none", factors: [], offline: false)
    }

    func present() { window.center(); window.makeKeyAndOrderFront(nil); window.orderFrontRegardless() }
    func dismiss() { window.orderOut(nil) }

    /// mode: "none" | "code" | "offline" | "push"
    func show(mode: String, factors: [String], offline: Bool, pinRequired: Bool = false) {
        self.mode = mode
        pushB.isHidden = !factors.contains("push"); codeB.isHidden = !factors.contains("totp")
        passkeyB.isHidden = !factors.contains("passkey"); offlineB.isHidden = !offline
        code.isHidden = !(mode == "code" || mode == "offline"); pin.isHidden = !((mode == "offline" && pinRequired) || mode == "keypin")
        goB.isHidden = code.isHidden && mode != "keypin"; number.isHidden = mode != "push"
        code.stringValue = ""; pin.stringValue = ""
        if !code.isHidden { window.makeFirstResponder(pin.isHidden ? code : pin) }
        else if mode == "keypin" { window.makeFirstResponder(pin) }
    }

    /// Asks for the security key's PIN (not the offline PIN). nil = the person cancelled.
    @MainActor func askPIN(retries: Int?) async -> String? {
        status.stringValue = retries.map { "Wrong PIN. \($0) tries left. Enter the security key PIN." } ?? "Enter the PIN of your security key."
        pin.placeholderString = "Security key PIN"
        show(mode: "keypin", factors: [], offline: false)
        return await withCheckedContinuation { pinContinuation = $0 }
    }

    @objc func push() { onPush() }
    @objc func codeTap() { onCode() }
    @objc func passkey() { onPasskey() }
    @objc func offline() { onOffline() }
    @objc func submit() {
        if let c = pinContinuation { pinContinuation = nil; let v = pin.stringValue; pin.stringValue = ""; pin.placeholderString = "Offline PIN"; c.resume(returning: v.isEmpty ? nil : v); return }
        onSubmit(code.stringValue, pin.stringValue)
    }
    @objc func cancel() {
        if let c = pinContinuation { pinContinuation = nil; pin.stringValue = ""; pin.placeholderString = "Offline PIN"; c.resume(returning: nil); return }
        onCancel()
    }
}

/// Runs one gate session; calls `done(allow)` exactly once.
final class MFASession {
    let panel = MFAPanel()
    let user: String
    let done: (Bool) -> Void
    var passwordVerified = false
    var gate: LoginGate?
    var prompt: GatePrompt?
    var pushTask: Task<Void, Never>?
    var finished = false

    init(user: String, done: @escaping (Bool) -> Void) { self.user = user; self.done = done }

    func finish(_ allow: Bool) {
        guard !finished else { return }
        finished = true
        pushTask?.cancel()
        panel.dismiss()
        done(allow)
    }

    func start(passwordVerified: Bool) {
        self.passwordVerified = passwordVerified
        panel.onCancel = { [weak self] in self?.finish(false) }
        panel.present()
        Task { @MainActor in
            let store = KeychainSecretStore()
            guard passwordVerified else { return self.denyLater("Sign-in blocked: password not verified") }
            guard let cfg = try? AgentConfig.load() else { return self.denyLater("Atlas is not configured. Contact your administrator.") }
            guard let key = DeviceKeyFactory.open(label: cfg.deviceKeyId, secrets: store, create: false) else {
                if !cfg.appliesTo(user: user) { return self.finish(true) }
                return self.denyLater("This Mac has no device key. Contact your administrator.")
            }
            // Security keys over USB HID: AuthenticationServices cannot run inside the login window (no entitlements, no app identity),
            // so the key is driven with CTAP2 directly. The PIN is asked on this panel.
            let keys = CTAP2Authenticator.usb(pin: { retries in await self.panel.askPIN(retries: retries) },
                                              status: { msg in DispatchQueue.main.async { self.panel.status.stringValue = msg } })
            let g = LoginGate(config: cfg, key: key, http: URLSessionHTTPClient(), secrets: store, passkey: Passkey.provider(for: keys))
            self.gate = g
            switch await g.begin(user: self.user, passwordVerified: self.passwordVerified) {
            case .allow: self.finish(true)
            case .deny(let why): self.denyLater("Sign-in blocked: \(why)")
            case .challenge(let p): self.wire(p)
            }
        }
    }

    @MainActor func denyLater(_ msg: String) {
        panel.status.stringValue = msg
        panel.show(mode: "none", factors: [], offline: false)
        DispatchQueue.main.asyncAfter(deadline: .now() + 4) { self.finish(false) }
    }

    @MainActor func wire(_ p: GatePrompt) {
        prompt = p
        panel.status.stringValue = p.online ? "Verify it is you to finish signing in." : "Offline: enter your PIN and the code from your authenticator app."
        panel.onPush = { [weak self] in self?.runPush() }
        panel.onCode = { [weak self] in self?.showMode("code") }
        panel.onOffline = { [weak self] in self?.showMode("offline") }
        panel.onPasskey = { [weak self] in self?.runPasskey() }
        panel.onSubmit = { [weak self] c, pin in self?.submit(c, pin) }
        showMode(p.online ? "none" : "offline")
    }

    @MainActor func showMode(_ m: String) {
        guard let p = prompt else { return }
        panel.show(mode: m, factors: p.online ? p.factors : [], offline: p.offlineAvailable && m != "offline", pinRequired: p.pinRequired)
    }

    @MainActor func handle(_ o: Outcome) {
        switch o {
        case .allowed: finish(true)
        case .retry(let m), .rejected(let m): panel.status.stringValue = m; showMode(prompt?.online == true ? "none" : "offline")
        case .unreachable:
            panel.status.stringValue = "Cannot reach Atlas."
            prompt = GatePrompt(online: false, factors: [], offlineAvailable: prompt?.offlineAvailable ?? false, pinRequired: prompt?.pinRequired ?? false)
            showMode(prompt!.offlineAvailable ? "offline" : "none")
            if !prompt!.offlineAvailable { denyLater("Cannot reach Atlas and no offline code is available.") }
        case .unsupported: panel.status.stringValue = "Security keys are not available here."
        case .locked: panel.status.stringValue = "Too many attempts. Try again in 15 minutes."
        }
    }

    @MainActor func runPush() {
        guard let g = gate else { return }
        panel.show(mode: "push", factors: [], offline: false)
        panel.status.stringValue = "Approve the request on your phone and pick this number."
        pushTask = Task { @MainActor in
            let o = await g.runPush(onNumber: { n in DispatchQueue.main.async { self.panel.number.stringValue = n } })
            self.handle(o)
        }
    }

    @MainActor func runPasskey() {
        guard let g = gate else { return }
        panel.status.stringValue = "Insert and touch your security key."
        Task { @MainActor in self.handle(await g.runPasskey()) }
    }

    @MainActor func submit(_ c: String, _ pin: String) {
        guard let g = gate else { return }
        if panel.mode == "offline" { handle(g.offline(pin: pin.isEmpty ? nil : pin, code: c)) }
        else { Task { @MainActor in self.handle(await g.verifyCode(c)) } }
    }
}

var activeSessions: [UnsafeMutableRawPointer: MFASession] = [:]

/// Verifies the account password with OpenDirectory (authentication search path: local + directory accounts).
/// Returns false on any error, an empty password, or a missing account. shortcut: the password is briefly a Swift String
/// (ODRecord.verifyPassword takes one) that cannot be zeroed; the C buffers are wiped.
func verifyPassword(user: String, password: String) -> Bool {
    guard !password.isEmpty else { return false }
    do {
        let node = try ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication))
        let rec = try node.record(withRecordType: kODRecordTypeUsers, name: user, attributes: nil)
        try rec.verifyPassword(password)
        return true
    } catch { return false }
}

@_cdecl("atlas_mfa_run")
public func atlas_mfa_run(_ user: UnsafePointer<CChar>, _ password: UnsafePointer<CChar>?, _ passwordLen: Int32,
                          _ ctx: UnsafeMutableRawPointer, _ done: @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void) {
    let name = String(cString: user)
    var pw: [UInt8] = password.map { Array(UnsafeBufferPointer(start: UnsafeRawPointer($0).assumingMemoryBound(to: UInt8.self), count: Int(passwordLen))) } ?? []
    DispatchQueue.global().async {
        var verified = false
        if !pw.isEmpty, let str = String(bytes: pw, encoding: .utf8) { verified = verifyPassword(user: name, password: str) }
        pw.withUnsafeMutableBytes { _ = memset_s($0.baseAddress, $0.count, 0, $0.count) }
        pw.removeAll()
        if !verified { Logger(subsystem: "net.atlasauth.desktop", category: "plugin").notice("password not verified by OpenDirectory; Atlas not contacted") }
        DispatchQueue.main.async {
            let s = MFASession(user: name) { allow in
                activeSessions[ctx] = nil
                done(ctx, allow ? 1 : 0)
            }
            activeSessions[ctx] = s
            s.start(passwordVerified: verified)
        }
    }
}
