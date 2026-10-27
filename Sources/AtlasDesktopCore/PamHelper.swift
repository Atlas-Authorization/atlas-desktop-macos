import Foundation

/// The agent side of pam_atlas.so: one process per PAM transaction, a line protocol on stdin/stdout, the same `LoginGate` the
/// login-window plugin uses (same config, same offline bundle, same break-glass accounts). The module has already verified the
/// password with OpenDirectory, which is what `passwordVerified: true` below attests.
///
///   BEGIN <user> <service>      -> ALLOW <text> | DENY <text> | CHALLENGE online=0|1 push=0|1 totp=0|1 offline=0|1 pin=0|1
///   PUSH                        -> NUMBER <digits>, then OK | REJECT <text> | UNREACHABLE
///   CODE <6 digits>             -> OK | RETRY <text> | REJECT <text> | LOCKED | UNREACHABLE
///   OFFLINE <pin|-> <6 digits>  -> OK | RETRY <text> | REJECT <text> | LOCKED
///   QUIT
public final class PamHelper {
    private let gate: LoginGate?
    private let config: AgentConfig
    private var began = false
    private var prompt: GatePrompt?

    /// `gate` is nil when this Mac holds no device key (not enrolled): only accounts the config does not cover, and break-glass
    /// accounts, pass; everyone else is refused, which is what the login-window plugin does too.
    public init(config: AgentConfig, gate: LoginGate?) { self.config = config; self.gate = gate }

    static func clean(_ s: String) -> String {
        String(s.unicodeScalars.map { $0.value >= 0x20 && $0.value < 0x7f ? Character($0) : "?" }).prefix(120).description
    }
    static func validName(_ s: String, max: Int) -> Bool {
        guard !s.isEmpty, s.utf8.count <= max, s.first != "-" else { return false }
        return s.unicodeScalars.allSatisfy { ($0.value >= 0x30 && $0.value <= 0x39) || ($0.value >= 0x41 && $0.value <= 0x5a) || ($0.value >= 0x61 && $0.value <= 0x7a) || $0 == "." || $0 == "_" || $0 == "-" }
    }
    static func digits(_ s: String, _ range: ClosedRange<Int>) -> Bool { range.contains(s.utf8.count) && s.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }

    private func reply(_ o: Outcome) -> String {
        switch o {
        case .allowed: return "OK"
        case .retry(let m): return "RETRY " + Self.clean(m)
        case .rejected(let m): return "REJECT " + Self.clean(m)
        case .unreachable: return "UNREACHABLE"
        case .unsupported: return "REJECT not supported here"
        case .locked: return "LOCKED"
        }
    }

    /// Handles one command line; each reply line goes to `out`. Returns false when the session is over.
    public func handle(_ line: String, out: (String) -> Void) async -> Bool {
        let parts = line.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        switch parts.first ?? "" {
        case "BEGIN":
            guard !began, parts.count == 3, Self.validName(parts[1], max: 63), Self.validName(parts[2], max: 31) else { out("DENY bad request"); return false }
            began = true
            guard let gate = gate else {
                if config.breakGlassAccounts?.contains(parts[1]) == true { out("ALLOW break-glass account"); return false }
                if !config.appliesTo(user: parts[1]) { out("ALLOW account not enrolled"); return false }
                out("DENY this Mac is not enrolled"); return false
            }
            switch await gate.begin(user: parts[1], passwordVerified: true) {
            case .allow(let why): out("ALLOW " + Self.clean(why)); return true
            case .deny(let why): out("DENY " + Self.clean(why)); return false
            case .challenge(let p):
                // A passkey needs a window and a security key prompt; a terminal or screen-sharing login cannot show that.
                let f = p.online ? p.factors : []
                let push = f.contains("push"), totp = f.contains("totp")
                if !push && !totp && !p.offlineAvailable { out("DENY no usable factor for this service"); return false }
                prompt = GatePrompt(online: p.online, factors: f.filter { $0 == "push" || $0 == "totp" }, offlineAvailable: p.offlineAvailable, pinRequired: p.pinRequired)
                out("CHALLENGE online=\(p.online ? 1 : 0) push=\(push ? 1 : 0) totp=\(totp ? 1 : 0) offline=\(p.offlineAvailable ? 1 : 0) pin=\(p.pinRequired ? 1 : 0)")
                return true
            }
        case "PUSH":
            guard let gate = gate, began, prompt?.factors.contains("push") == true, parts.count == 1 else { out("REJECT push unavailable"); return true }
            let o = await gate.runPush(onNumber: { out("NUMBER " + Self.clean($0)) }, maxPolls: 60)
            out(reply(o)); return true
        case "CODE":
            guard let gate = gate, began, parts.count == 2, Self.digits(parts[1], 6...6), prompt?.factors.contains("totp") == true else { out("REJECT bad request"); return true }
            out(reply(await gate.verifyCode(parts[1]))); return true
        case "OFFLINE":
            guard let gate = gate, began, parts.count == 3, Self.digits(parts[2], 6...6), parts[1] == "-" || Self.digits(parts[1], 6...12) else { out("REJECT bad request"); return true }
            out(reply(gate.offline(pin: parts[1] == "-" ? nil : parts[1], code: parts[2]))); return true
        case "QUIT": return false
        default: out("REJECT unknown command"); return false
        }
    }
}

/// atlas-pam-helper serve: reads commands from stdin until QUIT or EOF. Anything that goes wrong ends the session without an ALLOW.
public func runPamHelperMain(_ args: [String]) -> Int32 {
    guard args.dropFirst().first == "serve" else { FileHandle.standardError.write(Data("usage: atlas-pam-helper serve\n".utf8)); return 2 }
    func say(_ s: String) { FileHandle.standardOutput.write(Data((s + "\n").utf8)) }
    var code: Int32 = 0
    let sem = DispatchSemaphore(value: 0)
    Task {
        defer { sem.signal() }
        guard let cfg = try? AgentConfig.load() else { say("DENY Atlas is not configured"); code = 1; return }
        let store = KeychainSecretStore()
        var gate: LoginGate?
        if cfg.enrolled, let key = DeviceKeyFactory.open(label: cfg.deviceKeyId, secrets: store, create: false) {
            gate = LoginGate(config: cfg, key: key, http: URLSessionHTTPClient(), secrets: store)
        }
        let helper = PamHelper(config: cfg, gate: gate)
        while let line = readLine(strippingNewline: true) {
            if line.utf8.count > 255 { say("DENY bad request"); break }
            if !(await helper.handle(line, out: say)) { break }
        }
    }
    sem.wait()
    return code
}
