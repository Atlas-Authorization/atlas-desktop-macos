import Foundation
import os

/// Cached sync result: lets an offline workstation know whether MFA was required.
struct GateState: Codable, Equatable {
    var required: Bool?
    var allowedFactors: [String] = []
    var offlineEnabled = false
    var pinRequired = false
    var revoked = false
    var lastSyncMs: Int64 = 0
    var bundle: OfflineBundle?
    static let key = "gate_state"
}

enum StateSync {
    static let macKeyName = "bundle_mac_key"

    /// One sync round trip: updates the cached state, replaces/wipes the bundle, then uploads queued offline events.
    @discardableResult
    static func run(client: ProtocolClient, store: SecretStore, clock: Clock) async throws -> GateState {
        var st = store.load(GateState.self, GateState.key) ?? GateState()
        let resp: SyncResponse
        do { resp = try await client.sync(heldBundleId: st.bundle?.bundleId) }
        catch DesktopError.revoked {
            st.revoked = true; st.bundle = nil; st.required = true
            try? store.save(st, GateState.key)
            throw DesktopError.revoked
        }
        st.revoked = resp.status == "revoked"
        st.required = resp.required
        st.allowedFactors = resp.allowedFactors
        st.offlineEnabled = resp.offline.enabled
        st.pinRequired = resp.offline.pinRequired
        st.lastSyncMs = clock.nowMs
        if st.revoked || !resp.offline.keepCache || !resp.offline.enabled { st.bundle = nil }
        else if let b = resp.offline.bundle, let mk = store.get(macKeyName).flatMap({ Data(b64u: String(decoding: $0, as: UTF8.self)) }),
                b.macValid(macKey: mk, deviceId: client.config.deviceId) {
            st.bundle = b
        }
        try store.save(st, GateState.key)
        if st.revoked { throw DesktopError.revoked }

        let off = OfflineUnlock(store: store, clock: clock)
        let q = off.queue
        if !q.isEmpty, (try? await client.report(q)) != nil { off.removeQueued(min(q.count, 200)) }
        return st
    }
}

public enum Outcome: Equatable {
    case allowed
    case retry(String)      // wrong code, try again
    case rejected(String)   // challenge failed/denied/expired; pick another factor
    case unreachable        // network down: offline unlock may be used
    case unsupported
    case locked(untilMs: Int64)
}

public typealias PasskeyProvider = (_ options: [String: Any]) async throws -> [String: String]

public struct GatePrompt: Equatable {
    public var online: Bool
    public var factors: [String]
    public var offlineAvailable: Bool
    public var pinRequired: Bool
}

public enum GateDecision: Equatable {
    case allow(String)
    case deny(String)
    case challenge(GatePrompt)
}

public final class LoginGate {
    let config: AgentConfig, key: DeviceKey, secrets: SecretStore, clock: Clock
    let client: ProtocolClient
    let passkey: PasskeyProvider?
    let sleep: (TimeInterval) async -> Void
    var state = GateState()
    public private(set) var online = false
    var totpChallenge: String?

    public init(config: AgentConfig, key: DeviceKey, http: HTTPClient, secrets: SecretStore, clock: Clock = SystemClock(),
                passkey: PasskeyProvider? = nil, sleep: @escaping (TimeInterval) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1e9)) }) {
        self.config = config; self.key = key; self.secrets = secrets; self.clock = clock
        self.client = ProtocolClient(config: config, key: key, http: http)
        self.passkey = passkey; self.sleep = sleep
    }

    static let supported = ["push", "totp", "passkey"]

    /// Decides from a fresh sync when reachable, else from cached state. Defaults to deny.
    /// `passwordVerified` must be true only when the account password was verified by the caller (OpenDirectory) in this
    /// login attempt. When false the gate denies immediately and makes no network call, so a wrong password never sends a push.
    public func begin(user: String, passwordVerified: Bool) async -> GateDecision {
        guard passwordVerified else { return .deny("password not verified") }
        if config.breakGlassAccounts?.contains(user) == true {
            Logger(subsystem: "net.atlasauth.desktop", category: "gate").notice("break-glass login for account \(user, privacy: .public): Atlas MFA skipped")
            OfflineUnlock(store: secrets, clock: clock).record(clock.nowMs, "success", nil, "break_glass:" + user)
            return .allow("break-glass account")
        }
        guard config.appliesTo(user: user) else { return .allow("account not enrolled") }
        guard config.enrolled, !config.deviceId.isEmpty else {
            return config.failOpenWhenNeverSynced == true ? .allow("not enrolled, fail-open configured") : .deny("device not enrolled")
        }
        state = secrets.load(GateState.self, GateState.key) ?? GateState()
        do {
            state = try await StateSync.run(client: client, store: secrets, clock: clock)
            online = true
        } catch DesktopError.revoked { return .deny("device revoked") }
        catch { online = false }
        if state.revoked { return .deny("device revoked") }
        guard let req = state.required else {
            return config.failOpenWhenNeverSynced == true ? .allow("never synced, fail-open configured") : .deny("MFA state unknown")
        }
        if !req { return .allow("MFA not required") }
        let factors = state.allowedFactors.filter { Self.supported.contains($0) }
        let prompt = GatePrompt(online: online, factors: online ? factors : [], offlineAvailable: offlineAvailable(), pinRequired: state.pinRequired)
        if prompt.factors.isEmpty && !prompt.offlineAvailable { return .deny(online ? "no usable factor" : "offline and no valid offline bundle") }
        return .challenge(prompt)
    }

    func offlineAvailable() -> Bool {
        guard state.offlineEnabled, let b = state.bundle, let mk = secrets.get(StateSync.macKeyName).flatMap({ Data(b64u: String(decoding: $0, as: UTF8.self)) })
        else { return false }
        return b.macValid(macKey: mk, deviceId: config.deviceId) && clock.nowMs < b.expiresAt
    }

    private func classify(_ e: Error) -> Outcome {
        switch e {
        case DesktopError.revoked: return .rejected("device revoked")
        case DesktopError.network, DesktopError.insecureURL: online = false; return .unreachable
        case DesktopError.api(let s, _, _) where s == 422: return .retry("incorrect code")
        case DesktopError.api(let s, _, _) where s == 429: return .rejected("too many attempts")
        default: return .rejected("verification failed")
        }
    }

    /// Push: calls `onNumber` with the number to match, then polls every 2 s until verified/failed.
    public func runPush(onNumber: (String) -> Void, maxPolls: Int = 150) async -> Outcome {
        do {
            let c = try await client.startChallenge(factor: "push")
            if let n = c.numberMatch { onNumber(n) }
            for _ in 0..<maxPolls {
                if Task.isCancelled { return .rejected("cancelled") }
                switch try await client.verify(challengeId: c.id) {
                case "verified": return .allowed
                case "failed": return .rejected("denied on phone")
                default: await sleep(2)
                }
            }
            return .rejected("timed out")
        } catch { return classify(error) }
    }

    public func verifyCode(_ code: String) async -> Outcome {
        guard code.count == 6, code.allSatisfy({ $0.isASCII && $0.isNumber }) else { return .retry("enter the 6-digit code") }
        do {
            if totpChallenge == nil { totpChallenge = try await client.startChallenge(factor: "totp").id }
            let s = try await client.verify(challengeId: totpChallenge!, code: code)
            if s == "verified" { return .allowed }
            if s == "failed" { totpChallenge = nil; return .rejected("code rejected") }
            return .retry("incorrect code")
        } catch {
            let o = classify(error)
            if case .retry = o {} else { totpChallenge = nil }
            return o
        }
    }

    public func runPasskey() async -> Outcome {
        guard let provider = passkey else { return .unsupported }
        do {
            let c = try await client.startChallenge(factor: "passkey")
            guard let opts = c.passkeyOptions else { return .rejected("no passkey options") }
            let assertion = try await provider(opts)
            return try await client.verify(challengeId: c.id, assertion: assertion) == "verified" ? .allowed : .rejected("passkey rejected")
        } catch PasskeyError.cancelled { return .rejected("cancelled")
        } catch PasskeyError.unavailable { return .unsupported
        } catch is PasskeyError { return .rejected("passkey failed")
        } catch DesktopError.api(let s, _, _) where s == 400 || s == 422 {
            // A rejected assertion spent its challenge; the next attempt starts a new one.
            return .rejected("passkey rejected")
        } catch { return classify(error) }
    }

    /// Offline unlock: only while the server is unreachable, with a valid unexpired bundle.
    public func offline(pin: String?, code: String) -> Outcome {
        guard !online, offlineAvailable(), let b = state.bundle else { return .rejected("offline unlock unavailable") }
        guard let plain = try? b.open(with: key), plain.bundleId == b.bundleId, plain.deviceId == config.deviceId else {
            return .rejected("offline bundle unreadable")
        }
        switch OfflineUnlock(store: secrets, clock: clock).attempt(plain: plain, pin: pin, code: code) {
        case .allowed: return .allowed
        case .wrongPIN, .wrongCode: return .retry("incorrect PIN or code")
        case .locked(let u): return .locked(untilMs: u)
        case .expired: return .rejected("offline bundle expired")
        case .clockTampered: return .rejected("system clock is wrong")
        case .invalid: return .rejected("offline unlock failed")
        }
    }
}
