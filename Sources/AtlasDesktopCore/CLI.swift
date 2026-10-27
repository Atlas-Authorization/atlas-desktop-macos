import Foundation

private func arg(_ a: [String], _ name: String) -> String? {
    guard let i = a.firstIndex(of: name), i + 1 < a.count else { return nil }
    return a[i + 1]
}

private func err(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

/// atlas-sync [--config path]: one sync round trip, cache state, upload queued offline events.
public func runSyncMain(_ args: [String]) -> Int32 {
    var code: Int32 = 0
    let sem = DispatchSemaphore(value: 0)
    Task {
        defer { sem.signal() }
        do {
            let cfg = try AgentConfig.load(path: arg(args, "--config") ?? AgentConfig.defaultPath)
            let store = KeychainSecretStore()
            guard cfg.enrolled, let key = DeviceKeyFactory.open(label: cfg.deviceKeyId, secrets: store, create: false) else { throw DesktopError.notEnrolled }
            let st = try await StateSync.run(client: ProtocolClient(config: cfg, key: key, http: URLSessionHTTPClient()), store: store, clock: SystemClock())
            print("synced: required=\(st.required.map(String.init) ?? "unknown") offline_bundle=\(st.bundle != nil)")
        } catch DesktopError.revoked { err("device revoked; offline cache wiped"); code = 3 }
        catch { err("sync failed: \(error)"); code = 1 }
    }
    sem.wait()
    return code
}

/// atlas-enroll --instance-url U --publishable-key K --instance-id I --code C [--pin P] [--user name] [--config path]
/// Secrets may come from ATLAS_ENROLL_CODE / ATLAS_ENROLL_PIN, or the PIN is prompted for.
public func runEnrollMain(_ args: [String]) -> Int32 {
    guard let url = arg(args, "--instance-url"), let pk = arg(args, "--publishable-key"), let iid = arg(args, "--instance-id"),
          let enrolCode = arg(args, "--code") ?? ProcessInfo.processInfo.environment["ATLAS_ENROLL_CODE"] else {
        err("usage: atlas-enroll --instance-url URL --publishable-key PK --instance-id INS --code CODE [--pin PIN] [--user LOCAL_ACCOUNT] [--config PATH]")
        return 2
    }
    var pin = arg(args, "--pin") ?? ProcessInfo.processInfo.environment["ATLAS_ENROLL_PIN"]
    if pin == nil, let p = getpass("Offline PIN (6-12 digits, empty for none): ") { let s = String(cString: p); pin = s.isEmpty ? nil : s }
    let path = arg(args, "--config") ?? AgentConfig.defaultPath
    let label = "device"
    var code: Int32 = 0
    let sem = DispatchSemaphore(value: 0)
    Task {
        defer { sem.signal() }
        do {
            var cfg = AgentConfig(instanceUrl: url, publishableKey: pk, instanceId: iid, deviceId: "", deviceKeyId: label, enrolled: false,
                                  failOpenWhenNeverSynced: nil, enrolledUsers: arg(args, "--user").map { [$0] })
            try cfg.validate()
            let store = KeychainSecretStore()
            guard let key = DeviceKeyFactory.open(label: label, secrets: store, create: true) else { throw DesktopError.crypto("cannot create device key") }
            let r = try await ProtocolClient(config: cfg, key: key, http: URLSessionHTTPClient())
                .enroll(code: enrolCode, pin: pin, hostname: ProcessInfo.processInfo.hostName, agentVersion: "0.1.0")
            try store.set(StateSync.macKeyName, Data(r.bundleMacKey.utf8))
            cfg.deviceId = r.device.id; cfg.enrolled = true
            try cfg.write(path: path)
            print("enrolled device \(r.device.id)")
            if let uri = r.offlineOtpUri { print("Offline authenticator URI (shown once, add it to your authenticator app):\n\(uri)") }
            if let st = try? await StateSync.run(client: ProtocolClient(config: cfg, key: key, http: URLSessionHTTPClient()), store: store, clock: SystemClock()) {
                print("initial sync ok: required=\(st.required.map(String.init) ?? "unknown")")
            }
        } catch { err("enrol failed: \(error)"); code = 1 }
    }
    sem.wait()
    return code
}
