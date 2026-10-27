import AppKit
import AtlasDesktopCore

// atlas-passkey enrol [--via ctap|authservices] [--name LABEL] [--factor totp|push] [--code 123456]
//   ctap (default): the key is driven over USB HID. Needs no signing or entitlements, works in any session.
//   authservices:   AuthenticationServices, only inside the signed AtlasPasskey.app built by scripts/build-passkey-helper.sh.
// The run loop must stay free for the system's security-key sheet, so the work runs in a task and the process exits when it finishes.
func arg(_ name: String) -> String? {
    let a = CommandLine.arguments
    guard let i = a.firstIndex(of: name), i + 1 < a.count else { return nil }
    return a[i + 1]
}
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
Task { @MainActor in
    let via = arg("--via") ?? "ctap"
    let authenticator: PasskeyAuthenticator
    switch via {
    case "authservices": authenticator = SecurityKeyAuthenticator()
    case "ctap":
        authenticator = CTAP2Authenticator.usb(pin: { retries in
            if let r = retries { FileHandle.standardError.write(Data("Wrong PIN, \(r) tries left.\n".utf8)) }
            guard let p = getpass("Security key PIN: ") else { return nil }
            let s = String(cString: p); return s.isEmpty ? nil : s
        }, status: { print($0) })
    default:
        FileHandle.standardError.write(Data("--via must be ctap or authservices\n".utf8)); exit(2)
    }
    exit(await passkeyEnrolMain(CommandLine.arguments, authenticator: authenticator))
}
app.run()
