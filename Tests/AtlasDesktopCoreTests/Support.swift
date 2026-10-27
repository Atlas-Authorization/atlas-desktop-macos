import Foundation
import CryptoKit
@testable import AtlasDesktopCore

struct Vectors {
    let j: [String: Any]
    static func load() throws -> Vectors {
        let url = Bundle.module.url(forResource: "protocol-vectors", withExtension: "json")!
        return Vectors(j: try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any])
    }
    var privateD: String { (j["device_private_jwk"] as! [String: Any])["d"] as! String }
    var macKey: Data { Data(b64u: j["mac_key_b64u"] as! String)! }
    var bundleJ: [String: Any] { j["bundle"] as! [String: Any] }
    var bundle: OfflineBundle {
        OfflineBundle(bundleId: bundleJ["bundle_id"] as! String, generation: (bundleJ["generation"] as! NSNumber).int64Value,
                      issuedAt: 1800000000000, expiresAt: (bundleJ["expires_at"] as! NSNumber).int64Value,
                      sealed: bundleJ["sealed"] as! String, mac: bundleJ["mac"] as! String)
    }
    var deviceId: String { bundleJ["device_id"] as! String }
    var pin: [String: Any] { j["pin"] as! [String: Any] }
    var key: SoftwareDeviceKey { try! SoftwareDeviceKey(privateJWKD: privateD) }
}

final class TestClock: Clock { var nowMs: Int64; init(_ n: Int64) { nowMs = n } }

final class MockHTTP: HTTPClient {
    var routes: [String: (Int, [String: Any])] = [:]   // last path component(s) after desktop_mfa/
    var calls: [(path: String, body: [String: Any], headers: [String: String])] = []
    var down = false
    func post(_ url: URL, headers: [String: String], body: Data) async throws -> HTTPResponse {
        if down { throw DesktopError.network("down") }
        let p = url.path.components(separatedBy: "/desktop_mfa/").last!
        calls.append((p, (try? JSONSerialization.jsonObject(with: body) as? [String: Any]) ?? [:], headers))
        let (s, o) = routes[p] ?? (404, ["errors": [["code": "not_found"]]])
        return HTTPResponse(status: s, data: try JSONSerialization.data(withJSONObject: o))
    }
}

func testConfig() -> AgentConfig {
    AgentConfig(instanceUrl: "https://auth.example.com", publishableKey: "pk_test", instanceId: "ins_TESTVECTOR",
                deviceId: "ddv_TESTVECTOR", deviceKeyId: "device", enrolled: true, failOpenWhenNeverSynced: nil, enrolledUsers: nil)
}

func syncBody(required: Bool, factors: [String] = ["push", "totp"], bundle: OfflineBundle? = nil, enabled: Bool = true, keep: Bool = true) -> [String: Any] {
    var off: [String: Any] = ["enabled": enabled, "grace_hours": 72, "pin_required": true, "pin_set": true, "keep_cache": keep, "bundle_valid": bundle != nil]
    if let b = bundle {
        off["bundle"] = ["bundle_id": b.bundleId, "generation": b.generation, "issued_at": b.issuedAt, "expires_at": b.expiresAt, "sealed": b.sealed, "mac": b.mac]
    }
    return ["status": "active", "required": required, "allowed_factors": factors, "offline": off, "server_time": 1800000000000]
}
