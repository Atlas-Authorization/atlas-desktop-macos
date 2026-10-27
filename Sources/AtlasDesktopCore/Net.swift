import Foundation

public struct HTTPResponse { public var status: Int; public var data: Data
    public init(status: Int, data: Data) { self.status = status; self.data = data } }

public protocol HTTPClient {
    func post(_ url: URL, headers: [String: String], body: Data) async throws -> HTTPResponse
}

/// TLS only: any non-https URL is refused before a connection is made.
public struct URLSessionHTTPClient: HTTPClient {
    let session: URLSession
    public init(timeout: TimeInterval = 8) {
        let c = URLSessionConfiguration.ephemeral
        c.timeoutIntervalForRequest = timeout
        c.timeoutIntervalForResource = timeout * 2
        c.waitsForConnectivity = false
        session = URLSession(configuration: c)
    }
    public func post(_ url: URL, headers: [String: String], body: Data) async throws -> HTTPResponse {
        guard url.scheme == "https" else { throw DesktopError.insecureURL }
        var r = URLRequest(url: url); r.httpMethod = "POST"; r.httpBody = body
        for (k, v) in headers { r.setValue(v, forHTTPHeaderField: k) }
        do {
            let (d, resp) = try await session.data(for: r)
            return HTTPResponse(status: (resp as? HTTPURLResponse)?.statusCode ?? 0, data: d)
        } catch { throw DesktopError.network("request failed") }
    }
}

public struct AgentConfig: Codable, Equatable {
    public var instanceUrl: String
    public var publishableKey: String
    public var instanceId: String
    public var deviceId: String
    public var deviceKeyId: String
    public var enrolled: Bool
    public var failOpenWhenNeverSynced: Bool?
    /// Local account names this device is enrolled for. Nil/empty means every account.
    public var enrolledUsers: [String]?
    /// Local accounts that skip Atlas entirely (their password is still verified). Default empty.
    public var breakGlassAccounts: [String]? = nil

    enum CodingKeys: String, CodingKey {
        case instanceUrl = "instance_url", publishableKey = "publishable_key", instanceId = "instance_id"
        case deviceId = "device_id", deviceKeyId = "device_key_id", enrolled
        case failOpenWhenNeverSynced = "fail_open_when_never_synced", enrolledUsers = "enrolled_users", breakGlassAccounts = "break_glass_accounts"
    }

    public static let defaultDir = "/Library/Application Support/Atlas"
    public static var defaultPath: String { defaultDir + "/config.json" }

    public static func parse(_ data: Data) throws -> AgentConfig {
        let c: AgentConfig
        do { c = try JSONDecoder().decode(AgentConfig.self, from: data) } catch { throw DesktopError.malformed("config") }
        try c.validate()
        return c
    }
    public static func load(path: String = defaultPath) throws -> AgentConfig {
        guard let d = FileManager.default.contents(atPath: path) else { throw DesktopError.notEnrolled }
        return try parse(d)
    }
    public func validate() throws {
        guard let u = URL(string: instanceUrl), u.scheme == "https", let h = u.host, !h.isEmpty else { throw DesktopError.insecureURL }
        guard !publishableKey.isEmpty, !instanceId.isEmpty else { throw DesktopError.malformed("config fields") }
        if enrolled { guard !deviceId.isEmpty, !deviceKeyId.isEmpty else { throw DesktopError.malformed("enrolled without device") } }
    }
    public var baseURL: URL { URL(string: instanceUrl.hasSuffix("/") ? String(instanceUrl.dropLast()) : instanceUrl)! }
    public func appliesTo(user: String) -> Bool {
        guard let u = enrolledUsers, !u.isEmpty else { return true }
        return u.contains(user)
    }
    public func write(path: String = defaultPath) throws {
        let dir = (path as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        let enc = JSONEncoder(); enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try enc.encode(self).write(to: URL(fileURLWithPath: path), options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
    }
}
