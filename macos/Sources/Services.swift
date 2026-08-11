import Foundation
import Security

enum KeychainService {
    private static let service = "com.autunn.UniFiPolicyManagerMac"
    static let apiKeyAccount = "unifi-api-key"
    static let localPasswordAccount = "unifi-local-password"

    static func load(account: String) -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account, kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
    }

    static func save(_ value: String, account: String) throws {
        forget(account: account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: account, kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw UniFiError.api("无法写入 macOS 钥匙串（错误 \(status)）。") }
    }

    static func forget(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

struct ConnectionPreferences {
    static var host: String {
        get { UserDefaults.standard.string(forKey: "host") ?? "192.168.1.1" }
        set { UserDefaults.standard.set(newValue, forKey: "host") }
    }
    static var verifyTLS: Bool {
        get { UserDefaults.standard.bool(forKey: "verifyTLS") }
        set { UserDefaults.standard.set(newValue, forKey: "verifyTLS") }
    }
    static var authenticationMode: AuthenticationMode {
        get { AuthenticationMode(rawValue: UserDefaults.standard.string(forKey: "authenticationMode") ?? "") ?? .apiKey }
        set { UserDefaults.standard.set(newValue.rawValue, forKey: "authenticationMode") }
    }
    static var username: String {
        get { UserDefaults.standard.string(forKey: "username") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "username") }
    }
    static var rememberCredential: Bool {
        get { UserDefaults.standard.object(forKey: "rememberCredential") as? Bool ?? (UserDefaults.standard.object(forKey: "rememberKey") as? Bool ?? true) }
        set { UserDefaults.standard.set(newValue, forKey: "rememberCredential") }
    }
}

enum BackupService {
    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static var root: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("UniFiPolicyManager", isDirectory: true)
    }

    static func saveSnapshot(reason: String, bundle: PolicyBundle) throws -> URL {
        let directory = root.appendingPathComponent("backups", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss-SSS"
        let url = directory.appendingPathComponent("\(formatter.string(from: Date()))-\(reason).json")
        try encoder.encode(bundle).write(to: url, options: .atomic)
        return url
    }

    static func log(_ message: String) {
        do {
            let directory = root.appendingPathComponent("logs", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let url = directory.appendingPathComponent("operations.log")
            let line = "\(ISO8601DateFormatter().string(from: Date())) \(message)\n"
            if FileManager.default.fileExists(atPath: url.path) {
                let handle = try FileHandle(forWritingTo: url)
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: Data(line.utf8))
            } else {
                try Data(line.utf8).write(to: url)
            }
        } catch { }
    }
}
