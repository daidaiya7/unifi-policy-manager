import Foundation

enum AuthenticationMode: String, CaseIterable, Identifiable {
    case apiKey
    case localAccount

    var id: String { rawValue }
    var title: String { self == .apiKey ? "API Key" : "用户名密码" }
}

enum AuthenticationCredentials {
    case apiKey(String)
    case localAccount(username: String, password: String)
}

struct UniFiSite: Identifiable, Codable, Hashable {
    let id: String
    let internalReference: String
    let name: String

    var displayName: String { name.isEmpty ? internalReference : name }
}

enum PolicyKind: String, Codable, CaseIterable, Identifiable {
    case acl
    case firewall

    var id: String { rawValue }
    var title: String { self == .acl ? "ACL" : "防火墙" }
    var apiPath: String { self == .acl ? "acl-rules" : "firewall/policies" }
}

struct DNSRecord: Identifiable, Codable, Hashable {
    var id: String?
    var recordType: String
    var key: String
    var value: String
    var enabled: Bool
    var ttl: Int?
    var priority: Int?
    var weight: Int?
    var port: Int?
    var service: String
    var protocolName: String
    var domain: String

    init(
        id: String? = nil, recordType: String = "NS", key: String = "", value: String = "",
        enabled: Bool = true, ttl: Int? = nil, priority: Int? = nil, weight: Int? = nil,
        port: Int? = nil, service: String = "", protocolName: String = "", domain: String = ""
    ) {
        self.id = id
        self.recordType = recordType
        self.key = key
        self.value = value
        self.enabled = enabled
        self.ttl = ttl
        self.priority = priority
        self.weight = weight
        self.port = port
        self.service = service
        self.protocolName = protocolName
        self.domain = domain
    }

    enum CodingKeys: String, CodingKey {
        case id
        case recordType = "record_type"
        case key, value, enabled, ttl, priority, weight, port, service, domain
        case protocolName = "protocol"
    }

    var stableID: String { id ?? "\(recordType)|\(key)|\(value)" }
    var typeLabel: String { recordType == "NS" ? "转发域名" : recordType }
    var stateLabel: String { enabled ? "已启用" : "已停用" }
    var extraLabel: String {
        switch recordType {
        case "A", "AAAA", "CNAME": return (ttl ?? 0) > 0 ? "TTL \(ttl!) 秒" : "TTL 自动"
        case "MX": return "优先级 \(priority ?? 0)"
        case "SRV": return "端口 \(port ?? 0) · 优先级 \(priority ?? 0) · 权重 \(weight ?? 0)"
        default: return ""
        }
    }
}

struct PolicyRule: Identifiable, Codable, Hashable {
    let id: String
    let kind: PolicyKind
    let name: String
    let enabled: Bool
    let index: Int
    let type: String
    let action: String
    let origin: String
    let description: String
    let rawJSON: String

    var canModify: Bool { origin.caseInsensitiveCompare("USER_DEFINED") == .orderedSame }
    var stateLabel: String { enabled ? "已启用" : "已停用" }
    var originLabel: String {
        switch origin {
        case "USER_DEFINED": return "用户定义"
        case "SYSTEM_DEFINED": return "系统定义"
        case "DERIVED": return "派生"
        case "ORCHESTRATED": return "编排"
        default: return origin
        }
    }

    var editableJSON: String {
        guard var object = try? JSONSerialization.jsonObject(with: Data(rawJSON.utf8)) as? [String: Any] else { return rawJSON }
        object.removeValue(forKey: "id")
        object.removeValue(forKey: "index")
        object.removeValue(forKey: "metadata")
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return rawJSON }
        return String(decoding: data, as: UTF8.self)
    }
}

struct PolicyReference: Identifiable, Hashable {
    let id: String
    let name: String
    let kind: String
}

struct PolicyBundle: Codable {
    let schemaVersion: Int
    let createdAt: Date
    let target: String
    let site: String
    let siteID: String
    let networkVersion: String
    let dnsRecords: [DNSRecord]
    let aclRules: [JSONValue]
    let firewallPolicies: [JSONValue]

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case createdAt = "created_at"
        case target, site
        case siteID = "site_id"
        case networkVersion = "network_version"
        case dnsRecords = "dns_records"
        case aclRules = "acl_rules"
        case firewallPolicies = "firewall_policies"
    }
}

enum JSONValue: Codable, Hashable {
    case string(String), number(Double), bool(Bool), object([String: JSONValue]), array([JSONValue]), null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else { self = .array(try container.decode([JSONValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .bool(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .null: try container.encodeNil()
        }
    }
}

extension JSONValue {
    static func from(_ value: Any) -> JSONValue {
        switch value {
        case let value as String: return .string(value)
        case let value as Bool: return .bool(value)
        case let value as NSNumber: return .number(value.doubleValue)
        case let value as [String: Any]: return .object(value.mapValues(JSONValue.from))
        case let value as [Any]: return .array(value.map(JSONValue.from))
        default: return .null
        }
    }
}
