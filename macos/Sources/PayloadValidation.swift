import Foundation
import Network

enum UniFiPayloadValidator {
    static func normalizeDNS(_ source: DNSRecord) throws -> DNSRecord {
        var record = source
        record.recordType = record.recordType.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard ["NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV"].contains(record.recordType) else {
            throw UniFiError.api("不支持的 DNS 类型。")
        }

        if record.recordType == "SRV" {
            record.domain = try domain(record.domain, label: "域名")
            record.service = try service(record.service, label: "服务", example: "_sip")
            record.protocolName = try service(record.protocolName, label: "协议", example: "_tcp")
            record.key = "\(record.service).\(record.protocolName).\(record.domain)"
        } else {
            record.key = try domain(record.key, label: "域名")
        }

        switch record.recordType {
        case "NS":
            record.value = try ipAddress(record.value, family: nil, label: "DNS 服务器")
        case "A":
            record.value = try ipAddress(record.value, family: .v4, label: "IPv4 地址")
            record.ttl = try integer(record.ttl, label: "TTL", range: 0...86_400)
        case "AAAA":
            record.value = try ipAddress(record.value, family: .v6, label: "IPv6 地址")
            record.ttl = try integer(record.ttl, label: "TTL", range: 0...86_400)
        case "CNAME":
            record.value = try domain(record.value, label: "目标域名")
            record.ttl = try integer(record.ttl, label: "TTL", range: 0...604_800)
        case "MX":
            record.value = try domain(record.value, label: "邮件服务器域名")
            record.priority = try integer(record.priority, label: "优先级", range: 0...65_535)
        case "TXT":
            guard !record.value.isEmpty else { throw UniFiError.api("TXT 文本不能为空。") }
            guard record.value.count <= 1_024 else { throw UniFiError.api("TXT 文本总长度不能超过 1024 个字符。") }
            let lines = record.value.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false)
            guard lines.count <= 4 else { throw UniFiError.api("TXT 最多包含 4 段文本。") }
            guard lines.allSatisfy({ $0.count <= 255 }) else { throw UniFiError.api("TXT 每段不能超过 255 个字符。") }
            guard lines.allSatisfy({ !$0.contains(",") || ($0.hasPrefix("\"") && $0.hasSuffix("\"")) }) else {
                throw UniFiError.api("TXT 中包含逗号的行必须使用双引号包裹。")
            }
        case "SRV":
            record.value = try domain(record.value, label: "服务器域名")
            record.port = try integer(record.port, label: "端口", range: 0...65_535)
            record.priority = try integer(record.priority, label: "优先级", range: 0...65_535)
            record.weight = try integer(record.weight, label: "权重", range: 0...65_535)
        default:
            break
        }
        return record
    }

    static func dnsPayload(_ source: DNSRecord) throws -> [String: Any] {
        let record = try normalizeDNS(source)
        let apiType = [
            "NS": "FORWARD_DOMAIN", "A": "A_RECORD", "AAAA": "AAAA_RECORD",
            "CNAME": "CNAME_RECORD", "MX": "MX_RECORD", "TXT": "TXT_RECORD", "SRV": "SRV_RECORD"
        ][record.recordType]!
        var payload: [String: Any] = [
            "type": apiType,
            "enabled": record.enabled,
            "domain": record.recordType == "SRV" ? record.domain : record.key
        ]
        switch record.recordType {
        case "NS": payload["ipAddress"] = record.value
        case "A": payload["ipv4Address"] = record.value; payload["ttlSeconds"] = record.ttl!
        case "AAAA": payload["ipv6Address"] = record.value; payload["ttlSeconds"] = record.ttl!
        case "CNAME": payload["targetDomain"] = record.value; payload["ttlSeconds"] = record.ttl!
        case "MX": payload["mailServerDomain"] = record.value; payload["priority"] = record.priority!
        case "TXT": payload["text"] = record.value
        case "SRV":
            payload["service"] = record.service
            payload["protocol"] = record.protocolName
            payload["serverDomain"] = record.value
            payload["port"] = record.port!
            payload["priority"] = record.priority!
            payload["weight"] = record.weight!
        default: break
        }
        return payload
    }

    static func policyPayload(_ kind: PolicyKind, json: String) throws -> [String: Any] {
        guard var object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
            throw UniFiError.api("策略请求体必须是 JSON 对象。")
        }
        guard let name = object["name"] as? String, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw UniFiError.api("策略 JSON 缺少非空 name。")
        }
        guard object["enabled"] is Bool else { throw UniFiError.api("策略 JSON 缺少布尔字段 enabled。") }

        if kind == .acl {
            guard let type = (object["type"] as? String)?.uppercased(), ["IPV4", "MAC"].contains(type) else {
                throw UniFiError.api("ACL type 必须是 IPV4 或 MAC。")
            }
            guard let action = (object["action"] as? String)?.uppercased(), ["ALLOW", "BLOCK"].contains(action) else {
                throw UniFiError.api("ACL action 必须是 ALLOW 或 BLOCK。")
            }
            object["type"] = type
            object["action"] = action
            if type == "MAC" { try requireUUID(object["networkIdFilter"], label: "networkIdFilter") }
        } else {
            guard object["loggingEnabled"] is Bool else {
                throw UniFiError.api("防火墙策略缺少布尔字段 loggingEnabled。")
            }
            guard var action = object["action"] as? [String: Any],
                  let actionType = (action["type"] as? String)?.uppercased(),
                  ["ALLOW", "BLOCK", "REJECT"].contains(actionType) else {
                throw UniFiError.api("防火墙 action.type 必须是 ALLOW、BLOCK 或 REJECT。")
            }
            guard let source = object["source"] as? [String: Any] else {
                throw UniFiError.api("防火墙策略缺少 source 对象。")
            }
            guard let destination = object["destination"] as? [String: Any] else {
                throw UniFiError.api("防火墙策略缺少 destination 对象。")
            }
            guard var scope = object["ipProtocolScope"] as? [String: Any],
                  let ipVersion = (scope["ipVersion"] as? String)?.uppercased(),
                  ["IPV4", "IPV6", "IPV4_AND_IPV6"].contains(ipVersion) else {
                throw UniFiError.api("ipProtocolScope.ipVersion 必须是 IPV4、IPV6 或 IPV4_AND_IPV6。")
            }
            try requireUUID(source["zoneId"], label: "source.zoneId")
            try requireUUID(destination["zoneId"], label: "destination.zoneId")
            action["type"] = actionType
            if actionType == "ALLOW" && !(action["allowReturnTraffic"] is Bool) {
                action["allowReturnTraffic"] = false
            }
            scope["ipVersion"] = ipVersion
            object["action"] = action
            object["ipProtocolScope"] = scope
        }

        object.removeValue(forKey: "id")
        object.removeValue(forKey: "index")
        object.removeValue(forKey: "metadata")
        return object
    }

    private enum IPFamily { case v4, v6 }

    private static func ipAddress(_ value: String, family: IPFamily?, label: String) throws -> String {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let valid: Bool
        switch family {
        case .v4: valid = IPv4Address(text) != nil
        case .v6: valid = IPv6Address(text) != nil
        case nil: valid = IPv4Address(text) != nil || IPv6Address(text) != nil
        }
        guard valid else { throw UniFiError.api("请输入有效的\(label)。") }
        return text
    }

    private static func domain(_ value: String, label: String) throws -> String {
        let text = value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
        guard !text.isEmpty else { throw UniFiError.api("\(label)不能为空。") }
        guard text.count <= 127 else { throw UniFiError.api("\(label)不能超过 127 个字符。") }
        let labels = text.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 }) else {
            throw UniFiError.api("\(label)格式不正确。")
        }
        return text
    }

    private static func service(_ value: String, label: String, example: String) throws -> String {
        var text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !text.hasPrefix("_") { text = "_" + text }
        let pattern = "^_[a-z0-9][a-z0-9-]{0,61}$"
        guard text.range(of: pattern, options: .regularExpression) != nil else {
            throw UniFiError.api("\(label)格式应类似 \(example)。")
        }
        return text
    }

    private static func integer(_ value: Int?, label: String, range: ClosedRange<Int>) throws -> Int {
        let number = value ?? 0
        guard range.contains(number) else {
            throw UniFiError.api("\(label)必须在 \(range.lowerBound) 到 \(range.upperBound) 之间。")
        }
        return number
    }

    private static func requireUUID(_ value: Any?, label: String) throws {
        guard let text = value as? String, UUID(uuidString: text) != nil else {
            throw UniFiError.api("\(label) 必须是有效的 UUID。")
        }
    }
}
