import Foundation

enum PolicyChangeScope: String, CaseIterable {
    case dns, acl, firewall

    var label: String {
        switch self {
        case .dns: return "DNS"
        case .acl: return "ACL"
        case .firewall: return "防火墙"
        }
    }
}

enum PolicyChangeAction: String, CaseIterable {
    case add, update, delete, unchanged, invalid

    var label: String {
        switch self {
        case .add: return "新增"
        case .update: return "更新"
        case .delete: return "删除"
        case .unchanged: return "不变"
        case .invalid: return "无效"
        }
    }

    var actionable: Bool { self == .add || self == .update || self == .delete }
}

struct PolicyChangeItem: Identifiable {
    let id = UUID()
    var scope: PolicyChangeScope
    var action: PolicyChangeAction
    var name: String
    var details: String
    var currentID: String?
    var desiredSourceID: String?
    var actualID: String?
    var desiredIndex: Int = 0
    var desiredDNS: DNSRecord?
    var desiredPolicyJSON: String?
    var isSelected = false
    var status = "待执行"
}

struct PolicyChangePlan {
    var bundle: PolicyBundle
    var sourceURL: URL
    var synchronizeDeletes: Bool
    var items: [PolicyChangeItem]

    func count(_ action: PolicyChangeAction) -> Int { items.filter { $0.action == action }.count }
    var selectedCount: Int { items.filter(\.isSelected).count }
    var selectedDeleteCount: Int { items.filter { $0.isSelected && $0.action == .delete }.count }
}

enum PolicyBundleCodec {
    static func load(_ url: URL) throws -> PolicyBundle {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = fractional.date(from: value) { return date }
            let standard = ISO8601DateFormatter()
            if let date = standard.date(from: value) { return date }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "无法解析日期：\(value)")
        }
        do {
            return try decoder.decode(PolicyBundle.self, from: Data(contentsOf: url))
        } catch {
            throw UniFiError.api("无法读取策略基线 JSON：\(error.localizedDescription)")
        }
    }

    static func save(_ bundle: PolicyBundle, to url: URL) throws {
        try BackupService.encoder.encode(bundle).write(to: url, options: .atomic)
    }
}

enum PolicyChangeService {
    static func buildPlan(
        bundle: PolicyBundle,
        sourceURL: URL,
        currentDNS: [DNSRecord],
        currentACL: [PolicyRule],
        currentFirewall: [PolicyRule],
        synchronizeDeletes: Bool
    ) -> PolicyChangePlan {
        var items: [PolicyChangeItem] = []
        if bundle.hasDNSSection { buildDNSItems(&items, desiredRecords: bundle.dnsRecords, currentRecords: currentDNS, synchronizeDeletes: synchronizeDeletes) }
        if bundle.hasACLSection { buildPolicyItems(&items, kind: .acl, desiredValues: bundle.aclRules, currentRules: currentACL, synchronizeDeletes: synchronizeDeletes) }
        if bundle.hasFirewallSection { buildPolicyItems(&items, kind: .firewall, desiredValues: bundle.firewallPolicies, currentRules: currentFirewall, synchronizeDeletes: synchronizeDeletes) }
        for index in items.indices where items[index].action == .add || items[index].action == .update { items[index].isSelected = true }
        items.sort {
            let left = (scopeOrder($0.scope), actionOrder($0.action), $0.desiredIndex, $0.name.lowercased())
            let right = (scopeOrder($1.scope), actionOrder($1.action), $1.desiredIndex, $1.name.lowercased())
            return left < right
        }
        return PolicyChangePlan(bundle: bundle, sourceURL: sourceURL, synchronizeDeletes: synchronizeDeletes, items: items)
    }

    static func editablePolicyJSON(kind: PolicyKind, value: JSONValue) throws -> String {
        guard var object = value.foundationValue as? [String: Any] else { throw UniFiError.api("策略项不是 JSON 对象。") }
        object.removeValue(forKey: "id")
        object.removeValue(forKey: "index")
        object.removeValue(forKey: "metadata")
        let raw = String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        let normalized = try UniFiPayloadValidator.policyPayload(kind, json: raw)
        return String(decoding: try JSONSerialization.data(withJSONObject: normalized, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
    }

    static func policyID(_ value: JSONValue) -> String? {
        guard case .object(let object) = value, case .string(let id)? = object["id"] else { return nil }
        return id
    }

    static func policyName(_ value: JSONValue) -> String? {
        guard case .object(let object) = value, case .string(let name)? = object["name"] else { return nil }
        return name
    }

    private static func buildDNSItems(
        _ items: inout [PolicyChangeItem], desiredRecords: [DNSRecord], currentRecords: [DNSRecord], synchronizeDeletes: Bool
    ) {
        let currentByID = Dictionary(uniqueKeysWithValues: currentRecords.compactMap { record in record.id.map { ($0.lowercased(), record) } })
        let grouped = Dictionary(grouping: currentRecords, by: DNSImportService.identity)
        var desiredKeys = Set<String>()
        var matchedCurrent = Set<String>()
        var hasInvalid = false
        for source in desiredRecords {
            do {
                let desired = try UniFiPayloadValidator.normalizeDNS(source)
                let key = DNSImportService.identity(desired)
                guard desiredKeys.insert(key).inserted else {
                    hasInvalid = true
                    items.append(invalid(.dns, name: desired.key, details: "目标文件中存在重复 DNS 规则。"))
                    continue
                }
                let byID = desired.id.flatMap { currentByID[$0.lowercased()] }.flatMap { matchedCurrent.contains($0.stableID) ? nil : $0 }
                let current = byID ?? grouped[key]?.first(where: { !matchedCurrent.contains($0.stableID) })
                guard let current else {
                    items.append(PolicyChangeItem(scope: .dns, action: .add, name: "\(desired.typeLabel) · \(desired.key)", details: DNSImportService.describe(desired), desiredDNS: desired))
                    continue
                }
                matchedCurrent.insert(current.stableID)
                let changed = !dnsContentEquals(current, desired)
                items.append(PolicyChangeItem(
                    scope: .dns, action: changed ? .update : .unchanged,
                    name: "\(desired.typeLabel) · \(desired.key)",
                    details: changed ? "\(DNSImportService.describe(current))  →  \(DNSImportService.describe(desired))" : DNSImportService.describe(desired),
                    currentID: current.id, actualID: current.id, desiredDNS: desired,
                    status: changed ? "待执行" : "无需变更"
                ))
            } catch {
                hasInvalid = true
                items.append(invalid(.dns, name: source.key, details: error.localizedDescription))
            }
        }
        if synchronizeDeletes && !hasInvalid {
            for current in currentRecords where !matchedCurrent.contains(current.stableID) {
                items.append(PolicyChangeItem(
                    scope: .dns, action: .delete, name: "\(current.typeLabel) · \(current.key)",
                    details: DNSImportService.describe(current), currentID: current.id, actualID: current.id
                ))
            }
        }
    }

    private static func buildPolicyItems(
        _ items: inout [PolicyChangeItem], kind: PolicyKind, desiredValues: [JSONValue], currentRules: [PolicyRule], synchronizeDeletes: Bool
    ) {
        let scope: PolicyChangeScope = kind == .acl ? .acl : .firewall
        let currentUserRules = currentRules.filter(\.canModify)
        var unmatched = Set(currentUserRules.map(\.id))
        var desiredNames = Set<String>()
        var hasInvalid = false
        let ordered = desiredValues.sorted { policyIndex($0) < policyIndex($1) }
        for value in ordered {
            if let origin = policyOrigin(value), !origin.isEmpty, origin.caseInsensitiveCompare("USER_DEFINED") != .orderedSame { continue }
            let name = policyName(value) ?? "未命名策略"
            guard desiredNames.insert(name.lowercased()).inserted else {
                hasInvalid = true
                items.append(invalid(scope, name: name, details: "目标文件中存在重名的用户策略，无法安全匹配。"))
                continue
            }
            do {
                let editable = try editablePolicyJSON(kind: kind, value: value)
                let sourceID = policyID(value)
                let current = currentUserRules.first(where: { rule in
                    guard unmatched.contains(rule.id) else { return false }
                    if let sourceID, rule.id.caseInsensitiveCompare(sourceID) == .orderedSame { return true }
                    return rule.name.caseInsensitiveCompare(name) == .orderedSame
                })
                guard let current else {
                    items.append(PolicyChangeItem(
                        scope: scope, action: .add, name: name, details: describePolicy(kind, value),
                        desiredSourceID: sourceID, desiredIndex: policyIndex(value), desiredPolicyJSON: editable
                    ))
                    continue
                }
                unmatched.remove(current.id)
                let currentObject = try UniFiPayloadValidator.policyPayload(kind, json: current.editableJSON)
                let changed = !jsonEqual(editable, currentObject)
                items.append(PolicyChangeItem(
                    scope: scope, action: changed ? .update : .unchanged, name: name,
                    details: changed ? "\(current.action) / \(current.type)  →  \(describePolicy(kind, value))" : describePolicy(kind, value),
                    currentID: current.id, desiredSourceID: sourceID, actualID: current.id,
                    desiredIndex: policyIndex(value), desiredPolicyJSON: editable,
                    status: changed ? "待执行" : "无需变更"
                ))
            } catch {
                hasInvalid = true
                items.append(invalid(scope, name: name, details: error.localizedDescription))
            }
        }
        if synchronizeDeletes && !hasInvalid {
            for current in currentUserRules where unmatched.contains(current.id) {
                items.append(PolicyChangeItem(
                    scope: scope, action: .delete, name: current.name,
                    details: "\(current.action) / \(current.type) · \(current.description)",
                    currentID: current.id, actualID: current.id, desiredIndex: current.index
                ))
            }
        }
    }

    private static func dnsContentEquals(_ left: DNSRecord, _ right: DNSRecord) -> Bool {
        left.recordType.caseInsensitiveCompare(right.recordType) == .orderedSame &&
        left.key.caseInsensitiveCompare(right.key) == .orderedSame &&
        (left.recordType == "TXT" ? left.value == right.value : left.value.caseInsensitiveCompare(right.value) == .orderedSame) &&
        left.enabled == right.enabled && (left.ttl ?? 0) == (right.ttl ?? 0) &&
        (left.priority ?? 0) == (right.priority ?? 0) && (left.weight ?? 0) == (right.weight ?? 0) &&
        (left.port ?? 0) == (right.port ?? 0) &&
        left.service.caseInsensitiveCompare(right.service) == .orderedSame &&
        left.protocolName.caseInsensitiveCompare(right.protocolName) == .orderedSame
    }

    private static func jsonEqual(_ desiredJSON: String, _ currentObject: [String: Any]) -> Bool {
        guard let desired = try? JSONSerialization.jsonObject(with: Data(desiredJSON.utf8)) as? NSDictionary else { return false }
        return desired.isEqual(to: currentObject)
    }

    private static func invalid(_ scope: PolicyChangeScope, name: String, details: String) -> PolicyChangeItem {
        PolicyChangeItem(scope: scope, action: .invalid, name: name.isEmpty ? "无效项目" : name, details: details, status: "需要修正")
    }

    private static func policyIndex(_ value: JSONValue) -> Int {
        guard case .object(let object) = value, case .number(let number)? = object["index"] else { return 0 }
        return Int(number)
    }

    private static func policyOrigin(_ value: JSONValue) -> String? {
        guard case .object(let object) = value,
              case .object(let metadata)? = object["metadata"],
              case .string(let origin)? = metadata["origin"] else { return nil }
        return origin
    }

    private static func describePolicy(_ kind: PolicyKind, _ value: JSONValue) -> String {
        guard case .object(let object) = value else { return "-" }
        let action: String
        if kind == .acl, case .string(let raw)? = object["action"] { action = raw }
        else if case .object(let actionObject)? = object["action"], case .string(let raw)? = actionObject["type"] { action = raw }
        else { action = "-" }
        let type: String
        if kind == .acl, case .string(let raw)? = object["type"] { type = raw }
        else if case .object(let scope)? = object["ipProtocolScope"], case .string(let raw)? = scope["ipVersion"] { type = raw }
        else { type = "-" }
        let description: String
        if case .string(let raw)? = object["description"] { description = raw } else { description = "" }
        return "\(action) / \(type)\(description.isEmpty ? "" : " · \(description)")"
    }

    private static func scopeOrder(_ scope: PolicyChangeScope) -> Int {
        switch scope { case .dns: return 0; case .acl: return 1; case .firewall: return 2 }
    }

    private static func actionOrder(_ action: PolicyChangeAction) -> Int {
        switch action { case .invalid: return 0; case .add: return 1; case .update: return 2; case .delete: return 3; case .unchanged: return 4 }
    }
}
