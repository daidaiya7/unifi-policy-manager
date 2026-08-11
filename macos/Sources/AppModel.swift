import AppKit
import Foundation
import SwiftUI

enum WorkspacePage: String, CaseIterable, Identifiable {
    case overview, dns, acl, firewall

    var id: String { rawValue }
    var title: String {
        switch self {
        case .overview: return "概览"
        case .dns: return "DNS 记录"
        case .acl: return "ACL 规则"
        case .firewall: return "防火墙策略"
        }
    }
    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .dns: return "network"
        case .acl: return "checklist.checked"
        case .firewall: return "shield.lefthalf.filled"
        }
    }
}

@MainActor
final class AppModel: ObservableObject {
    @Published var host = ConnectionPreferences.host
    @Published var authenticationMode = ConnectionPreferences.authenticationMode
    @Published var apiKey = ConnectionPreferences.rememberCredential ? KeychainService.load(account: KeychainService.apiKeyAccount) : ""
    @Published var username = ConnectionPreferences.username
    @Published var password = ConnectionPreferences.rememberCredential ? KeychainService.load(account: KeychainService.localPasswordAccount) : ""
    @Published var verifyTLS = ConnectionPreferences.verifyTLS
    @Published var rememberCredential = ConnectionPreferences.rememberCredential
    @Published var connected = false
    @Published var demoMode = false
    @Published var busy = false
    @Published var status = "准备连接"
    @Published var errorMessage: String?
    @Published var selectedPage: WorkspacePage? = .overview
    @Published var sites: [UniFiSite] = []
    @Published var selectedSite: UniFiSite?
    @Published var showSitePicker = false
    @Published var dnsRecords: [DNSRecord] = []
    @Published var aclRules: [PolicyRule] = []
    @Published var firewallRules: [PolicyRule] = []
    @Published var references: [PolicyReference] = []
    @Published var search = ""
    @Published var dnsTypeFilter = "全部"
    @Published var lastBackupURL: URL?

    private var api: UniFiAPI?

    var targetLabel: String { demoMode ? "演示环境" : (api?.target ?? host) }
    var versionLabel: String { demoMode ? "Demo 10.4.57" : (api?.applicationVersion ?? "未知") }
    var totalCount: Int { dnsRecords.count + aclRules.count + firewallRules.count }
    var canConnect: Bool {
        guard !host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        return authenticationMode == .apiKey
            ? !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            : !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !password.isEmpty
    }

    var filteredDNS: [DNSRecord] {
        dnsRecords.filter { record in
            let matchesType = dnsTypeFilter == "全部" || record.recordType == dnsTypeFilter
            let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
            return matchesType && (query.isEmpty || [record.key, record.value, record.recordType].contains { $0.localizedCaseInsensitiveContains(query) })
        }
    }

    func filteredPolicies(_ kind: PolicyKind) -> [PolicyRule] {
        let source = kind == .acl ? aclRules : firewallRules
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return source }
        return source.filter { [$0.name, $0.type, $0.action, $0.origin, $0.description].contains { $0.localizedCaseInsensitiveContains(query) } }
    }

    func connect() {
        Task {
            await perform(authenticationMode == .apiKey ? "正在验证 API Key…" : "正在登录 UniFi Console…") {
                let credentials: AuthenticationCredentials = self.authenticationMode == .apiKey
                    ? .apiKey(self.apiKey)
                    : .localAccount(username: self.username, password: self.password)
                let client = try UniFiAPI(host: self.host, credentials: credentials, verifyTLS: self.verifyTLS)
                try await client.connect()
                self.api = client
                self.sites = client.sites
                if client.sites.count == 1 {
                    await self.finishConnection(site: client.sites[0])
                } else {
                    self.showSitePicker = true
                    self.status = "请选择要管理的站点"
                }
            }
        }
    }

    func chooseSite(_ site: UniFiSite) {
        showSitePicker = false
        Task {
            await perform("正在读取站点策略…") {
                await self.finishConnection(site: site)
            }
        }
    }

    private func finishConnection(site: UniFiSite) async {
        guard let api else { return }
        api.selectSite(site)
        selectedSite = site
        ConnectionPreferences.host = host
        ConnectionPreferences.verifyTLS = verifyTLS
        ConnectionPreferences.authenticationMode = authenticationMode
        ConnectionPreferences.username = authenticationMode == .localAccount ? username.trimmingCharacters(in: .whitespacesAndNewlines) : ""
        ConnectionPreferences.rememberCredential = rememberCredential
        do {
            if rememberCredential {
                if authenticationMode == .apiKey {
                    try KeychainService.save(apiKey, account: KeychainService.apiKeyAccount)
                    KeychainService.forget(account: KeychainService.localPasswordAccount)
                } else {
                    try KeychainService.save(password, account: KeychainService.localPasswordAccount)
                    KeychainService.forget(account: KeychainService.apiKeyAccount)
                }
            } else {
                KeychainService.forget(account: KeychainService.apiKeyAccount)
                KeychainService.forget(account: KeychainService.localPasswordAccount)
            }
        } catch { errorMessage = error.localizedDescription }
        connected = true
        demoMode = false
        selectedPage = .overview
        await refreshAllBody()
        apiKey = ""
        password = ""
    }

    func startDemo() {
        demoMode = true
        connected = true
        selectedSite = UniFiSite(id: "cf95a3c0-21f4-48a8-a028-6ad714b9689e", internalReference: "default", name: "家庭网络")
        dnsRecords = DemoData.dns
        aclRules = DemoData.acl
        firewallRules = DemoData.firewall
        references = DemoData.references
        selectedPage = .overview
        status = "演示模式：不会连接或修改真实 UCG"
    }

    func disconnect() {
        api = nil
        connected = false
        demoMode = false
        selectedSite = nil
        dnsRecords = []
        aclRules = []
        firewallRules = []
        references = []
        search = ""
        apiKey = rememberCredential ? KeychainService.load(account: KeychainService.apiKeyAccount) : ""
        password = rememberCredential ? KeychainService.load(account: KeychainService.localPasswordAccount) : ""
        status = "已断开连接"
    }

    func forgetCredential() {
        KeychainService.forget(account: KeychainService.apiKeyAccount)
        KeychainService.forget(account: KeychainService.localPasswordAccount)
        apiKey = ""
        password = ""
        rememberCredential = false
        ConnectionPreferences.rememberCredential = false
        status = "已从 macOS 钥匙串删除保存的认证凭据"
    }

    func refreshAll() { Task { await perform("正在刷新全部策略…") { await self.refreshAllBody() } } }

    private func refreshAllBody() async {
        guard !demoMode, let api else { status = "演示数据已刷新"; return }
        async let dns = api.listDNSRecords()
        async let acl = api.listPolicies(.acl)
        async let firewall = api.listPolicies(.firewall)
        async let refs = api.listReferences()
        do {
            dnsRecords = try await dns.sorted { $0.key.localizedCaseInsensitiveCompare($1.key) == .orderedAscending }
            aclRules = try await acl
            firewallRules = try await firewall
            references = await refs
            status = "已读取 DNS \(dnsRecords.count) 条、ACL \(aclRules.count) 条、防火墙 \(firewallRules.count) 条"
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func saveDNS(_ record: DNSRecord) {
        Task {
            await perform(record.id == nil ? "正在新增 DNS 记录…" : "正在更新 DNS 记录…") {
                try self.backup(reason: record.id == nil ? "before-create-dns" : "before-update-dns")
                if self.demoMode {
                    var saved = record
                    if saved.id == nil { saved.id = UUID().uuidString; self.dnsRecords.append(saved) }
                    else if let index = self.dnsRecords.firstIndex(where: { $0.id == saved.id }) { self.dnsRecords[index] = saved }
                } else if let api = self.api {
                    if record.id == nil { try await api.createDNS(record) } else { try await api.updateDNS(record) }
                    await self.refreshAllBody()
                }
                BackupService.log(record.id == nil ? "create dns \(record.key)" : "update dns \(record.key)")
                self.status = record.id == nil ? "DNS 记录已新增" : "DNS 记录已更新"
            }
        }
    }

    func deleteDNS(_ record: DNSRecord) {
        Task {
            await perform("正在删除 DNS 记录…") {
                try self.backup(reason: "before-delete-dns")
                if self.demoMode { self.dnsRecords.removeAll { $0.stableID == record.stableID } }
                else if let api = self.api { try await api.deleteDNS(record); await self.refreshAllBody() }
                BackupService.log("delete dns \(record.key)")
                self.status = "DNS 记录已删除"
            }
        }
    }

    func toggleDNS(_ record: DNSRecord) { var updated = record; updated.enabled.toggle(); saveDNS(updated) }

    func savePolicy(kind: PolicyKind, existing: PolicyRule?, json: String) {
        Task {
            await perform(existing == nil ? "正在新增策略…" : "正在更新策略…") {
                try self.backup(reason: existing == nil ? "before-create-policy" : "before-update-policy")
                if self.demoMode {
                    let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] ?? [:]
                    let raw = String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
                    let rule = PolicyRule(
                        id: existing?.id ?? UUID().uuidString, kind: kind, name: object["name"] as? String ?? "未命名",
                        enabled: object["enabled"] as? Bool ?? false, index: existing?.index ?? 999,
                        type: object["type"] as? String ?? "IPV4", action: (object["action"] as? String) ?? ((object["action"] as? [String: Any])?["type"] as? String ?? "BLOCK"),
                        origin: "USER_DEFINED", description: object["description"] as? String ?? "", rawJSON: raw
                    )
                    if kind == .acl { self.upsert(rule, in: &self.aclRules) } else { self.upsert(rule, in: &self.firewallRules) }
                } else if let api = self.api {
                    if let existing { try await api.updatePolicy(existing, json: json) } else { try await api.createPolicy(kind, json: json) }
                    await self.refreshAllBody()
                }
                BackupService.log("save \(kind.rawValue) policy")
                self.status = existing == nil ? "策略已新增" : "策略已更新"
            }
        }
    }

    func deletePolicy(_ rule: PolicyRule) {
        Task {
            await perform("正在删除策略…") {
                try self.backup(reason: "before-delete-policy")
                if self.demoMode {
                    if rule.kind == .acl { self.aclRules.removeAll { $0.id == rule.id } } else { self.firewallRules.removeAll { $0.id == rule.id } }
                } else if let api = self.api { try await api.deletePolicy(rule); await self.refreshAllBody() }
                BackupService.log("delete \(rule.kind.rawValue) policy \(rule.name)")
                self.status = "策略已删除"
            }
        }
    }

    func togglePolicy(_ rule: PolicyRule) {
        guard rule.canModify,
              var object = try? JSONSerialization.jsonObject(with: Data(rule.editableJSON.utf8)) as? [String: Any] else { return }
        object["enabled"] = !rule.enabled
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]) else { return }
        savePolicy(kind: rule.kind, existing: rule, json: String(decoding: data, as: UTF8.self))
    }

    func exportBaseline() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "unifi-policy-baseline-\(dateStamp()).json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try BackupService.encoder.encode(bundle()).write(to: url, options: .atomic)
            status = "基线已导出到 \(url.lastPathComponent)"
        } catch { errorMessage = error.localizedDescription }
    }

    func revealBackups() {
        try? FileManager.default.createDirectory(at: BackupService.root.appendingPathComponent("backups"), withIntermediateDirectories: true)
        NSWorkspace.shared.activateFileViewerSelecting([BackupService.root.appendingPathComponent("backups")])
    }

    private func backup(reason: String) throws { lastBackupURL = try BackupService.saveSnapshot(reason: reason, bundle: bundle()) }

    private func bundle() -> PolicyBundle {
        PolicyBundle(
            schemaVersion: 2, createdAt: Date(), target: targetLabel, site: selectedSite?.displayName ?? "",
            siteID: selectedSite?.id ?? "", networkVersion: versionLabel, dnsRecords: dnsRecords,
            aclRules: aclRules.map(jsonValue), firewallPolicies: firewallRules.map(jsonValue)
        )
    }

    private func jsonValue(_ rule: PolicyRule) -> JSONValue {
        guard let object = try? JSONSerialization.jsonObject(with: Data(rule.rawJSON.utf8)) else { return .object([:]) }
        return .from(object)
    }

    private func upsert(_ rule: PolicyRule, in array: inout [PolicyRule]) {
        if let index = array.firstIndex(where: { $0.id == rule.id }) { array[index] = rule } else { array.append(rule) }
    }

    private func perform(_ message: String, operation: @escaping () async throws -> Void) async {
        guard !busy else { return }
        busy = true
        status = message
        do { try await operation() } catch { errorMessage = error.localizedDescription; status = "操作失败" }
        busy = false
    }

    private func dateStamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}

enum DemoData {
    static let dns = [
        DNSRecord(id: UUID().uuidString, recordType: "NS", key: "openai.com", value: "192.168.1.10"),
        DNSRecord(id: UUID().uuidString, recordType: "A", key: "nas.home.arpa", value: "192.168.1.20", ttl: 300),
        DNSRecord(id: UUID().uuidString, recordType: "CNAME", key: "media.home.arpa", value: "nas.home.arpa", ttl: 300),
        DNSRecord(id: UUID().uuidString, recordType: "TXT", key: "_policy.home.arpa", value: "managed-by=unifi-policy-manager")
    ]
    static let acl = [
        policy(.acl, "允许管理网段", true, 1, "IPV4", "ALLOW", "USER_DEFINED"),
        policy(.acl, "访客隔离", true, 2, "IPV4", "BLOCK", "USER_DEFINED"),
        policy(.acl, "System default", true, 3, "IPV4", "ALLOW", "SYSTEM_DEFINED")
    ]
    static let firewall = [
        policy(.firewall, "允许 DNS 到基础设施", true, 10, "IPV4", "ALLOW", "USER_DEFINED"),
        policy(.firewall, "阻止 IoT 访问管理网", true, 20, "IPV4_AND_IPV6", "BLOCK", "USER_DEFINED")
    ]
    static let references = [
        PolicyReference(id: UUID().uuidString, name: "Default", kind: "网络"),
        PolicyReference(id: UUID().uuidString, name: "Internal", kind: "防火墙区域")
    ]

    private static func policy(_ kind: PolicyKind, _ name: String, _ enabled: Bool, _ index: Int, _ type: String, _ action: String, _ origin: String) -> PolicyRule {
        let id = UUID().uuidString
        let object: [String: Any] = kind == .acl
            ? ["id": id, "name": name, "enabled": enabled, "type": type, "action": action, "description": "", "metadata": ["origin": origin]]
            : ["id": id, "name": name, "enabled": enabled, "loggingEnabled": false, "description": "", "action": ["type": action], "source": ["zoneId": UUID().uuidString], "destination": ["zoneId": UUID().uuidString], "ipProtocolScope": ["ipVersion": type], "metadata": ["origin": origin]]
        let raw = String(decoding: try! JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]), as: UTF8.self)
        return PolicyRule(id: id, kind: kind, name: name, enabled: enabled, index: index, type: type, action: action, origin: origin, description: "", rawJSON: raw)
    }
}
