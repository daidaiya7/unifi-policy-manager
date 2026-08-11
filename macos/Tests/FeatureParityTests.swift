import Foundation
import XCTest
@testable import UniFiPolicyManagerMac

final class FeatureParityTests: XCTestCase {
    func testDNSBatchParserSupportsAllOfficialTypesAndDeduplicates() throws {
        let csv = """
        类型,域名,值或服务器,TTL,优先级,权重,端口,服务,协议,启用
        NS,example.com,192.168.1.10,,,,,,,TRUE
        FORWARD_DOMAIN,example.com,192.168.1.10,,,,,,,TRUE
        A,a.example.com,192.0.2.10,300,,,,,,TRUE
        AAAA,aaaa.example.com,2001:db8::10,3600,,,,,,TRUE
        CNAME,www.example.com,target.example.com,300,,,,,,TRUE
        MX,example.com,mail.example.com,,10,,,,,TRUE
        TXT,_policy.example.com,managed=true,,,,,,,TRUE
        SRV,example.com,sip.example.com,,10,5,5060,_sip,_tcp,TRUE
        """

        let result = try DNSImportService.parseText(csv, defaultDNSServer: "192.168.1.10")

        XCTAssertEqual(result.records.count, 7)
        XCTAssertEqual(Set(result.records.map(\.recordType)), Set(["NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV"]))
        XCTAssertEqual(result.duplicateInput.count, 1)
        XCTAssertTrue(result.invalid.isEmpty)
    }

    func testWindowsBaselineFieldsDecodeOnMac() throws {
        let json = """
        {
          "schema_version": 2,
          "created_at": "2026-08-11T10:00:00.1234567+00:00",
          "target": "https://192.168.1.1",
          "site": "default",
          "site_id": "site-id",
          "network_version": "10.4.57",
          "dns_records": [
            { "_id": "dns-id", "record_type": "NS", "key": "example.com", "value": "192.168.1.10", "enabled": true }
          ],
          "acl_rules": [],
          "firewall_policies": [],
          "acl_ordering": {
            "kind": "Acl",
            "ordered_acl_rule_ids": ["acl-id"],
            "before_system_defined": [],
            "after_system_defined": []
          }
        }
        """
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        try Data(json.utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let bundle = try PolicyBundleCodec.load(url)

        XCTAssertEqual(bundle.dnsRecords.first?.id, "dns-id")
        XCTAssertEqual(bundle.aclOrdering?.kind, .acl)
        XCTAssertEqual(bundle.aclOrdering?.orderedACLRuleIDs, ["acl-id"])
        XCTAssertTrue(bundle.hasDNSSection)
        XCTAssertTrue(bundle.hasACLSection)
        XCTAssertTrue(bundle.hasFirewallSection)
    }

    func testBundledForwardDomainCSVContains212UsableRules() throws {
        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let preset = repositoryRoot.appendingPathComponent("Presets/unifi-forward-domains-by-service.csv")

        let result = try DNSImportService.importFile(preset, defaultDNSServer: "192.168.1.10")

        XCTAssertEqual(result.records.count, 212)
        XCTAssertTrue(result.records.allSatisfy { $0.recordType == "NS" && $0.value == "192.168.1.10" })
        XCTAssertTrue(result.duplicateInput.isEmpty)
        XCTAssertTrue(result.invalid.isEmpty)
    }

    func testStrictSyncControlsDeletionPlan() {
        let current = [
            DNSRecord(id: "keep", recordType: "NS", key: "keep.example.com", value: "192.168.1.10"),
            DNSRecord(id: "remove", recordType: "NS", key: "remove.example.com", value: "192.168.1.10")
        ]
        let bundle = PolicyBundle(dnsRecords: [current[0]])
        let source = URL(fileURLWithPath: "/tmp/baseline.json")

        let safe = PolicyChangeService.buildPlan(bundle: bundle, sourceURL: source, currentDNS: current, currentACL: [], currentFirewall: [], synchronizeDeletes: false)
        let strict = PolicyChangeService.buildPlan(bundle: bundle, sourceURL: source, currentDNS: current, currentACL: [], currentFirewall: [], synchronizeDeletes: true)

        XCTAssertEqual(safe.count(.delete), 0)
        XCTAssertEqual(strict.count(.delete), 1)
        XCTAssertEqual(strict.items.first(where: { $0.action == .delete })?.isSelected, false)
    }
}
