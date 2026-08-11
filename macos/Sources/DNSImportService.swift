import AppKit
import Foundation
import FoundationXML

struct DNSImportResult {
    var records: [DNSRecord]
    var duplicateInput: [String]
    var invalid: [String]
}

struct DNSBatchPreview: Identifiable {
    let id = UUID()
    var pending: [DNSRecord]
    var existing: [DNSRecord]
    var duplicateInput: [String]
    var invalid: [String]
}

enum DNSImportService {
    static let editorHeader = "类型,域名,值或服务器,TTL,优先级,权重,端口,服务,协议,启用"

    static let csvTemplate = """
    类型,域名,值或服务器,TTL,优先级,权重,端口,服务,协议,启用,备注
    # NS,example.com,192.168.1.10,,,,,,,TRUE,转发域名（NS 也可写 FORWARD_DOMAIN）
    # A,host.example.com,192.0.2.10,0,,,,,,TRUE,IPv4；TTL 0 表示自动
    # AAAA,host.example.com,2001:db8::10,3600,,,,,,TRUE,IPv6
    # CNAME,www.example.com,target.example.com,300,,,,,,TRUE,别名
    # MX,example.com,mail.example.com,,10,,,,,TRUE,邮件服务器
    # TXT,_dmarc.example.com,"v=DMARC1; p=none",,,,,,,TRUE,文本中需要逗号时请用双引号包裹整格
    # SRV,example.com,sip.example.com,,10,5,5060,_sip,_tcp,TRUE,SRV 域名不含服务和协议前缀
    """

    private static let headerAliases: [String: String] = {
        var result: [String: String] = [:]
        func add(_ canonical: String, _ names: [String]) {
            for name in names { result[normalizeHeader(name)] = canonical }
        }
        add("type", ["类型", "记录类型", "record type", "record_type", "type"])
        add("domain", ["域名", "转发域名", "新增域名", "domain", "domains", "hostname", "host", "name"])
        add("value", ["值", "值或服务器", "DNS服务器", "DNS 服务器", "服务器", "value", "server", "target", "ipaddress", "ip address"])
        add("ttl", ["ttl", "ttl秒", "ttl seconds"])
        add("priority", ["优先级", "priority"])
        add("weight", ["权重", "weight"])
        add("port", ["端口", "port"])
        add("service", ["服务", "service"])
        add("protocol", ["协议", "protocol"])
        add("enabled", ["启用", "状态", "enabled", "enable"])
        return result
    }()

    static func importFile(_ url: URL, defaultDNSServer: String) throws -> DNSImportResult {
        switch url.pathExtension.lowercased() {
        case "xlsx": return try parseRows(readXLSXRows(url), defaultDNSServer: defaultDNSServer)
        case "csv": return try parseRows(parseDelimitedText(readText(url)), defaultDNSServer: defaultDNSServer)
        case "txt", "list", "": return try parseText(readText(url), defaultDNSServer: defaultDNSServer)
        default: throw UniFiError.api("仅支持 TXT、CSV 和 XLSX 文件。")
        }
    }

    static func loadBundled(defaultDNSServer: String) throws -> DNSImportResult {
        guard let url = Bundle.main.url(forResource: "unifi-forward-domains-by-service", withExtension: "csv") else {
            throw UniFiError.api("应用内置的 212 条转发域规则不存在，请重新下载完整应用包。")
        }
        return try parseRows(parseDelimitedText(readText(url)), defaultDNSServer: defaultDNSServer)
    }

    static func parseText(_ text: String, defaultDNSServer: String) throws -> DNSImportResult {
        let rows = parseDelimitedText(text)
        if findHeader(rows) != nil { return try parseRows(rows, defaultDNSServer: defaultDNSServer) }
        return extractForwardDomains(text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n"), defaultDNSServer: defaultDNSServer)
    }

    static func formatRecords(_ records: [DNSRecord]) -> String {
        var lines = [editorHeader]
        for source in records {
            guard let record = try? UniFiPayloadValidator.normalizeDNS(source) else { continue }
            let domain = record.recordType == "SRV" ? record.domain : record.key
            let value = record.recordType == "TXT" ? record.value.replacingOccurrences(of: "\n", with: "\\n") : record.value
            let cells = [
                record.recordType, domain, value,
                ["A", "AAAA", "CNAME"].contains(record.recordType) ? String(record.ttl ?? 0) : "",
                ["MX", "SRV"].contains(record.recordType) ? String(record.priority ?? 0) : "",
                record.recordType == "SRV" ? String(record.weight ?? 0) : "",
                record.recordType == "SRV" ? String(record.port ?? 0) : "",
                record.recordType == "SRV" ? record.service : "",
                record.recordType == "SRV" ? record.protocolName : "",
                record.enabled ? "TRUE" : "FALSE"
            ]
            lines.append(cells.map(escapeCSV).joined(separator: ","))
        }
        return lines.joined(separator: "\n")
    }

    static func identity(_ source: DNSRecord) -> String {
        let type = source.recordType.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let key = source.key.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let value = source.value.trimmingCharacters(in: .whitespacesAndNewlines)
        let fields: [String]
        switch type {
        case "NS", "CNAME": fields = [type, key]
        case "A", "AAAA": fields = [type, key, value.lowercased()]
        case "TXT": fields = [type, key, source.value]
        case "MX": fields = [type, key, value.lowercased(), String(source.priority ?? 0)]
        case "SRV": fields = [type, key, value.lowercased(), String(source.port ?? 0), String(source.priority ?? 0), String(source.weight ?? 0)]
        default: fields = [type, key, value.lowercased()]
        }
        return fields.joined(separator: "\u{001f}")
    }

    static func describe(_ source: DNSRecord) -> String {
        guard let record = try? UniFiPayloadValidator.normalizeDNS(source) else { return "\(source.recordType) | \(source.key)" }
        let extra: String
        switch record.recordType {
        case "A", "AAAA", "CNAME": extra = " · TTL \(record.ttl ?? 0)"
        case "MX": extra = " · 优先级 \(record.priority ?? 0)"
        case "SRV": extra = " · 端口 \(record.port ?? 0) · 优先级 \(record.priority ?? 0) · 权重 \(record.weight ?? 0)"
        default: extra = ""
        }
        return "\(record.typeLabel) | \(record.key) → \(record.value)\(extra)"
    }

    private static func parseRows(_ rows: [[String]], defaultDNSServer: String) throws -> DNSImportResult {
        guard let header = findHeader(rows) else {
            return extractForwardDomains(selectDomainColumn(rows), defaultDNSServer: defaultDNSServer)
        }
        var records: [DNSRecord] = []
        var duplicateInput: [String] = []
        var invalid: [String] = []
        var seen = Set<String>()
        for rowIndex in (header.row + 1)..<rows.count {
            let row = rows[rowIndex]
            let first = row.first(where: { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty })?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if first.isEmpty || first.hasPrefix("#") { continue }
            do {
                let type = try parseRecordType(cell(row, header.columns, "type"))
                var domain = cell(row, header.columns, "domain")
                var value = cell(row, header.columns, "value")
                if type == "NS", value.isEmpty { value = defaultDNSServer }
                var record = DNSRecord(
                    recordType: type, value: type == "TXT" ? normalizeImportedTXT(value) : value,
                    enabled: try parseEnabled(cell(row, header.columns, "enabled")),
                    ttl: try optionalInt(cell(row, header.columns, "ttl"), label: "TTL"),
                    priority: try optionalInt(cell(row, header.columns, "priority"), label: "优先级"),
                    weight: try optionalInt(cell(row, header.columns, "weight"), label: "权重"),
                    port: try optionalInt(cell(row, header.columns, "port"), label: "端口")
                )
                if type == "SRV" {
                    var service = cell(row, header.columns, "service")
                    var protocolName = cell(row, header.columns, "protocol")
                    let parts = domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".").map(String.init)
                    if (service.isEmpty || protocolName.isEmpty), parts.count >= 3, parts[0].hasPrefix("_"), parts[1].hasPrefix("_") {
                        service = parts[0]
                        protocolName = parts[1]
                        domain = parts.dropFirst(2).joined(separator: ".")
                    }
                    guard !service.isEmpty, !protocolName.isEmpty else {
                        throw UniFiError.api("SRV 必须填写服务和协议，或将域名写成 _服务._协议.example.com。")
                    }
                    record.domain = domain
                    record.service = service
                    record.protocolName = protocolName
                } else {
                    record.key = domain
                }
                record = try UniFiPayloadValidator.normalizeDNS(record)
                let key = identity(record)
                if seen.insert(key).inserted { records.append(record) } else { duplicateInput.append(describe(record)) }
            } catch {
                invalid.append("第 \(rowIndex + 1) 行：\(error.localizedDescription)")
            }
        }
        return DNSImportResult(records: records, duplicateInput: duplicateInput, invalid: invalid)
    }

    private static func extractForwardDomains(_ values: [String], defaultDNSServer: String) -> DNSImportResult {
        var records: [DNSRecord] = []
        var duplicateInput: [String] = []
        var invalid: [String] = []
        var seen = Set<String>()
        let headers = Set(["domain", "domains", "域名", "转发域名", "新增域名", "hostname", "host"])
        for (offset, rawValue) in values.enumerated() {
            var raw = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if raw.isEmpty || headers.contains(raw.lowercased()) || raw.hasPrefix("#") { continue }
            if let comment = raw.range(of: #"\s+#"#, options: .regularExpression) { raw = String(raw[..<comment.lowerBound]).trimmingCharacters(in: .whitespaces) }
            var candidates = [raw]
            if let url = URL(string: raw), let scheme = url.scheme, !scheme.isEmpty, let host = url.host { candidates = [host] }
            else if raw.contains(",") || raw.contains(";") || raw.contains("\t") {
                candidates = raw.components(separatedBy: CharacterSet(charactersIn: ",;\t")).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            }
            for candidate in candidates {
                do {
                    let record = try UniFiPayloadValidator.normalizeDNS(DNSRecord(recordType: "NS", key: candidate, value: defaultDNSServer))
                    let key = identity(record)
                    if seen.insert(key).inserted { records.append(record) } else { duplicateInput.append(describe(record)) }
                } catch {
                    if Double(candidate) == nil { invalid.append("第 \(offset + 1) 行：\(candidate) — \(error.localizedDescription)") }
                }
            }
        }
        return DNSImportResult(records: records, duplicateInput: duplicateInput, invalid: invalid)
    }

    private static func findHeader(_ rows: [[String]]) -> (row: Int, columns: [String: Int])? {
        for rowIndex in 0..<min(rows.count, 25) {
            var found: [String: Int] = [:]
            for (columnIndex, value) in rows[rowIndex].enumerated() {
                if let canonical = headerAliases[normalizeHeader(value)], found[canonical] == nil { found[canonical] = columnIndex }
            }
            if found["domain"] != nil { return (rowIndex, found) }
        }
        return nil
    }

    private static func selectDomainColumn(_ rows: [[String]]) -> [String] {
        let width = rows.map(\.count).max() ?? 0
        var best: [String] = []
        var bestScore = 0
        for column in 0..<width {
            let values = rows.compactMap { column < $0.count ? $0[column].trimmingCharacters(in: .whitespacesAndNewlines) : nil }.filter { !$0.isEmpty }
            let score = values.filter { (try? UniFiPayloadValidator.normalizeDNS(DNSRecord(recordType: "NS", key: $0, value: "192.0.2.1"))) != nil }.count
            if score > bestScore { bestScore = score; best = values }
        }
        return bestScore > 0 ? best : []
    }

    private static func parseDelimitedText(_ text: String) -> [[String]] {
        let firstLine = text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n").first(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) ?? ""
        let delimiter: Character = firstLine.contains("\t") && !firstLine.contains(",") ? "\t" : ","
        var rows: [[String]] = []
        var row: [String] = []
        var value = ""
        var quoted = false
        let characters = Array(text)
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if character == "\"" {
                if quoted, index + 1 < characters.count, characters[index + 1] == "\"" { value.append("\""); index += 1 }
                else { quoted.toggle() }
            } else if character == delimiter, !quoted {
                row.append(value.trimmingCharacters(in: .whitespacesAndNewlines)); value = ""
            } else if (character == "\r" || character == "\n"), !quoted {
                if character == "\r", index + 1 < characters.count, characters[index + 1] == "\n" { index += 1 }
                row.append(value.trimmingCharacters(in: .whitespacesAndNewlines)); value = ""; rows.append(row); row = []
            } else { value.append(character) }
            index += 1
        }
        if !value.isEmpty || !row.isEmpty { row.append(value.trimmingCharacters(in: .whitespacesAndNewlines)); rows.append(row) }
        return rows
    }

    private static func readXLSXRows(_ url: URL) throws -> [[String]] {
        let listing = try runUnzip(["-Z1", url.path])
        let entries = String(decoding: listing, as: UTF8.self).components(separatedBy: .newlines)
        var sharedStrings: [String] = []
        if entries.contains("xl/sharedStrings.xml") {
            let document = try XMLDocument(data: runUnzip(["-p", url.path, "xl/sharedStrings.xml"]))
            sharedStrings = try document.nodes(forXPath: "//*[local-name()='si']").map { node in
                try node.nodes(forXPath: ".//*[local-name()='t']").compactMap(\.stringValue).joined()
            }
        }
        let sheets = entries.filter { $0.range(of: #"^xl/worksheets/sheet\d+\.xml$"#, options: .regularExpression) != nil }.sorted()
        for sheet in sheets {
            let document = try XMLDocument(data: runUnzip(["-p", url.path, sheet]))
            var rows: [Int: [Int: String]] = [:]
            for node in try document.nodes(forXPath: "//*[local-name()='c']") {
                guard let cell = node as? XMLElement,
                      let reference = cell.attribute(forName: "r")?.stringValue,
                      let match = reference.firstMatch(of: /^([A-Za-z]+)(\d+)$/),
                      let rowNumber = Int(match.2) else { continue }
                let columnNumber = columnIndex(String(match.1))
                let type = cell.attribute(forName: "t")?.stringValue
                var value = ""
                if type == "inlineStr" {
                    value = try cell.nodes(forXPath: ".//*[local-name()='t']").compactMap(\.stringValue).joined()
                } else if let raw = try cell.nodes(forXPath: ".//*[local-name()='v']").first?.stringValue {
                    value = raw
                    if type == "s", let sharedIndex = Int(raw), sharedStrings.indices.contains(sharedIndex) { value = sharedStrings[sharedIndex] }
                    else if type == "b" { value = raw == "1" ? "TRUE" : "FALSE" }
                }
                value = value.trimmingCharacters(in: .whitespacesAndNewlines)
                if !value.isEmpty { rows[rowNumber, default: [:]][columnNumber] = value }
            }
            let matrix = rows.keys.sorted().map { rowNumber -> [String] in
                let row = rows[rowNumber] ?? [:]
                var values = Array(repeating: "", count: (row.keys.max() ?? -1) + 1)
                for (column, value) in row { values[column] = value }
                return values
            }
            if findHeader(matrix) != nil || !selectDomainColumn(matrix).isEmpty { return matrix }
        }
        throw UniFiError.api("XLSX 中没有找到可识别的 DNS 规则表。")
    }

    private static func runUnzip(_ arguments: [String]) throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = arguments
        let output = Pipe()
        let error = Pipe()
        process.standardOutput = output
        process.standardError = error
        try process.run()
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let message = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw UniFiError.api("无法读取 XLSX：\(message.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        return data
    }

    private static func readText(_ url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        if let value = String(data: data, encoding: .utf8) { return value.replacingOccurrences(of: "\u{feff}", with: "") }
        if let value = String(data: data, encoding: .utf16) { return value }
        if let value = String(data: data, encoding: .isoLatin1) { return value }
        throw UniFiError.api("无法识别文件编码，请保存为 UTF-8 后重试。")
    }

    private static func normalizeHeader(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().replacingOccurrences(of: #"[\s_\-()/]+"#, with: "", options: .regularExpression)
    }

    private static func cell(_ row: [String], _ columns: [String: Int], _ name: String) -> String {
        guard let index = columns[name], row.indices.contains(index) else { return "" }
        return row[index].trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func optionalInt(_ value: String, label: String) throws -> Int? {
        if value.isEmpty { return nil }
        guard let result = Int(value) else { throw UniFiError.api("\(label)必须是整数。") }
        return result
    }

    private static func parseEnabled(_ value: String) throws -> Bool {
        if value.isEmpty { return true }
        switch value.lowercased() {
        case "true", "1", "yes", "y", "是", "启用", "enabled": return true
        case "false", "0", "no", "n", "否", "停用", "disabled": return false
        default: throw UniFiError.api("启用列只接受 TRUE/FALSE、1/0、是/否或启用/停用。")
        }
    }

    private static func parseRecordType(_ value: String) throws -> String {
        let normalized = value.uppercased().replacingOccurrences(of: #"[-\s_()/]+"#, with: "", options: .regularExpression)
        switch normalized {
        case "", "NS", "FORWARDDOMAIN", "转发域名", "转发域": return "NS"
        case "A", "ARECORD", "主机A": return "A"
        case "AAAA", "AAAARECORD", "主机AAAA": return "AAAA"
        case "CNAME", "CNAMERECORD", "别名": return "CNAME"
        case "MX", "MXRECORD", "邮件": return "MX"
        case "TXT", "TXTRECORD", "文本": return "TXT"
        case "SRV", "SRVRECORD", "服务": return "SRV"
        default: throw UniFiError.api("不支持的 DNS 记录类型：\(value)")
        }
    }

    private static func normalizeImportedTXT(_ value: String) -> String {
        value.replacingOccurrences(of: "\\n", with: "\n")
    }

    private static func escapeCSV(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r") else { return value }
        return "\"\(value.replacingOccurrences(of: "\"", with: "\"\""))\""
    }

    private static func columnIndex(_ letters: String) -> Int {
        letters.uppercased().unicodeScalars.reduce(0) { $0 * 26 + Int($1.value - 64) } - 1
    }
}
