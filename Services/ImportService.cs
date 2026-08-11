using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

public static partial class ImportService
{
    private const string EditorHeader = "类型,域名,值或服务器,TTL,优先级,权重,端口,服务,协议,启用";

    private static readonly IReadOnlyDictionary<string, string> HeaderAliases = BuildHeaderAliases();

    [GeneratedRegex("^[a-z][a-z0-9+.-]*://", RegexOptions.IgnoreCase)]
    private static partial Regex UrlRegex();

    public static void SaveDnsRulesCsvTemplate(string path)
    {
        const string template =
            "类型,域名,值或服务器,TTL,优先级,权重,端口,服务,协议,启用,备注\r\n" +
            "# NS,example.com,192.168.1.10,,,,,,,TRUE,转发域名（NS 也可写 FORWARD_DOMAIN）\r\n" +
            "# A,host.example.com,192.0.2.10,0,,,,,,TRUE,IPv4；TTL 0 表示自动\r\n" +
            "# AAAA,host.example.com,2001:db8::10,3600,,,,,,TRUE,IPv6\r\n" +
            "# CNAME,www.example.com,target.example.com,300,,,,,,TRUE,别名\r\n" +
            "# MX,example.com,mail.example.com,,10,,,,,TRUE,邮件服务器\r\n" +
            "# TXT,_dmarc.example.com,v=DMARC1; p=none,,,,,,,TRUE,文本中需要逗号时请用双引号包裹整格\r\n" +
            "# SRV,example.com,sip.example.com,,10,5,5060,_sip,_tcp,TRUE,SRV 域名不含服务和协议前缀\r\n";
        File.WriteAllText(path, template, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
    }

    public static void SaveForwardDomainCsvTemplate(string path) => SaveDnsRulesCsvTemplate(path);

    public static ImportResult ImportFile(string path, string defaultDnsServer = "192.168.1.10")
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension switch
        {
            ".xlsx" => ParseRows(ReadXlsxRows(path), defaultDnsServer),
            ".csv" => ParseRows(ParseDelimitedText(File.ReadAllText(path, DetectEncoding(path))), defaultDnsServer),
            ".txt" or ".list" or "" => ParseText(File.ReadAllText(path, DetectEncoding(path)), defaultDnsServer),
            _ => throw new ValidationException("仅支持 TXT、CSV 和 XLSX 文件。")
        };
    }

    public static ImportResult ParseText(string text, string defaultDnsServer = "192.168.1.10")
    {
        var rows = ParseDelimitedText(text);
        if (TryFindHeader(rows, out _, out _)) return ParseRows(rows, defaultDnsServer);
        return ExtractForwardDomains(text.Replace("\r\n", "\n").Split('\n'), defaultDnsServer);
    }

    public static ImportResult ExtractForwardDomains(IEnumerable<string> values, string defaultDnsServer = "192.168.1.10")
    {
        var records = new List<DnsRecord>();
        var duplicates = new List<string>();
        var invalid = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var headers = new HashSet<string>(["domain", "domains", "域名", "转发域名", "新增域名", "hostname", "host"], StringComparer.OrdinalIgnoreCase);
        var lineNumber = 0;
        foreach (var rawValue in values)
        {
            lineNumber++;
            var raw = (rawValue ?? string.Empty).Trim();
            if (raw.Length == 0 || headers.Contains(raw) || raw.StartsWith('#')) continue;
            raw = Regex.Replace(raw, "\\s+#.*$", string.Empty).Trim();
            var candidates = new List<string> { raw };
            if (UrlRegex().IsMatch(raw) && Uri.TryCreate(raw, UriKind.Absolute, out var uri))
                candidates = [uri.Host];
            else if (raw.IndexOfAny([',', ';', '\t']) >= 0)
                candidates = raw.Split([',', ';', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

            foreach (var candidate in candidates)
            {
                try
                {
                    var record = DnsValidator.Normalize(new DnsRecord
                    {
                        RecordType = "NS",
                        Key = candidate,
                        Value = defaultDnsServer,
                        Enabled = true
                    });
                    var identity = IdentityKey(record);
                    if (seen.Add(identity)) records.Add(record);
                    else duplicates.Add(Describe(record));
                }
                catch (ValidationException exception)
                {
                    if (candidate.Length > 0 && !double.TryParse(candidate, out _))
                        invalid.Add($"第 {lineNumber} 行：{candidate} — {exception.Message}");
                }
            }
        }
        return new ImportResult(records, duplicates, invalid);
    }

    public static string FormatRecordsForEditor(IEnumerable<DnsRecord> records)
    {
        var lines = new List<string> { EditorHeader };
        foreach (var source in records)
        {
            var record = DnsValidator.Normalize(source);
            var domain = record.RecordType == "SRV" ? record.Domain : record.Key;
            var value = record.RecordType == "TXT" ? record.Value.Replace("\r\n", "\\n").Replace("\n", "\\n") : record.Value;
            lines.Add(string.Join(',', new[]
            {
                record.RecordType,
                domain,
                value,
                DnsTypes.TtlTypes.Contains(record.RecordType) ? record.Ttl.GetValueOrDefault().ToString() : string.Empty,
                record.RecordType is "MX" or "SRV" ? record.Priority.GetValueOrDefault().ToString() : string.Empty,
                record.RecordType == "SRV" ? record.Weight.GetValueOrDefault().ToString() : string.Empty,
                record.RecordType == "SRV" ? record.Port.GetValueOrDefault().ToString() : string.Empty,
                record.RecordType == "SRV" ? record.Service : string.Empty,
                record.RecordType == "SRV" ? record.Protocol : string.Empty,
                record.Enabled ? "TRUE" : "FALSE"
            }.Select(EscapeCsv)));
        }
        return string.Join(Environment.NewLine, lines);
    }

    public static string IdentityKey(DnsRecord source)
    {
        var record = source;
        var fields = record.RecordType switch
        {
            "NS" => new[] { record.RecordType, record.Key },
            "A" or "AAAA" or "TXT" => new[] { record.RecordType, record.Key, record.Value },
            "CNAME" => new[] { record.RecordType, record.Key },
            "MX" => new[] { record.RecordType, record.Key, record.Value, record.Priority.GetValueOrDefault().ToString() },
            "SRV" => new[]
            {
                record.RecordType, record.Key, record.Value,
                record.Port.GetValueOrDefault().ToString(),
                record.Priority.GetValueOrDefault().ToString(),
                record.Weight.GetValueOrDefault().ToString()
            },
            _ => new[] { record.RecordType, record.Key, record.Value }
        };
        return string.Join('\u001f', fields.Select(value => value.Trim().ToLowerInvariant()));
    }

    public static string Describe(DnsRecord source)
    {
        var record = DnsValidator.Normalize(source);
        var extra = record.RecordType switch
        {
            "A" or "AAAA" or "CNAME" => $" · TTL {record.Ttl.GetValueOrDefault()}",
            "MX" => $" · 优先级 {record.Priority.GetValueOrDefault()}",
            "SRV" => $" · 端口 {record.Port.GetValueOrDefault()} · 优先级 {record.Priority.GetValueOrDefault()} · 权重 {record.Weight.GetValueOrDefault()}",
            _ => string.Empty
        };
        return $"{record.TypeLabel} | {record.Key} → {record.Value}{extra}";
    }

    private static ImportResult ParseRows(IReadOnlyList<IReadOnlyList<string>> rows, string defaultDnsServer)
    {
        if (!TryFindHeader(rows, out var headerRow, out var columns))
        {
            var legacyValues = SelectDomainColumn(rows);
            return ExtractForwardDomains(legacyValues, defaultDnsServer);
        }

        var records = new List<DnsRecord>();
        var duplicates = new List<string>();
        var invalid = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var rowIndex = headerRow + 1; rowIndex < rows.Count; rowIndex++)
        {
            var row = rows[rowIndex];
            var first = row.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;
            if (first.Length == 0 || first.StartsWith('#')) continue;
            try
            {
                var type = ParseRecordType(Cell(row, columns, "type"));
                var domain = Cell(row, columns, "domain");
                var value = Cell(row, columns, "value");
                if (type == "NS" && string.IsNullOrWhiteSpace(value)) value = defaultDnsServer;

                var record = new DnsRecord
                {
                    RecordType = type,
                    Value = type == "TXT" ? NormalizeImportedTxt(value) : value,
                    Enabled = ParseEnabled(Cell(row, columns, "enabled")),
                    Ttl = ParseOptionalInt(Cell(row, columns, "ttl"), "TTL"),
                    Priority = ParseOptionalInt(Cell(row, columns, "priority"), "优先级"),
                    Weight = ParseOptionalInt(Cell(row, columns, "weight"), "权重"),
                    Port = ParseOptionalInt(Cell(row, columns, "port"), "端口")
                };

                if (type == "SRV")
                {
                    var service = Cell(row, columns, "service");
                    var protocol = Cell(row, columns, "protocol");
                    var parts = domain.Trim().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
                    if ((string.IsNullOrWhiteSpace(service) || string.IsNullOrWhiteSpace(protocol)) &&
                        parts.Length >= 3 && parts[0].StartsWith('_') && parts[1].StartsWith('_'))
                    {
                        service = parts[0];
                        protocol = parts[1];
                        domain = string.Join('.', parts.Skip(2));
                    }
                    if (string.IsNullOrWhiteSpace(service) || string.IsNullOrWhiteSpace(protocol))
                        throw new ValidationException("SRV 必须填写服务和协议，或将域名写成 _服务._协议.example.com。");
                    record.Domain = domain;
                    record.Service = service;
                    record.Protocol = protocol;
                }
                else record.Key = domain;

                record = DnsValidator.Normalize(record);
                var identity = IdentityKey(record);
                if (seen.Add(identity)) records.Add(record);
                else duplicates.Add(Describe(record));
            }
            catch (Exception exception) when (exception is ValidationException or FormatException)
            {
                invalid.Add($"第 {rowIndex + 1} 行：{exception.Message}");
            }
        }
        return new ImportResult(records, duplicates, invalid);
    }

    private static bool TryFindHeader(IReadOnlyList<IReadOnlyList<string>> rows, out int headerRow, out Dictionary<string, int> columns)
    {
        for (var rowIndex = 0; rowIndex < Math.Min(rows.Count, 25); rowIndex++)
        {
            var found = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (var columnIndex = 0; columnIndex < rows[rowIndex].Count; columnIndex++)
            {
                var normalized = NormalizeHeader(rows[rowIndex][columnIndex]);
                if (HeaderAliases.TryGetValue(normalized, out var canonical) && !found.ContainsKey(canonical))
                    found[canonical] = columnIndex;
            }
            if (found.ContainsKey("domain"))
            {
                headerRow = rowIndex;
                columns = found;
                return true;
            }
        }
        headerRow = -1;
        columns = [];
        return false;
    }

    internal static IReadOnlyList<string> SelectDomainColumn(IReadOnlyList<IReadOnlyList<string>> rows)
    {
        var width = rows.Count == 0 ? 0 : rows.Max(row => row.Count);
        IReadOnlyList<string> best = [];
        var bestScore = 0;
        for (var column = 0; column < width; column++)
        {
            var values = rows.Where(row => column < row.Count && !string.IsNullOrWhiteSpace(row[column]))
                .Select(row => row[column].Trim()).ToList();
            var score = values.Count(value =>
            {
                try { DnsValidator.NormalizeForwardDomain(value); return true; }
                catch (ValidationException) { return false; }
            });
            if (score > bestScore) { bestScore = score; best = values; }
        }
        return bestScore > 0 ? best : [];
    }

    private static IReadOnlyList<IReadOnlyList<string>> ReadXlsxRows(string path)
    {
        using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var archive = new ZipArchive(fileStream, ZipArchiveMode.Read, leaveOpen: false);
        var sharedStrings = new List<string>();
        var sharedEntry = archive.GetEntry("xl/sharedStrings.xml");
        if (sharedEntry is not null)
        {
            using var stream = sharedEntry.Open();
            var document = XDocument.Load(stream);
            sharedStrings.AddRange(document.Descendants().Where(element => element.Name.LocalName == "si")
                .Select(item => string.Concat(item.Descendants().Where(element => element.Name.LocalName == "t").Select(element => element.Value))));
        }

        var sheets = archive.Entries
            .Where(entry => Regex.IsMatch(entry.FullName, "^xl/worksheets/sheet\\d+\\.xml$", RegexOptions.IgnoreCase))
            .OrderBy(entry => SheetNumber(entry.FullName));
        foreach (var sheet in sheets)
        {
            using var sheetStream = sheet.Open();
            var sheetDocument = XDocument.Load(sheetStream);
            var rows = new SortedDictionary<int, SortedDictionary<int, string>>();
            foreach (var cell in sheetDocument.Descendants().Where(element => element.Name.LocalName == "c"))
            {
                var reference = cell.Attribute("r")?.Value ?? "A1";
                var match = Regex.Match(reference, "^([A-Z]+)(\\d+)$", RegexOptions.IgnoreCase);
                if (!match.Success) continue;
                var rowNumber = int.Parse(match.Groups[2].Value);
                var columnNumber = ColumnNumber(match.Groups[1].Value);
                var type = cell.Attribute("t")?.Value;
                string value;
                if (type == "inlineStr")
                    value = string.Concat(cell.Descendants().Where(element => element.Name.LocalName == "t").Select(element => element.Value));
                else
                {
                    var valueElement = cell.Descendants().FirstOrDefault(element => element.Name.LocalName == "v");
                    if (valueElement is null) continue;
                    value = valueElement.Value;
                    if (type == "s" && int.TryParse(value, out var sharedIndex) && sharedIndex >= 0 && sharedIndex < sharedStrings.Count)
                        value = sharedStrings[sharedIndex];
                    else if (type == "b") value = value == "1" ? "TRUE" : "FALSE";
                }
                value = value.Trim();
                if (value.Length == 0) continue;
                if (!rows.TryGetValue(rowNumber, out var row)) rows[rowNumber] = row = [];
                row[columnNumber] = value;
            }
            var matrix = rows.Values.Select(row =>
            {
                var width = row.Count == 0 ? 0 : row.Keys.Max() + 1;
                var values = Enumerable.Repeat(string.Empty, width).ToArray();
                foreach (var pair in row) values[pair.Key] = pair.Value;
                return (IReadOnlyList<string>)values;
            }).ToList();
            if (TryFindHeader(matrix, out _, out _) || SelectDomainColumn(matrix).Count > 0) return matrix;
        }
        return [];
    }

    private static IReadOnlyList<IReadOnlyList<string>> ParseDelimitedText(string text)
    {
        var firstLine = text.Replace("\r\n", "\n").Split('\n').FirstOrDefault(line => !string.IsNullOrWhiteSpace(line)) ?? string.Empty;
        var delimiter = firstLine.Contains('\t') && !firstLine.Contains(',') ? '\t' : ',';
        var rows = new List<IReadOnlyList<string>>();
        var row = new List<string>();
        var value = new StringBuilder();
        var quoted = false;
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (character == '"')
            {
                if (quoted && index + 1 < text.Length && text[index + 1] == '"') { value.Append('"'); index++; }
                else quoted = !quoted;
            }
            else if (character == delimiter && !quoted)
            {
                row.Add(value.ToString().Trim());
                value.Clear();
            }
            else if ((character == '\r' || character == '\n') && !quoted)
            {
                if (character == '\r' && index + 1 < text.Length && text[index + 1] == '\n') index++;
                row.Add(value.ToString().Trim());
                value.Clear();
                rows.Add(row);
                row = [];
            }
            else value.Append(character);
        }
        if (value.Length > 0 || row.Count > 0)
        {
            row.Add(value.ToString().Trim());
            rows.Add(row);
        }
        return rows;
    }

    private static string Cell(IReadOnlyList<string> row, IReadOnlyDictionary<string, int> columns, string name) =>
        columns.TryGetValue(name, out var index) && index < row.Count ? row[index].Trim() : string.Empty;

    private static int? ParseOptionalInt(string value, string label)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        return int.TryParse(value.Trim(), out var number) ? number : throw new FormatException($"{label}必须是整数。");
    }

    private static bool ParseEnabled(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;
        return value.Trim().ToLowerInvariant() switch
        {
            "true" or "1" or "yes" or "y" or "是" or "启用" or "enabled" => true,
            "false" or "0" or "no" or "n" or "否" or "停用" or "disabled" => false,
            _ => throw new ValidationException("启用列只接受 TRUE/FALSE、1/0、是/否或启用/停用。")
        };
    }

    private static string ParseRecordType(string value)
    {
        var normalized = Regex.Replace((value ?? string.Empty).Trim().ToUpperInvariant(), "[-\\s_()/]+", string.Empty);
        return normalized switch
        {
            "" or "NS" or "FORWARDDOMAIN" or "转发域名" or "转发域" => "NS",
            "A" or "ARECORD" or "主机A" => "A",
            "AAAA" or "AAAARECORD" or "主机AAAA" => "AAAA",
            "CNAME" or "CNAMERECORD" or "别名" => "CNAME",
            "MX" or "MXRECORD" or "邮件" => "MX",
            "TXT" or "TXTRECORD" or "文本" => "TXT",
            "SRV" or "SRVRECORD" or "服务" => "SRV",
            _ => throw new ValidationException($"不支持的 DNS 记录类型：{value}")
        };
    }

    private static string NormalizeImportedTxt(string value)
    {
        var lines = value.Replace("\\n", "\n", StringComparison.Ordinal).Replace("\r\n", "\n").Split('\n');
        return string.Join('\n', lines.Select(line =>
            line.Contains(',') && !(line.StartsWith('"') && line.EndsWith('"')) ? $"\"{line}\"" : line));
    }

    private static string EscapeCsv(string value)
    {
        if (value.IndexOfAny([',', '"', '\r', '\n']) < 0) return value;
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string NormalizeHeader(string value) =>
        Regex.Replace((value ?? string.Empty).Trim().ToLowerInvariant(), "[\\s_\\-/]+", string.Empty);

    private static IReadOnlyDictionary<string, string> BuildHeaderAliases()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        Add("type", "类型", "记录类型", "dnstype", "recordtype", "type");
        Add("domain", "域名", "转发域名", "新增域名", "srv域名", "domain", "domains", "hostname", "host", "name");
        Add("value", "值", "值或服务器", "服务器", "dns服务器", "目标", "目标值", "value", "target", "address", "ipaddress", "dnsserver");
        Add("ttl", "ttl", "ttl秒", "ttlseconds");
        Add("priority", "优先级", "priority");
        Add("weight", "权重", "weight");
        Add("port", "端口", "port");
        Add("service", "服务", "srv服务", "服务名", "service");
        Add("protocol", "协议", "protocol");
        Add("enabled", "启用", "是否启用", "状态", "enabled", "active");
        return result;

        void Add(string canonical, params string[] aliases)
        {
            foreach (var alias in aliases) result[NormalizeHeader(alias)] = canonical;
        }
    }

    private static Encoding DetectEncoding(string path)
    {
        Span<byte> bom = stackalloc byte[4];
        using var stream = File.OpenRead(path);
        var count = stream.Read(bom);
        if (count >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF) return new UTF8Encoding(true);
        if (count >= 2 && bom[0] == 0xFF && bom[1] == 0xFE) return Encoding.Unicode;
        if (count >= 2 && bom[0] == 0xFE && bom[1] == 0xFF) return Encoding.BigEndianUnicode;
        return new UTF8Encoding(false, true);
    }

    private static int ColumnNumber(string letters)
    {
        var result = 0;
        foreach (var character in letters.ToUpperInvariant()) result = result * 26 + character - 'A' + 1;
        return result - 1;
    }

    private static int SheetNumber(string name)
    {
        var match = Regex.Match(name, "sheet(\\d+)", RegexOptions.IgnoreCase);
        return match.Success ? int.Parse(match.Groups[1].Value) : int.MaxValue;
    }
}
