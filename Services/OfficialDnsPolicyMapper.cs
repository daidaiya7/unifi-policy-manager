using System.Text.Json;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

internal static class OfficialDnsPolicyMapper
{
    private static readonly IReadOnlyDictionary<string, string> UiToApiTypes = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["NS"] = "FORWARD_DOMAIN",
        ["A"] = "A_RECORD",
        ["AAAA"] = "AAAA_RECORD",
        ["CNAME"] = "CNAME_RECORD",
        ["MX"] = "MX_RECORD",
        ["TXT"] = "TXT_RECORD",
        ["SRV"] = "SRV_RECORD"
    };

    private static readonly IReadOnlyDictionary<string, string> ApiToUiTypes =
        UiToApiTypes.ToDictionary(item => item.Value, item => item.Key, StringComparer.Ordinal);

    public static Dictionary<string, object?> BuildPayload(DnsRecord input)
    {
        var record = DnsValidator.Normalize(input);
        if (!UiToApiTypes.TryGetValue(record.RecordType, out var apiType))
            throw new ValidationException("不支持的 DNS Policy 类型。");

        var payload = new Dictionary<string, object?>
        {
            ["type"] = apiType,
            ["enabled"] = record.Enabled,
            ["domain"] = record.RecordType == "SRV" ? record.Domain : record.Key
        };

        switch (record.RecordType)
        {
            case "NS":
                payload["ipAddress"] = record.Value;
                break;
            case "A":
                payload["ipv4Address"] = record.Value;
                payload["ttlSeconds"] = record.Ttl.GetValueOrDefault();
                break;
            case "AAAA":
                payload["ipv6Address"] = record.Value;
                payload["ttlSeconds"] = record.Ttl.GetValueOrDefault();
                break;
            case "CNAME":
                payload["targetDomain"] = record.Value;
                payload["ttlSeconds"] = record.Ttl.GetValueOrDefault();
                break;
            case "MX":
                payload["mailServerDomain"] = record.Value;
                payload["priority"] = record.Priority.GetValueOrDefault();
                break;
            case "TXT":
                payload["text"] = record.Value;
                break;
            case "SRV":
                payload["service"] = record.Service;
                payload["protocol"] = record.Protocol;
                payload["serverDomain"] = record.Value;
                payload["port"] = record.Port.GetValueOrDefault();
                payload["priority"] = record.Priority.GetValueOrDefault();
                payload["weight"] = record.Weight.GetValueOrDefault();
                break;
        }

        return payload;
    }

    public static DnsRecord Parse(JsonElement item)
    {
        var apiType = RequiredString(item, "type");
        if (!ApiToUiTypes.TryGetValue(apiType, out var recordType))
            throw new UniFiApiException($"控制器返回了程序尚不支持的 DNS Policy 类型：{apiType}");

        var record = new DnsRecord
        {
            Id = OptionalString(item, "id"),
            RecordType = recordType,
            Enabled = item.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.True,
            Key = OptionalString(item, "domain") ?? string.Empty
        };

        switch (recordType)
        {
            case "NS":
                record.Value = OptionalString(item, "ipAddress") ?? string.Empty;
                break;
            case "A":
                record.Value = OptionalString(item, "ipv4Address") ?? string.Empty;
                record.Ttl = OptionalInt(item, "ttlSeconds");
                break;
            case "AAAA":
                record.Value = OptionalString(item, "ipv6Address") ?? string.Empty;
                record.Ttl = OptionalInt(item, "ttlSeconds");
                break;
            case "CNAME":
                record.Value = OptionalString(item, "targetDomain") ?? string.Empty;
                record.Ttl = OptionalInt(item, "ttlSeconds");
                break;
            case "MX":
                record.Value = OptionalString(item, "mailServerDomain") ?? string.Empty;
                record.Priority = OptionalInt(item, "priority");
                break;
            case "TXT":
                record.Value = OptionalString(item, "text") ?? string.Empty;
                break;
            case "SRV":
                record.Domain = record.Key;
                record.Service = OptionalString(item, "service") ?? string.Empty;
                record.Protocol = OptionalString(item, "protocol") ?? string.Empty;
                record.Value = OptionalString(item, "serverDomain") ?? string.Empty;
                record.Port = OptionalInt(item, "port");
                record.Priority = OptionalInt(item, "priority");
                record.Weight = OptionalInt(item, "weight");
                record.Key = $"{record.Service}.{record.Protocol}.{record.Domain}";
                break;
        }

        return record;
    }

    private static string RequiredString(JsonElement element, string name) =>
        OptionalString(element, name) ?? throw new UniFiApiException($"UniFi 响应缺少字段：{name}");

    private static string? OptionalString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static int? OptionalInt(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.TryGetInt32(out var number) ? number : null;
}
