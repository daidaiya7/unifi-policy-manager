using System.Text.Json;
using System.Text.Json.Nodes;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

internal static class LocalSessionPolicyMapper
{
    public static Dictionary<string, object?> BuildDnsPayload(DnsRecord input, string? id = null)
    {
        var record = DnsValidator.Normalize(input);
        var payload = new Dictionary<string, object?>
        {
            ["enabled"] = record.Enabled,
            ["key"] = record.Key,
            ["record_type"] = record.RecordType,
            ["value"] = record.Value
        };
        if (!string.IsNullOrWhiteSpace(id)) payload["_id"] = id;
        switch (record.RecordType)
        {
            case "A":
            case "AAAA":
            case "CNAME":
                payload["ttl"] = record.Ttl.GetValueOrDefault();
                break;
            case "MX":
                payload["priority"] = record.Priority.GetValueOrDefault();
                break;
            case "SRV":
                payload["priority"] = record.Priority.GetValueOrDefault();
                payload["weight"] = record.Weight.GetValueOrDefault();
                payload["port"] = record.Port.GetValueOrDefault();
                break;
        }
        return payload;
    }

    public static DnsRecord ParseDns(JsonElement item)
    {
        var type = String(item, "record_type", "type").ToUpperInvariant();
        type = type switch
        {
            "FORWARD_DOMAIN" => "NS",
            "A_RECORD" => "A",
            "AAAA_RECORD" => "AAAA",
            "CNAME_RECORD" => "CNAME",
            "MX_RECORD" => "MX",
            "TXT_RECORD" => "TXT",
            "SRV_RECORD" => "SRV",
            _ => type
        };
        var record = new DnsRecord
        {
            Id = String(item, "id", "_id"),
            RecordType = type,
            Key = String(item, "key", "domain"),
            Value = String(item, "value"),
            Enabled = Bool(item, "enabled", defaultValue: true),
            Ttl = Int(item, "ttl", "ttlSeconds"),
            Priority = Int(item, "priority"),
            Weight = Int(item, "weight"),
            Port = Int(item, "port"),
            Service = String(item, "service"),
            Protocol = String(item, "protocol")
        };
        if (record.RecordType == "SRV")
        {
            record.Domain = String(item, "domain");
            if (string.IsNullOrWhiteSpace(record.Domain)) record.PopulateSrvParts();
        }
        return record;
    }

    public static OfficialPolicyRule ParsePolicy(OfficialPolicyKind kind, JsonElement item, int fallbackIndex)
    {
        var id = String(item, "id", "_id");
        var action = String(item, "action");
        if (item.TryGetProperty("action", out var actionObject) && actionObject.ValueKind == JsonValueKind.Object)
            action = String(actionObject, "type");
        var type = kind == OfficialPolicyKind.Acl
            ? String(item, "type", "ip_version")
            : NestedString(item, "ipProtocolScope", "ipVersion");
        if (string.IsNullOrWhiteSpace(type)) type = String(item, "ip_version");
        var origin = NestedString(item, "metadata", "origin");
        if (string.IsNullOrWhiteSpace(origin)) origin = Bool(item, "predefined") ? "SYSTEM_DEFINED" : "USER_DEFINED";

        var canonical = new JsonObject
        {
            ["id"] = id,
            ["index"] = Int(item, "index") ?? fallbackIndex,
            ["name"] = String(item, "name"),
            ["description"] = String(item, "description"),
            ["enabled"] = Bool(item, "enabled", defaultValue: true),
            ["metadata"] = new JsonObject { ["origin"] = origin }
        };
        if (kind == OfficialPolicyKind.Acl)
        {
            canonical["type"] = type;
            canonical["action"] = action;
        }
        else
        {
            canonical["ipProtocolScope"] = new JsonObject { ["ipVersion"] = type };
            canonical["action"] = new JsonObject { ["type"] = action };
        }
        using var document = JsonDocument.Parse(canonical.ToJsonString());
        return OfficialPolicyRule.Parse(kind, document.RootElement);
    }

    private static string String(JsonElement item, params string[] names)
    {
        foreach (var name in names)
            if (item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String) return value.GetString() ?? string.Empty;
        return string.Empty;
    }

    private static string NestedString(JsonElement item, string parent, string child) =>
        item.TryGetProperty(parent, out var value) && value.ValueKind == JsonValueKind.Object ? String(value, child) : string.Empty;

    private static int? Int(JsonElement item, params string[] names)
    {
        foreach (var name in names)
            if (item.TryGetProperty(name, out var value) && value.TryGetInt32(out var number)) return number;
        return null;
    }

    private static bool Bool(JsonElement item, string name, bool defaultValue = false)
    {
        if (!item.TryGetProperty(name, out var value)) return defaultValue;
        return value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.String && bool.TryParse(value.GetString(), out var parsed) && parsed;
    }
}
