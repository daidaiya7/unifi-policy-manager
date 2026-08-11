using System.Text.Json;
using System.Text.Json.Nodes;

namespace UniFiDnsManager.Models;

public enum OfficialPolicyKind
{
    Acl,
    Firewall
}

public sealed class OfficialPolicyRule
{
    public required OfficialPolicyKind Kind { get; init; }
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required bool Enabled { get; init; }
    public required int Index { get; init; }
    public required string Type { get; init; }
    public required string Action { get; init; }
    public required string Origin { get; init; }
    public required string Description { get; init; }
    public required string RawResponseJson { get; init; }

    public bool CanModify => string.Equals(Origin, "USER_DEFINED", StringComparison.OrdinalIgnoreCase);
    public string StateLabel => Enabled ? "已启用" : "已停用";
    public string OriginLabel => Origin switch
    {
        "USER_DEFINED" => "用户定义",
        "SYSTEM_DEFINED" => "系统定义",
        "DERIVED" => "派生",
        "ORCHESTRATED" => "编排",
        _ => Origin
    };

    public string ToEditableJson()
    {
        var node = JsonNode.Parse(RawResponseJson)?.AsObject()
            ?? throw new InvalidOperationException("策略响应不是 JSON 对象。");
        node.Remove("id");
        node.Remove("index");
        node.Remove("metadata");
        return node.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public static OfficialPolicyRule Parse(OfficialPolicyKind kind, JsonElement item)
    {
        var id = GetString(item, "id");
        var name = GetString(item, "name");
        var enabled = item.TryGetProperty("enabled", out var enabledElement) && enabledElement.ValueKind == JsonValueKind.True;
        var index = item.TryGetProperty("index", out var indexElement) && indexElement.TryGetInt32(out var value) ? value : 0;
        var type = kind == OfficialPolicyKind.Acl
            ? GetString(item, "type")
            : GetNestedString(item, "ipProtocolScope", "ipVersion");
        var action = kind == OfficialPolicyKind.Acl
            ? GetString(item, "action")
            : GetNestedString(item, "action", "type");
        var origin = GetNestedString(item, "metadata", "origin");
        var description = item.TryGetProperty("description", out var descriptionElement) && descriptionElement.ValueKind == JsonValueKind.String
            ? descriptionElement.GetString() ?? string.Empty
            : string.Empty;

        return new OfficialPolicyRule
        {
            Kind = kind,
            Id = id,
            Name = name,
            Enabled = enabled,
            Index = index,
            Type = type,
            Action = action,
            Origin = origin,
            Description = description,
            RawResponseJson = JsonSerializer.Serialize(item, new JsonSerializerOptions { WriteIndented = true })
        };
    }

    private static string GetString(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static string GetNestedString(JsonElement element, string parent, string child) =>
        element.TryGetProperty(parent, out var parentElement) && parentElement.ValueKind == JsonValueKind.Object
            ? GetString(parentElement, child)
            : string.Empty;
}

public sealed record PolicyReferenceItem(string Id, string Name, string Kind)
{
    public string DisplayName => $"{Name} · {Id}";
}
