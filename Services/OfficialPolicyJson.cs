using System.Text.Json;
using System.Text.Json.Nodes;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

internal static class OfficialPolicyJson
{
    public static string CreateTemplate(OfficialPolicyKind kind, string variant = "IPV4") => kind switch
    {
        OfficialPolicyKind.Acl when variant == "MAC" => """
        {
          "type": "MAC",
          "name": "新建 MAC ACL",
          "description": "",
          "enabled": false,
          "action": "BLOCK",
          "networkIdFilter": "<NETWORK_UUID>"
        }
        """,
        OfficialPolicyKind.Acl => """
        {
          "type": "IPV4",
          "name": "新建 IPv4 ACL",
          "description": "",
          "enabled": false,
          "action": "BLOCK"
        }
        """,
        OfficialPolicyKind.Firewall => """
        {
          "name": "新建防火墙策略",
          "description": "",
          "enabled": false,
          "loggingEnabled": false,
          "action": {
            "type": "BLOCK"
          },
          "source": {
            "zoneId": "<SOURCE_ZONE_UUID>"
          },
          "destination": {
            "zoneId": "<DESTINATION_ZONE_UUID>"
          },
          "ipProtocolScope": {
            "ipVersion": "IPV4"
          }
        }
        """,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    public static string NormalizeAndValidate(OfficialPolicyKind kind, string json)
    {
        JsonObject root;
        try { root = JsonNode.Parse(json)?.AsObject() ?? throw new JsonException(); }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            throw new ValidationException("策略请求体必须是有效的 JSON 对象。");
        }

        RequireString(root, "name");
        RequireBoolean(root, "enabled");
        if (kind == OfficialPolicyKind.Acl)
        {
            var type = RequireString(root, "type");
            if (type is not ("IPV4" or "MAC")) throw new ValidationException("ACL type 必须是 IPV4 或 MAC。");
            var action = RequireString(root, "action");
            if (action is not ("ALLOW" or "BLOCK")) throw new ValidationException("ACL action 必须是 ALLOW 或 BLOCK。");
            if (type == "MAC") RequireUuid(root, "networkIdFilter");
        }
        else
        {
            RequireBoolean(root, "loggingEnabled");
            RequireObject(root, "action");
            RequireObject(root, "source");
            RequireObject(root, "destination");
            RequireObject(root, "ipProtocolScope");
            RequireUuid(root["source"]!.AsObject(), "zoneId");
            RequireUuid(root["destination"]!.AsObject(), "zoneId");
            var action = RequireString(root["action"]!.AsObject(), "type");
            if (action is not ("ALLOW" or "BLOCK" or "REJECT"))
                throw new ValidationException("防火墙 action.type 必须是 ALLOW、BLOCK 或 REJECT。");
            var ipVersion = RequireString(root["ipProtocolScope"]!.AsObject(), "ipVersion");
            if (ipVersion is not ("IPV4" or "IPV6" or "IPV4_AND_IPV6"))
                throw new ValidationException("ipProtocolScope.ipVersion 不正确。");
            if (action == "ALLOW" && root["action"]!["allowReturnTraffic"] is null)
                root["action"]!["allowReturnTraffic"] = false;
        }

        root.Remove("id");
        root.Remove("index");
        root.Remove("metadata");
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public static string WithEnabled(OfficialPolicyKind kind, string json, bool enabled)
    {
        var root = JsonNode.Parse(json)?.AsObject() ?? throw new ValidationException("策略 JSON 无效。");
        root["enabled"] = enabled;
        return NormalizeAndValidate(kind, root.ToJsonString());
    }

    private static JsonObject RequireObject(JsonObject root, string name) =>
        root[name] is JsonObject value ? value : throw new ValidationException($"缺少 JSON 对象字段：{name}");

    private static string RequireString(JsonObject root, string name) =>
        root[name] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)
            ? text
            : throw new ValidationException($"缺少字符串字段：{name}");

    private static void RequireBoolean(JsonObject root, string name)
    {
        if (root[name] is not JsonValue value || !value.TryGetValue<bool>(out _))
            throw new ValidationException($"缺少布尔字段：{name}");
    }

    private static void RequireUuid(JsonObject root, string name)
    {
        var value = RequireString(root, name);
        if (!Guid.TryParse(value, out _)) throw new ValidationException($"{name} 必须是有效的 UUID。");
    }
}
