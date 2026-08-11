using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

public sealed class ValidationException(string message) : Exception(message);

public static partial class DnsValidator
{
    [GeneratedRegex("^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", RegexOptions.IgnoreCase)]
    private static partial Regex OwnerLabelRegex();

    [GeneratedRegex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.IgnoreCase)]
    private static partial Regex HostLabelRegex();

    [GeneratedRegex("^_[a-z0-9][a-z0-9-]{0,61}$", RegexOptions.IgnoreCase)]
    private static partial Regex ServiceRegex();

    public static DnsRecord Normalize(DnsRecord input)
    {
        var type = (input.RecordType ?? string.Empty).Trim().ToUpperInvariant();
        if (!DnsTypes.All.Contains(type))
            throw new ValidationException("不支持的 DNS 记录类型。");

        var result = new DnsRecord
        {
            Id = input.Id,
            RecordType = type,
            Enabled = input.Enabled
        };

        if (type == "SRV" && !string.IsNullOrWhiteSpace(input.Domain))
        {
            var service = NormalizeService(input.Service, "服务", "_ldap");
            var protocol = NormalizeService(input.Protocol, "协议", "_tcp");
            result.Domain = NormalizeDomain(input.Domain, true);
            result.Service = service;
            result.Protocol = protocol;
            result.Key = $"{service}.{protocol}.{result.Domain}";
        }
        else
        {
            result.Key = NormalizeDomain(input.Key, true);
        }

        switch (type)
        {
            case "A":
                if (!IPAddress.TryParse(input.Value?.Trim(), out var ipv4) || ipv4.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                    throw new ValidationException("请输入有效的 IPv4 地址。");
                result.Value = ipv4.ToString();
                result.Ttl = Range(input.Ttl ?? 0, "TTL", 0, 86400);
                break;
            case "AAAA":
                if (!IPAddress.TryParse(input.Value?.Trim(), out var ipv6) || ipv6.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
                    throw new ValidationException("请输入有效的 IPv6 地址。");
                result.Value = ipv6.ToString();
                result.Ttl = Range(input.Ttl ?? 0, "TTL", 0, 86400);
                break;
            case "NS":
                result.Key = NormalizeDomain(input.Key, false);
                if (!IPAddress.TryParse(input.Value?.Trim(), out var dnsServer))
                    throw new ValidationException("请输入有效的 IPv4 或 IPv6 DNS 服务器地址。");
                result.Value = dnsServer.ToString();
                break;
            case "CNAME":
                result.Value = NormalizeDomain(input.Value, false);
                result.Ttl = Range(input.Ttl ?? 0, "TTL", 0, 604800);
                break;
            case "MX":
                result.Value = NormalizeDomain(input.Value, false);
                result.Priority = Range(input.Priority ?? 0, "优先级", 0, 65535);
                break;
            case "TXT":
                result.Value = input.Value ?? string.Empty;
                if (result.Value.Length == 0) throw new ValidationException("TXT 文本不能为空。");
                if (result.Value.Length > 1024) throw new ValidationException("TXT 文本总长度不能超过 1024 个字符。");
                var txtParts = result.Value.Replace("\r\n", "\n").Split('\n');
                if (txtParts.Length > 4) throw new ValidationException("TXT 最多包含 4 段文本。");
                if (txtParts.Any(line => line.Length > 255))
                    throw new ValidationException("TXT 每行不能超过 255 个字符。");
                if (txtParts.Any(line => line.Contains(',') && !(line.StartsWith('"') && line.EndsWith('"'))))
                    throw new ValidationException("TXT 中包含逗号的行必须使用双引号包裹。");
                break;
            case "SRV":
                result.Value = NormalizeDomain(input.Value, false);
                result.Port = Range(input.Port ?? 0, "端口", 0, 65535);
                result.Priority = Range(input.Priority ?? 0, "优先级", 0, 65535);
                result.Weight = Range(input.Weight ?? 0, "权重", 0, 65535);
                break;
        }
        return result;
    }

    public static string NormalizeForwardDomain(string value) => NormalizeDomain(value, false);

    public static string NormalizeDomain(string? value, bool owner)
    {
        var text = (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
        if (text.Length == 0) throw new ValidationException("域名不能为空。");
        var labels = text.Split('.');
        var idn = new IdnMapping();
        var output = new List<string>(labels.Length);
        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63) throw new ValidationException("域名标签不能为空且不能超过 63 个字符。");
            string ascii;
            try { ascii = idn.GetAscii(label); }
            catch (ArgumentException) { throw new ValidationException("域名包含无法转换的字符。"); }
            var regex = owner ? OwnerLabelRegex() : HostLabelRegex();
            if (!regex.IsMatch(ascii)) throw new ValidationException("域名标签格式不正确。");
            output.Add(ascii.ToLowerInvariant());
        }
        var normalized = string.Join('.', output);
        if (normalized.Length > 127) throw new ValidationException("UniFi DNS Policy 的域名不能超过 127 个字符。");
        return normalized;
    }

    private static string NormalizeService(string? value, string label, string example)
    {
        var text = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (!text.StartsWith('_')) text = "_" + text;
        if (!ServiceRegex().IsMatch(text)) throw new ValidationException($"{label}格式应类似 {example}。");
        return text;
    }

    private static int Range(int value, string label, int minimum, int maximum)
    {
        if (value < minimum || value > maximum)
            throw new ValidationException($"{label}必须在 {minimum} 到 {maximum} 之间。");
        return value;
    }
}
