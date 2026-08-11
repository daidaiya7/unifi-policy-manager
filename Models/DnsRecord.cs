using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;

namespace UniFiDnsManager.Models;

public sealed class DnsRecord : INotifyPropertyChanged
{
    private bool _isSelectedForBatch;

    [JsonPropertyName("_id")]
    public string? Id { get; set; }

    [JsonPropertyName("record_type")]
    public string RecordType { get; set; } = "NS";

    [JsonPropertyName("key")]
    public string Key { get; set; } = string.Empty;

    [JsonPropertyName("value")]
    public string Value { get; set; } = string.Empty;

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("ttl")]
    public int? Ttl { get; set; }

    [JsonPropertyName("priority")]
    public int? Priority { get; set; }

    [JsonPropertyName("weight")]
    public int? Weight { get; set; }

    [JsonPropertyName("port")]
    public int? Port { get; set; }

    [JsonPropertyName("service")]
    public string Service { get; set; } = string.Empty;

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = string.Empty;

    [JsonPropertyName("domain")]
    public string Domain { get; set; } = string.Empty;

    [JsonIgnore]
    public bool IsSelectedForBatch
    {
        get => _isSelectedForBatch;
        set
        {
            if (_isSelectedForBatch == value) return;
            _isSelectedForBatch = value;
            OnPropertyChanged();
        }
    }

    [JsonIgnore]
    public bool IsForwardDomain => RecordType == "NS";

    [JsonIgnore]
    public string TypeLabel => RecordType switch
    {
        "NS" => "转发域名",
        "A" => "A",
        "AAAA" => "AAAA",
        "CNAME" => "CNAME",
        "MX" => "MX",
        "TXT" => "TXT",
        "SRV" => "SRV",
        _ => RecordType
    };

    [JsonIgnore]
    public string StateLabel => Enabled ? "已启用" : "已停用";

    [JsonIgnore]
    public string ExtraLabel => RecordType switch
    {
        "A" or "AAAA" or "CNAME" => Ttl.GetValueOrDefault() > 0 ? $"TTL {Ttl} 秒" : "TTL 自动",
        "MX" => $"优先级 {Priority.GetValueOrDefault()}",
        "SRV" => $"端口 {Port} · 优先级 {Priority.GetValueOrDefault()} · 权重 {Weight.GetValueOrDefault()}",
        _ => "—"
    };

    public DnsRecord Clone() => new()
    {
        Id = Id,
        RecordType = RecordType,
        Key = Key,
        Value = Value,
        Enabled = Enabled,
        Ttl = Ttl,
        Priority = Priority,
        Weight = Weight,
        Port = Port,
        Service = Service,
        Protocol = Protocol,
        Domain = Domain,
        IsSelectedForBatch = IsSelectedForBatch
    };

    public void PopulateSrvParts()
    {
        if (RecordType != "SRV") return;
        var parts = Key.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3) return;
        Service = parts[0];
        Protocol = parts[1];
        Domain = string.Join('.', parts.Skip(2));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public static class DnsTypes
{
    public static readonly string[] All = ["NS", "A", "AAAA", "CNAME", "MX", "TXT", "SRV"];
    public static readonly HashSet<string> TtlTypes = ["A", "AAAA", "CNAME"];

    public static string Label(string type) => type switch
    {
        "NS" => "转发域名",
        "A" => "主机 (A)",
        "AAAA" => "主机 (AAAA)",
        "CNAME" => "别名 (CNAME)",
        "MX" => "邮件 (MX)",
        "TXT" => "文本 (TXT)",
        "SRV" => "服务 (SRV)",
        _ => type
    };
}
