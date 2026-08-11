using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace UniFiDnsManager.Models;

public enum PolicyChangeScope
{
    Dns,
    Acl,
    Firewall
}

public enum PolicyChangeAction
{
    Add,
    Update,
    Delete,
    Unchanged,
    Invalid
}

public sealed class PolicyChangeItem : INotifyPropertyChanged
{
    private bool _isSelected;
    private string _status = "待执行";

    public PolicyChangeScope Scope { get; init; }
    public PolicyChangeAction Action { get; init; }
    public string Name { get; init; } = string.Empty;
    public string Details { get; init; } = string.Empty;
    public string? CurrentId { get; init; }
    public string? DesiredSourceId { get; init; }
    public string? ActualId { get; set; }
    public int DesiredIndex { get; init; }
    public DnsRecord? DesiredDns { get; init; }
    public string? DesiredPolicyJson { get; init; }

    public bool IsActionable => Action is PolicyChangeAction.Add or PolicyChangeAction.Update or PolicyChangeAction.Delete;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (value && !IsActionable) return;
            if (_isSelected == value) return;
            _isSelected = value;
            OnPropertyChanged();
        }
    }

    public string Status
    {
        get => _status;
        set
        {
            if (_status == value) return;
            _status = value;
            OnPropertyChanged();
        }
    }

    public string ScopeLabel => Scope switch
    {
        PolicyChangeScope.Dns => "DNS",
        PolicyChangeScope.Acl => "ACL",
        PolicyChangeScope.Firewall => "防火墙",
        _ => Scope.ToString()
    };

    public string ActionLabel => Action switch
    {
        PolicyChangeAction.Add => "新增",
        PolicyChangeAction.Update => "更新",
        PolicyChangeAction.Delete => "删除",
        PolicyChangeAction.Unchanged => "不变",
        PolicyChangeAction.Invalid => "无效",
        _ => Action.ToString()
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class PolicyChangePlan
{
    public required PolicyBundle Bundle { get; init; }
    public required string SourcePath { get; init; }
    public required bool SynchronizeDeletes { get; init; }
    public List<PolicyChangeItem> Items { get; init; } = [];

    public int AddCount => Items.Count(item => item.Action == PolicyChangeAction.Add);
    public int UpdateCount => Items.Count(item => item.Action == PolicyChangeAction.Update);
    public int DeleteCount => Items.Count(item => item.Action == PolicyChangeAction.Delete);
    public int UnchangedCount => Items.Count(item => item.Action == PolicyChangeAction.Unchanged);
    public int InvalidCount => Items.Count(item => item.Action == PolicyChangeAction.Invalid);
    public int SelectedCount => Items.Count(item => item.IsActionable && item.IsSelected);
}

public sealed class PolicyBundle
{
    [JsonIgnore]
    public bool HasDnsSection { get; set; } = true;

    [JsonIgnore]
    public bool HasAclSection { get; set; } = true;

    [JsonIgnore]
    public bool HasFirewallSection { get; set; } = true;

    [JsonPropertyName("schema_version")]
    public int SchemaVersion { get; set; } = 2;

    [JsonPropertyName("created_at")]
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;

    [JsonPropertyName("target")]
    public string? Target { get; set; }

    [JsonPropertyName("site")]
    public string? Site { get; set; }

    [JsonPropertyName("site_id")]
    public string? SiteId { get; set; }

    [JsonPropertyName("network_version")]
    public string? NetworkVersion { get; set; }

    [JsonPropertyName("dns_records")]
    public List<DnsRecord> DnsRecords { get; set; } = [];

    [JsonPropertyName("acl_rules")]
    public List<JsonElement> AclRules { get; set; } = [];

    [JsonPropertyName("firewall_policies")]
    public List<JsonElement> FirewallPolicies { get; set; } = [];

    [JsonPropertyName("acl_ordering")]
    public PolicyOrderingSnapshot? AclOrdering { get; set; }

    [JsonPropertyName("firewall_ordering")]
    public PolicyOrderingSnapshot? FirewallOrdering { get; set; }
}

public sealed class PolicyOrderingSnapshot
{
    [JsonPropertyName("kind")]
    public OfficialPolicyKind Kind { get; set; }

    [JsonPropertyName("ordered_acl_rule_ids")]
    public List<string> OrderedAclRuleIds { get; set; } = [];

    [JsonPropertyName("before_system_defined")]
    public List<string> BeforeSystemDefined { get; set; } = [];

    [JsonPropertyName("after_system_defined")]
    public List<string> AfterSystemDefined { get; set; } = [];
}
