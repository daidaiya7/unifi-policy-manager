using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

public static class PolicyChangeExecutor
{
    public static async Task ExecuteItemAsync(IUniFiClient client, PolicyChangeItem item, CancellationToken cancellationToken = default)
    {
        if (item.Scope == PolicyChangeScope.Dns)
        {
            switch (item.Action)
            {
                case PolicyChangeAction.Add:
                    var createdDns = await client.CreateRecordAsync(item.DesiredDns ?? throw new ValidationException("缺少目标 DNS 记录。"), cancellationToken);
                    item.ActualId = createdDns?.Id;
                    break;
                case PolicyChangeAction.Update:
                    await client.UpdateRecordAsync(item.CurrentId ?? throw new UniFiApiException("DNS 记录 ID 缺失。"), item.DesiredDns ?? throw new ValidationException("缺少目标 DNS 记录。"), cancellationToken);
                    item.ActualId = item.CurrentId;
                    break;
                case PolicyChangeAction.Delete:
                    await client.DeleteRecordAsync(item.CurrentId ?? throw new UniFiApiException("DNS 记录 ID 缺失。"), cancellationToken);
                    item.ActualId = null;
                    break;
            }
            return;
        }

        var kind = item.Scope switch
        {
            PolicyChangeScope.Acl => OfficialPolicyKind.Acl,
            PolicyChangeScope.Firewall => OfficialPolicyKind.Firewall,
            _ => throw new ArgumentOutOfRangeException(nameof(item.Scope))
        };
        switch (item.Action)
        {
            case PolicyChangeAction.Add:
                var createdPolicy = await client.CreatePolicyAsync(kind, item.DesiredPolicyJson ?? throw new ValidationException("缺少目标策略 JSON。"), cancellationToken);
                item.ActualId = createdPolicy?.Id;
                break;
            case PolicyChangeAction.Update:
                await client.UpdatePolicyAsync(kind, item.CurrentId ?? throw new UniFiApiException("策略 ID 缺失。"), item.DesiredPolicyJson ?? throw new ValidationException("缺少目标策略 JSON。"), cancellationToken);
                item.ActualId = item.CurrentId;
                break;
            case PolicyChangeAction.Delete:
                await client.DeletePolicyAsync(kind, item.CurrentId ?? throw new UniFiApiException("策略 ID 缺失。"), cancellationToken);
                item.ActualId = null;
                break;
        }
    }

    public static async Task RestoreOrderingAsync(IUniFiClient client, PolicyChangePlan plan, CancellationToken cancellationToken = default)
    {
        var idMap = plan.Items
            .Where(item => (item.Scope is PolicyChangeScope.Acl or PolicyChangeScope.Firewall) &&
                           !string.IsNullOrWhiteSpace(item.DesiredSourceId) &&
                           !string.IsNullOrWhiteSpace(item.ActualId))
            .GroupBy(item => item.DesiredSourceId!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().ActualId!, StringComparer.OrdinalIgnoreCase);

        if (!plan.Items.Any(item => item.Scope == PolicyChangeScope.Acl && item.Action == PolicyChangeAction.Invalid) &&
            plan.Bundle.AclOrdering is { OrderedAclRuleIds.Count: > 0 } sourceAcl)
        {
            var current = await client.GetPolicyOrderingAsync(OfficialPolicyKind.Acl, cancellationToken);
            var target = MapOrder(sourceAcl.OrderedAclRuleIds, idMap);
            target.AddRange(current.OrderedAclRuleIds.Where(id => !target.Contains(id, StringComparer.OrdinalIgnoreCase)));
            await client.SetPolicyOrderingAsync(OfficialPolicyKind.Acl, new PolicyOrderingSnapshot
            {
                Kind = OfficialPolicyKind.Acl,
                OrderedAclRuleIds = target
            }, cancellationToken);
        }

        if (!plan.Items.Any(item => item.Scope == PolicyChangeScope.Firewall && item.Action == PolicyChangeAction.Invalid) &&
            plan.Bundle.FirewallOrdering is { } sourceFirewall &&
            (sourceFirewall.BeforeSystemDefined.Count > 0 || sourceFirewall.AfterSystemDefined.Count > 0))
        {
            var current = await client.GetPolicyOrderingAsync(OfficialPolicyKind.Firewall, cancellationToken);
            var before = MapOrder(sourceFirewall.BeforeSystemDefined, idMap);
            var after = MapOrder(sourceFirewall.AfterSystemDefined, idMap);
            var mapped = before.Concat(after).ToHashSet(StringComparer.OrdinalIgnoreCase);
            before.AddRange(current.BeforeSystemDefined.Where(id => mapped.Add(id)));
            after.AddRange(current.AfterSystemDefined.Where(id => mapped.Add(id)));
            await client.SetPolicyOrderingAsync(OfficialPolicyKind.Firewall, new PolicyOrderingSnapshot
            {
                Kind = OfficialPolicyKind.Firewall,
                BeforeSystemDefined = before,
                AfterSystemDefined = after
            }, cancellationToken);
        }
    }

    private static List<string> MapOrder(IEnumerable<string> sourceIds, IReadOnlyDictionary<string, string> idMap) =>
        sourceIds.Where(idMap.ContainsKey).Select(id => idMap[id]).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
