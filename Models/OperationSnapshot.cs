namespace UniFiDnsManager.Models;

public enum OperationKind
{
    Create,
    Update,
    Delete,
    BatchCreate,
    BatchDelete
}

public sealed class OperationSnapshot
{
    public required OperationKind Kind { get; init; }
    public string? RecordId { get; init; }
    public List<DnsRecord> Records { get; init; } = [];
}

public sealed record ImportResult(
    IReadOnlyList<DnsRecord> Records,
    IReadOnlyList<string> DuplicateInput,
    IReadOnlyList<string> Invalid)
{
    public IReadOnlyList<string> Domains => Records
        .Where(record => record.RecordType == "NS")
        .Select(record => record.Key)
        .ToList();
}

public sealed record BatchPreview(
    IReadOnlyList<DnsRecord> Pending,
    IReadOnlyList<DnsRecord> Existing,
    IReadOnlyList<string> DuplicateInput,
    IReadOnlyList<string> Invalid);
