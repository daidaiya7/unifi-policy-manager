using System.Text.Json;
using UniFiDnsManager.Models;

namespace UniFiDnsManager.Services;

public sealed class BackupService
{
    private readonly JsonSerializerOptions _options = new() { WriteIndented = true };
    public string RootDirectory { get; }
    public string BackupDirectory => Path.Combine(RootDirectory, "backups");

    public BackupService()
    {
        RootDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "UniFiPolicyManager");
        Directory.CreateDirectory(RootDirectory);
        Directory.CreateDirectory(BackupDirectory);
    }

    public async Task<string> SaveSnapshotAsync(string reason, IReadOnlyList<DnsRecord> records, CancellationToken cancellationToken = default)
    {
        var directory = BackupDirectory;
        var safeReason = string.Concat(reason.ToLowerInvariant().Select(character => char.IsLetterOrDigit(character) || character is '-' or '_' ? character : '-')).Trim('-');
        var path = Path.Combine(directory, $"{DateTime.Now:yyyyMMdd-HHmmss-fff}-{safeReason}.json");
        var envelope = new { created_at = DateTimeOffset.Now, reason, records };
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(envelope, _options), cancellationToken);
        return path;
    }

    public async Task<string> SaveObjectSnapshotAsync(string reason, object snapshot, CancellationToken cancellationToken = default)
    {
        var directory = BackupDirectory;
        var safeReason = string.Concat(reason.ToLowerInvariant().Select(character => char.IsLetterOrDigit(character) || character is '-' or '_' ? character : '-')).Trim('-');
        var path = Path.Combine(directory, $"{DateTime.Now:yyyyMMdd-HHmmss-fff}-{safeReason}.json");
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, _options), cancellationToken);
        return path;
    }

    public async Task ExportAsync(string path, IReadOnlyList<DnsRecord> records, CancellationToken cancellationToken = default)
    {
        var envelope = new { created_at = DateTimeOffset.Now, records };
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(envelope, _options), cancellationToken);
    }

    public async Task ExportObjectAsync(string path, object snapshot, CancellationToken cancellationToken = default) =>
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(snapshot, _options), cancellationToken);

    public async Task LogOperationAsync(object operation, CancellationToken cancellationToken = default)
    {
        var directory = Path.Combine(RootDirectory, "logs");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "operations.ndjson");
        var line = JsonSerializer.Serialize(new { at = DateTimeOffset.Now, operation });
        await File.AppendAllTextAsync(path, line + Environment.NewLine, cancellationToken);
    }
}
