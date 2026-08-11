using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace UniFiDnsManager.Services;

public sealed record ConnectionSettings(string Host, bool VerifyTls, bool RememberApiKey, string ApiKey);

public sealed class SecureSettingsService
{
    private static readonly byte[] OptionalEntropy = Encoding.UTF8.GetBytes("UniFi Policy Manager connection settings v1");
    private readonly string _settingsPath;

    public SecureSettingsService(string? settingsDirectory = null)
    {
        settingsDirectory ??= Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UniFiPolicyManager");
        _settingsPath = Path.Combine(settingsDirectory, "connection-settings.json");
    }

    public string SettingsPath => _settingsPath;

    public ConnectionSettings Load()
    {
        if (!File.Exists(_settingsPath)) return DefaultSettings();
        try
        {
            var persisted = JsonSerializer.Deserialize<PersistedConnectionSettings>(File.ReadAllText(_settingsPath));
            if (persisted is null) return DefaultSettings();
            var apiKey = string.Empty;
            var remember = persisted.RememberApiKey && !string.IsNullOrWhiteSpace(persisted.ProtectedApiKey);
            if (remember)
            {
                var encrypted = Convert.FromBase64String(persisted.ProtectedApiKey!);
                var decrypted = ProtectedData.Unprotect(encrypted, OptionalEntropy, DataProtectionScope.CurrentUser);
                apiKey = Encoding.UTF8.GetString(decrypted);
                CryptographicOperations.ZeroMemory(decrypted);
            }
            return new ConnectionSettings(
                string.IsNullOrWhiteSpace(persisted.Host) ? "192.168.1.1" : persisted.Host,
                persisted.VerifyTls,
                remember,
                apiKey);
        }
        catch
        {
            return DefaultSettings();
        }
    }

    public void Save(string host, bool verifyTls, bool rememberApiKey, string apiKey)
    {
        string? protectedApiKey = null;
        if (rememberApiKey)
        {
            if (string.IsNullOrWhiteSpace(apiKey)) throw new InvalidOperationException("无法保存空的 API Key。");
            var plaintext = Encoding.UTF8.GetBytes(apiKey);
            try
            {
                var encrypted = ProtectedData.Protect(plaintext, OptionalEntropy, DataProtectionScope.CurrentUser);
                protectedApiKey = Convert.ToBase64String(encrypted);
                CryptographicOperations.ZeroMemory(encrypted);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        var persisted = new PersistedConnectionSettings(
            SchemaVersion: 1,
            Host: string.IsNullOrWhiteSpace(host) ? "192.168.1.1" : host.Trim(),
            VerifyTls: verifyTls,
            RememberApiKey: rememberApiKey,
            ProtectedApiKey: protectedApiKey);
        var directory = Path.GetDirectoryName(_settingsPath) ?? throw new InvalidOperationException("设置目录无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = _settingsPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(persisted, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        File.Move(temporaryPath, _settingsPath, overwrite: true);
    }

    public void ForgetApiKey(string host, bool verifyTls) => Save(host, verifyTls, rememberApiKey: false, apiKey: string.Empty);

    private static ConnectionSettings DefaultSettings() => new("192.168.1.1", VerifyTls: false, RememberApiKey: true, ApiKey: string.Empty);

    private sealed record PersistedConnectionSettings(
        int SchemaVersion,
        string Host,
        bool VerifyTls,
        bool RememberApiKey,
        string? ProtectedApiKey);
}
