using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace UniFiDnsManager.Services;

public sealed record ConnectionSettings(
    string Host,
    bool VerifyTls,
    AuthenticationMode AuthenticationMode,
    bool RememberCredential,
    string Username,
    string Secret);

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
            var mode = Enum.TryParse<AuthenticationMode>(persisted.AuthenticationMode, ignoreCase: true, out var parsedMode)
                ? parsedMode
                : AuthenticationMode.ApiKey;
            var protectedSecret = persisted.ProtectedSecret ?? persisted.ProtectedApiKey;
            var remember = (persisted.RememberCredential ?? persisted.RememberApiKey) && !string.IsNullOrWhiteSpace(protectedSecret);
            var secret = string.Empty;
            if (remember)
            {
                var encrypted = Convert.FromBase64String(protectedSecret!);
                var decrypted = ProtectedData.Unprotect(encrypted, OptionalEntropy, DataProtectionScope.CurrentUser);
                secret = Encoding.UTF8.GetString(decrypted);
                CryptographicOperations.ZeroMemory(decrypted);
            }
            return new ConnectionSettings(
                string.IsNullOrWhiteSpace(persisted.Host) ? "192.168.1.1" : persisted.Host,
                persisted.VerifyTls,
                mode,
                remember,
                persisted.Username ?? string.Empty,
                secret);
        }
        catch
        {
            return DefaultSettings();
        }
    }

    public void Save(
        string host,
        bool verifyTls,
        AuthenticationMode authenticationMode,
        bool rememberCredential,
        string username,
        string secret)
    {
        string? protectedSecret = null;
        if (rememberCredential)
        {
            if (string.IsNullOrEmpty(secret)) throw new InvalidOperationException("无法保存空的认证凭据。");
            var plaintext = Encoding.UTF8.GetBytes(secret);
            try
            {
                var encrypted = ProtectedData.Protect(plaintext, OptionalEntropy, DataProtectionScope.CurrentUser);
                protectedSecret = Convert.ToBase64String(encrypted);
                CryptographicOperations.ZeroMemory(encrypted);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }

        var persisted = new PersistedConnectionSettings(
            SchemaVersion: 2,
            Host: string.IsNullOrWhiteSpace(host) ? "192.168.1.1" : host.Trim(),
            VerifyTls: verifyTls,
            AuthenticationMode: authenticationMode.ToString(),
            RememberCredential: rememberCredential,
            Username: authenticationMode == AuthenticationMode.LocalAccount ? username.Trim() : string.Empty,
            ProtectedSecret: protectedSecret,
            RememberApiKey: false,
            ProtectedApiKey: null);
        var directory = Path.GetDirectoryName(_settingsPath) ?? throw new InvalidOperationException("设置目录无效。");
        Directory.CreateDirectory(directory);
        var temporaryPath = _settingsPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(persisted, new JsonSerializerOptions { WriteIndented = true }), new UTF8Encoding(false));
        File.Move(temporaryPath, _settingsPath, overwrite: true);
    }

    public void ForgetCredential(string host, bool verifyTls, AuthenticationMode authenticationMode, string username) =>
        Save(host, verifyTls, authenticationMode, rememberCredential: false, username, secret: string.Empty);

    private static ConnectionSettings DefaultSettings() =>
        new("192.168.1.1", VerifyTls: false, AuthenticationMode.ApiKey, RememberCredential: true, Username: string.Empty, Secret: string.Empty);

    private sealed record PersistedConnectionSettings(
        int SchemaVersion,
        string Host,
        bool VerifyTls,
        string? AuthenticationMode,
        bool? RememberCredential,
        string? Username,
        string? ProtectedSecret,
        bool RememberApiKey,
        string? ProtectedApiKey);
}
