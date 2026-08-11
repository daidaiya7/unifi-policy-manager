namespace UniFiDnsManager.Models;

public sealed record UniFiSite(string Id, string InternalReference, string Name)
{
    public string DisplayName => string.Equals(Name, InternalReference, StringComparison.OrdinalIgnoreCase)
        ? Name
        : $"{Name} ({InternalReference})";
}
