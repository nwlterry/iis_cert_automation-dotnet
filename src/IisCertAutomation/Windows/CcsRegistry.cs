using Microsoft.Win32;

namespace IisCertAutomation.Windows;

public static class CcsRegistry
{
    public const string KeyPath = @"SOFTWARE\Microsoft\IIS\CentralCertProvider";

    public sealed record CcsSettings(bool Found, int Enabled, string? CertStoreLocation);

    public static CcsSettings Read()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS CCS registry is only available on Windows.");
        }

        using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: false);
        if (key is null)
        {
            return new CcsSettings(false, 0, null);
        }

        var enabled = key.GetValue("Enabled") is int value ? value : 0;
        var location = key.GetValue("CertStoreLocation") as string;
        return new CcsSettings(true, enabled, location);
    }

    public static void WriteLocation(string ccsPath)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS CCS registry is only available on Windows.");
        }

        using var key = Registry.LocalMachine.CreateSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not open the CCS registry key.");
        key.SetValue("Enabled", 1, RegistryValueKind.DWord);
        key.SetValue("CertStoreLocation", ccsPath, RegistryValueKind.String);
        key.DeleteValue("Username", throwOnMissingValue: false);
        key.DeleteValue("Password", throwOnMissingValue: false);
    }

    public static void RequireMatch(string ccsPath)
    {
        var settings = Read();
        if (!settings.Found)
        {
            throw new InvalidOperationException("CCS registry key not found. Run setup on the primary node first.");
        }

        if (settings.Enabled != 1 || !string.Equals(settings.CertStoreLocation, ccsPath, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("CCS registry does not match the requested path.");
        }
    }

    public static void RemoveCredentialValues()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("IIS CCS registry is only available on Windows.");
        }

        using var key = Registry.LocalMachine.OpenSubKey(KeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not open the CCS registry key.");
        key.DeleteValue("Username", throwOnMissingValue: false);
        key.DeleteValue("Password", throwOnMissingValue: false);
    }
}
