using System.Text.Json;
using System.Text.Json.Serialization;

namespace IisCertAutomation.Config;

public sealed class AppConfig
{
    public string? CcsPhysicalPath { get; init; }
    public string[] SniHostNames { get; init; } = [];
    public string[] NodeHostNames { get; init; } = [];
    public string? FileServer { get; init; }
    public string? UncPath { get; init; }
    public string? MappedDrive { get; init; }
    public string? MappedTestPath { get; init; }
    public string HealthUrl { get; init; } = "https://localhost/";
    public bool AllowInsecureHealthCheck { get; init; }
    public string LogDirectory { get; init; } = @"C:\Logs";
    public string TempDirectory { get; init; } = @"C:\Temp";
    public int MaxLogFiles { get; init; } = 5;
    public int BackupKeep { get; init; } = 3;
    public string CredentialTarget { get; init; } = "PFXCertPassword";
    public string TaskName { get; init; } = "Certificate Export on Renewal";

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static AppConfig Load(string path)
    {
        var text = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(text);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException("Config root must be an object.");
        }

        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            if (IsSecretName(prop.Name))
            {
                throw new InvalidDataException("Config must not contain a password field. Store the PFX password only in Credential Manager.");
            }
        }

        return JsonSerializer.Deserialize<AppConfig>(text, JsonOptions)
            ?? throw new InvalidDataException("Config was empty.");
    }

    public static bool IsSecretName(string name)
    {
        return name.Equals("password", StringComparison.OrdinalIgnoreCase)
            || name.Equals("pfxPassword", StringComparison.OrdinalIgnoreCase)
            || name.Equals("passwd", StringComparison.OrdinalIgnoreCase)
            || name.Equals("secret", StringComparison.OrdinalIgnoreCase)
            || name.Equals("privateKey", StringComparison.OrdinalIgnoreCase)
            || name.Equals("privateKeyPassword", StringComparison.OrdinalIgnoreCase);
    }
}
