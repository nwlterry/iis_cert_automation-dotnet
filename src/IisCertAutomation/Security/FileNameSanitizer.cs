namespace IisCertAutomation.Security;

public static class FileNameSanitizer
{
    public static string ForPfx(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new InvalidOperationException("Certificate file name is empty.");
        }

        var trimmed = name.Trim();
        if (trimmed.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[..^4];
        }

        var invalid = Path.GetInvalidFileNameChars();
        var chars = trimmed.Select(ch => invalid.Contains(ch) || ch is '/' or '\\' or ':' ? '_' : ch).ToArray();
        var cleaned = new string(chars).Trim(' ', '.', '_');
        while (cleaned.Contains("..", StringComparison.Ordinal))
        {
            cleaned = cleaned.Replace("..", "_", StringComparison.Ordinal);
        }

        cleaned = cleaned.Trim(' ', '.', '_');
        if (cleaned.Length == 0 || cleaned is "." or "..")
        {
            throw new InvalidOperationException("Certificate file name is not usable.");
        }

        return cleaned + ".pfx";
    }
}
