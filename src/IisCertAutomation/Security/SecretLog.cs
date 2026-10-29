namespace IisCertAutomation.Security;

public static class SecretLog
{
    public static string DescribePresence(string? secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return "credential absent";
        }

        return "credential present";
    }

    public static string Redact(string message, string? secret)
    {
        if (string.IsNullOrEmpty(message) || string.IsNullOrEmpty(secret) || secret.Length < 4)
        {
            return message;
        }

        return message.Replace(secret, "<redacted>", StringComparison.Ordinal);
    }
}
