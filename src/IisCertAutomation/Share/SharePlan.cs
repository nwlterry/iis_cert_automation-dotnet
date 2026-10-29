namespace IisCertAutomation.Share;

public static class SharePlan
{
    public const string MapTaskName = "Map Drive As System";
    public const string UncTaskName = "UNC Connectivity Checker";

    public static bool NeedsRemap(bool testPathExists) => !testPathExists;

    public static bool IsHealthyStatus(int statusCode) => statusCode is >= 200 and <= 399;

    public static IReadOnlyList<string> SelectExpiredLogs(
        IEnumerable<(string Name, DateTime LastWriteUtc)> files,
        DateTime cutoffUtc)
    {
        return files
            .Where(file => file.Name.StartsWith("UNC_Check_", StringComparison.OrdinalIgnoreCase)
                && file.Name.EndsWith(".log", StringComparison.OrdinalIgnoreCase)
                && file.LastWriteUtc < cutoffUtc)
            .Select(file => file.Name)
            .ToArray();
    }
}
