namespace IisCertAutomation.Cert;

public static class BackupPlanner
{
    public static IReadOnlyList<string> SelectForDeletion(IEnumerable<(string Path, DateTime CreatedUtc)> files, int keep)
    {
        if (keep < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(keep));
        }

        return files
            .OrderByDescending(file => file.CreatedUtc)
            .Skip(keep)
            .Select(file => file.Path)
            .ToArray();
    }
}
