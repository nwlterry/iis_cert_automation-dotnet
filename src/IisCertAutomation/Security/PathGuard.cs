using System.Text.RegularExpressions;

namespace IisCertAutomation.Security;

public static partial class PathGuard
{
    [GeneratedRegex(@"^(?:[A-Za-z]:\\(?:[^\\/:*?""<>|]+\\)*[^\\/:*?""<>|]+|\\\\[^\\/:*?""<>|]+\\[^\\/:*?""<>|]+(?:\\[^\\/:*?""<>|]+)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex SafePath();

    public static void RequireSafePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 240 || HasMetacharacter(path) || !SafePath().IsMatch(path))
        {
            throw new InvalidOperationException("Refusing unsafe path. Use a drive path or UNC path with no quotes or shell metacharacters.");
        }
    }

    public static void RequireSafeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Length > 253 || !HostPattern().IsMatch(host))
        {
            throw new InvalidOperationException("Refusing unsafe host name.");
        }
    }

    public static void RequireSafeTaskName(string taskName)
    {
        if (string.IsNullOrWhiteSpace(taskName) || !TaskNamePattern().IsMatch(taskName))
        {
            throw new InvalidOperationException("Refusing unsafe scheduled task name.");
        }
    }

    public static string CombineUnderRoot(string root, string fileName)
    {
        var leaf = Path.GetFileName(fileName);
        if (!string.Equals(leaf, fileName, StringComparison.Ordinal)
            || leaf.Contains("..", StringComparison.Ordinal)
            || leaf.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidOperationException("Refusing unsafe file name.");
        }

        var rootFull = Path.GetFullPath(root);
        var full = Path.GetFullPath(Path.Combine(rootFull, leaf));
        var prefix = rootFull.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Resolved path escapes the output directory.");
        }

        return full;
    }

    private static bool HasMetacharacter(string path)
    {
        foreach (var ch in path)
        {
            if (ch is '\'' or '"' or '`' or '$' or ';' or '&' or '|' or '<' or '>' or '\r' or '\n' or '\0')
            {
                return true;
            }
        }

        return false;
    }

    [GeneratedRegex("^[A-Za-z0-9.-]{1,253}$", RegexOptions.CultureInvariant)]
    private static partial Regex HostPattern();

    [GeneratedRegex("^[A-Za-z0-9 ._-]{1,80}$", RegexOptions.CultureInvariant)]
    private static partial Regex TaskNamePattern();
}
