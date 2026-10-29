using System.Text.RegularExpressions;

namespace IisCertAutomation.Cert;

public static partial class BindingParser
{
    public sealed record HttpsBinding(string Host, int Port, string PfxFile);

    public static IReadOnlyList<HttpsBinding> ParseAppCmdSites(string output)
    {
        var found = new List<HttpsBinding>();
        foreach (var rawLine in output.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (Match match in HttpsBindingPattern().Matches(rawLine))
            {
                if (!int.TryParse(match.Groups[1].Value, out var port))
                {
                    continue;
                }

                var host = match.Groups[2].Value;
                var pfx = string.IsNullOrEmpty(host) ? "default.pfx" : host + ".pfx";
                found.Add(new HttpsBinding(host, port, pfx));
            }
        }

        return found;
    }

    [GeneratedRegex(@"https/[^:]+:(\d+):([^ ,]*)", RegexOptions.CultureInvariant)]
    private static partial Regex HttpsBindingPattern();
}
