namespace IisCertAutomation.Cert;

public static class ExportPlan
{
    public static string? CommonName(string subject)
    {
        const string marker = "CN=";
        var start = subject.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (start < 0)
        {
            return null;
        }

        start += marker.Length;
        var end = subject.IndexOf(',', start);
        var cn = (end < 0 ? subject[start..] : subject[start..end]).Trim().Trim('"');
        return cn.Length == 0 ? null : cn;
    }

    public static IReadOnlyList<string> OutputNames(string commonName, IEnumerable<string> sniHostNames, IEnumerable<string> nodeHostNames)
    {
        var names = new List<string>();
        foreach (var sni in sniHostNames)
        {
            if (string.Equals(sni, commonName, StringComparison.OrdinalIgnoreCase))
            {
                names.Add(sni);
            }
        }

        names.AddRange(nodeHostNames.Where(node => !string.IsNullOrWhiteSpace(node)));
        return names;
    }
}
