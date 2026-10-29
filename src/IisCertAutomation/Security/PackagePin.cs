namespace IisCertAutomation.Security;

public static class PackagePin
{
    public const string CredentialManagerNupkgSha256 = "f520ddc58ab12e888bd9fb50d56ead511aa2b416df07ccef01800775f4501299";

    public static void RequireSha256(string path, string expectedHex)
    {
        var actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
        if (!actual.Equals(expectedHex, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Package hash mismatch. Refusing to use an unexpected file.");
        }
    }
}
