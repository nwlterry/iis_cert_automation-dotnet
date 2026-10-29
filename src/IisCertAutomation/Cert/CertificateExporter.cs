using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using IisCertAutomation.Security;

namespace IisCertAutomation.Cert;

public static class CertificateExporter
{
    public static int ExportMatching(string outputDirectory, string tempDirectory, IReadOnlyList<string> sniHostNames, IReadOnlyList<string> nodeHostNames, string password, int backupKeep, Action<string> log)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("The LocalMachine certificate store is only available on Windows.");
        }

        PathGuard.RequireSafePath(outputDirectory);
        PathGuard.RequireSafePath(tempDirectory);
        Directory.CreateDirectory(outputDirectory);
        Directory.CreateDirectory(tempDirectory);

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        var exported = 0;
        foreach (var cert in store.Certificates)
        {
            var cn = ExportPlan.CommonName(cert.Subject);
            if (cn is null || !sniHostNames.Contains(cn, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!cert.HasPrivateKey)
            {
                log("Skipping certificate without a private key: " + cert.Subject);
                continue;
            }

            byte[]? pfx = null;
            try
            {
                pfx = cert.Export(X509ContentType.Pfx, password);
                foreach (var name in ExportPlan.OutputNames(cn, sniHostNames, nodeHostNames))
                {
                    var destination = PathGuard.CombineUnderRoot(outputDirectory, FileNameSanitizer.ForPfx(name));
                    BackupExisting(outputDirectory, cn, destination, backupKeep);
                    var temp = PathGuard.CombineUnderRoot(tempDirectory, FileNameSanitizer.ForPfx(name));
                    File.WriteAllBytes(temp, pfx);
                    Verify(temp, password);
                    File.Copy(temp, destination, overwrite: true);
                    Verify(destination, password);
                    File.Delete(temp);
                    exported++;
                    log("Exported " + destination);
                }
            }
            finally
            {
                if (pfx is not null)
                {
                    CryptographicOperations.ZeroMemory(pfx);
                }
            }
        }

        return exported;
    }

    private static void BackupExisting(string outputDirectory, string commonName, string destination, int backupKeep)
    {
        if (!File.Exists(destination))
        {
            return;
        }

        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
        var backupName = FileNameSanitizer.ForPfx(commonName)[..^4] + "_" + stamp + ".pfx.bak";
        var backup = PathGuard.CombineUnderRoot(outputDirectory, backupName);
        File.Copy(destination, backup, overwrite: false);
        var prefix = FileNameSanitizer.ForPfx(commonName)[..^4] + "_";
        var existing = Directory.GetFiles(outputDirectory, prefix + "*.pfx.bak")
            .Select(path => (path, File.GetCreationTimeUtc(path)))
            .ToArray();
        foreach (var stale in BackupPlanner.SelectForDeletion(existing, backupKeep))
        {
            File.Delete(stale);
        }
    }

    private static void Verify(string path, string password)
    {
        using var loaded = LoadEphemeral(path, password);
        if (!loaded.HasPrivateKey)
        {
            throw new InvalidOperationException("Exported PFX did not contain a private key.");
        }
    }

    private static X509Certificate2 LoadEphemeral(string path, string password)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(path, password, X509KeyStorageFlags.EphemeralKeySet);
#else
        return new X509Certificate2(path, password, X509KeyStorageFlags.EphemeralKeySet);
#endif
    }
}
