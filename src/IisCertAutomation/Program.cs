using IisCertAutomation.Cert;
using IisCertAutomation.Commands;
using IisCertAutomation.Config;
using IisCertAutomation.Security;
using IisCertAutomation.Share;
using IisCertAutomation.Windows;

namespace IisCertAutomation;

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            Cli.RejectPasswordOnCommandLine(args);
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
            {
                Console.WriteLine("""
                    IisCertAutomation (.NET 8 and .NET 10, same source)

                    CCS
                      setup --ccs \\server\share --config C:\Scripts\iis-cert-automation.config.json
                      setup-node --ccs \\server\share
                      export --config C:\Scripts\iis-cert-automation.config.json
                      store-credential --blob C:\Temp\pfx.bin --target PFXCertPassword

                    File share
                      map-drive --config C:\Scripts\iis-cert-automation.config.json
                      unc-check --config C:\Scripts\iis-cert-automation.config.json
                      register-share-tasks --config C:\Scripts\iis-cert-automation.config.json

                    The PFX password is prompted by setup. It is not accepted as an argument.
                    Prefer net10.0. setup-node does not store a password.
                    """);
                return args.Length == 0 ? 1 : 0;
            }

            return args[0].ToLowerInvariant() switch
            {
                "setup" => Setup(args.AsSpan(1).ToArray()),
                "setup-node" => SetupNode(args.AsSpan(1).ToArray()),
                "export" => Export(args.AsSpan(1).ToArray()),
                "store-credential" => StoreCredential(args.AsSpan(1).ToArray()),
                "map-drive" => MapDrive(args.AsSpan(1).ToArray()),
                "unc-check" => UncCheck(args.AsSpan(1).ToArray()),
                "register-share-tasks" => RegisterShareTasks(args.AsSpan(1).ToArray()),
                "qa" => Qa(args.AsSpan(1).ToArray()),
                "qa-write" => QaWrite(args.AsSpan(1).ToArray()),
                _ => Unknown(args[0])
            };
        }
        catch (InvalidDataException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
        catch (PlatformNotSupportedException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 3;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or IOException)
        {
            Console.Error.WriteLine(SecretLog.Redact(ex.Message, null));
            return 1;
        }
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine("Unknown command: " + command);
        return 1;
    }

    private static int Setup(string[] args)
    {
        RequireWindows();
        var ccs = Cli.Option(args, "--ccs") ?? throw new InvalidOperationException("--ccs is required.");
        var configPath = Cli.Option(args, "--config") ?? throw new InvalidOperationException("--config is required.");
        PathGuard.RequireSafePath(ccs);
        PathGuard.RequireSafePath(configPath);
        var config = AppConfig.Load(configPath);
        var taskName = string.IsNullOrWhiteSpace(config.TaskName) ? "Certificate Export on Renewal" : config.TaskName;
        PathGuard.RequireSafeTaskName(taskName);
        var secret = Cli.ReadConsoleSecret();
        try
        {
            var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss_fff");
            var blob = Path.Combine(config.TempDirectory, "PfxCredBlob_" + stamp + ".bin");
            var result = blob + ".result";
            PathGuard.RequireSafePath(config.TempDirectory);
            Directory.CreateDirectory(config.TempDirectory);
            PathGuard.RequireSafePath(blob);
            CredentialVault.ProtectToFile(secret, blob);
            CommandRunner.TightenAcl(blob);
            var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Could not resolve this executable.");
            PathGuard.RequireSafePath(exe);
            var arguments = "store-credential --blob \"" + blob + "\" --target " + config.CredentialTarget + " --result \"" + result + "\"";
            RegisterTask("Store PFX Credential", exe, arguments, "Stores the DPAPI-protected PFX password for SYSTEM.", eventTrigger: false);
            var run = CommandRunner.Run("schtasks.exe", "/Run", "/TN", "Store PFX Credential");
            if (run != 0)
            {
                throw new InvalidOperationException("Could not start the SYSTEM credential task.");
            }
            var deadline = DateTime.UtcNow.AddMinutes(2);
            while (DateTime.UtcNow < deadline && !File.Exists(result))
            {
                Thread.Sleep(TimeSpan.FromSeconds(1));
            }

            if (!File.Exists(result) || File.ReadAllText(result).Trim() != "OK")
            {
                throw new InvalidOperationException("SYSTEM did not confirm credential storage.");
            }

            File.Delete(result);
            CcsRegistry.WriteLocation(ccs);
            var exportXml = TaskXml.BuildExportTask(taskName, exe, configPath);
            RegisterXml(taskName, exportXml);
            Console.WriteLine("Setup completed. Password value was not logged.");
            return 0;
        }
        finally
        {
            secret = "";
        }
    }

    private static int StoreCredential(string[] args)
    {
        RequireWindows();
        var blob = Cli.Option(args, "--blob") ?? throw new InvalidOperationException("--blob is required.");
        var target = Cli.Option(args, "--target") ?? "PFXCertPassword";
        var result = Cli.Option(args, "--result") ?? blob + ".result";
        PathGuard.RequireSafePath(blob);
        PathGuard.RequireSafePath(result);
        if (!target.Equals("PFXCertPassword", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Refusing unexpected credential target.");
        }

        var secret = CredentialVault.UnprotectFile(blob);
        try
        {
            CredentialVault.WriteMachineGeneric(target, "PFXUser", secret);
            File.WriteAllText(result, "OK");
            return 0;
        }
        finally
        {
            secret = "";
            if (File.Exists(blob))
            {
                File.Delete(blob);
            }
        }
    }

    private static int Export(string[] args)
    {
        RequireWindows();
        var configPath = Cli.Option(args, "--config") ?? throw new InvalidOperationException("--config is required.");
        PathGuard.RequireSafePath(configPath);
        var config = AppConfig.Load(configPath);
        if (config.SniHostNames.Length == 0)
        {
            throw new InvalidOperationException("Config sniHostNames is required.");
        }

        var settings = CcsRegistry.Read();
        var output = settings.CertStoreLocation ?? config.CcsPhysicalPath ?? throw new InvalidOperationException("CCS path is not configured.");
        PathGuard.RequireSafePath(output);
        var secret = CredentialVault.ReadSecret(config.CredentialTarget);
        try
        {
            var count = CertificateExporter.ExportMatching(output, config.TempDirectory, config.SniHostNames, config.NodeHostNames, secret, config.BackupKeep, Console.WriteLine);
            Console.WriteLine("Exported " + count + " file(s). Password value was not logged.");
            return count == 0 ? 4 : 0;
        }
        finally
        {
            secret = "";
        }
    }

    private static int SetupNode(string[] args)
    {
        RequireWindows();
        var ccs = Cli.Option(args, "--ccs") ?? throw new InvalidOperationException("--ccs is required.");
        PathGuard.RequireSafePath(ccs);
        CcsRegistry.RequireMatch(ccs);
        if (!Directory.Exists(ccs))
        {
            throw new InvalidOperationException("CCS path is not accessible.");
        }

        CcsRegistry.RemoveCredentialValues();
        Console.WriteLine("Node check completed. Username and Password registry values were removed. No password was stored.");
        return 0;
    }

    private static int MapDrive(string[] args)
    {
        RequireWindows();
        var config = LoadShare(args);
        if (!SharePlan.NeedsRemap(Directory.Exists(config.MappedTestPath)))
        {
            Console.WriteLine("UNC path is accessible.");
            return 0;
        }

        return Remap(config) ? 0 : 4;
    }

    private static int UncCheck(string[] args)
    {
        RequireWindows();
        var config = LoadShare(args);
        if (SharePlan.NeedsRemap(Directory.Exists(config.MappedTestPath)) && !Remap(config))
        {
            return 4;
        }

        using var handler = new HttpClientHandler();
        if (config.AllowInsecureHealthCheck)
        {
            Console.Error.WriteLine("WARNING: TLS certificate validation disabled for health check by config.");
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        for (var attempt = 1; attempt <= 10; attempt++)
        {
            var reset = CommandRunner.Run("iisreset.exe", "/restart");
            Thread.Sleep(TimeSpan.FromSeconds(3));
            if (reset != 0)
            {
                Console.Error.WriteLine("iisreset failed on attempt " + attempt + ".");
                Thread.Sleep(TimeSpan.FromSeconds(5));
                continue;
            }

            try
            {
                using var response = client.GetAsync(config.HealthUrl).GetAwaiter().GetResult();
                var status = (int)response.StatusCode;
                Console.WriteLine("Health status: " + status);
                if (SharePlan.IsHealthyStatus(status))
                {
                    Console.WriteLine("IIS health check passed on attempt " + attempt + ".");
                    return 0;
                }
            }
            catch (HttpRequestException ex)
            {
                Console.Error.WriteLine(SecretLog.Redact(ex.Message, null));
            }

            Thread.Sleep(TimeSpan.FromSeconds(5));
        }

        Console.Error.WriteLine("IIS health check failed after 10 attempts.");
        return 4;
    }

    private static int RegisterShareTasks(string[] args)
    {
        RequireWindows();
        var configPath = RequiredConfig(args);
        LoadShare(args);
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("Could not resolve this executable.");
        PathGuard.RequireSafePath(exe);
        var mapArguments = "map-drive --config \"" + configPath + "\"";
        var checkArguments = "unc-check --config \"" + configPath + "\"";
        RegisterXml(SharePlan.MapTaskName, TaskXml.BuildShareTask(SharePlan.MapTaskName, exe, mapArguments, "Maps the configured UNC path after startup.", hourly: false));
        RegisterXml(SharePlan.UncTaskName, TaskXml.BuildShareTask(SharePlan.UncTaskName, exe, checkArguments, "Checks the configured UNC path hourly, then resets IIS and checks HTTPS.", hourly: true));
        Console.WriteLine("File-share tasks registered. No password is used.");
        return 0;
    }

    private static bool Remap(AppConfig config)
    {
        CommandRunner.Run("net.exe", "use", config.MappedDrive + ":", "/delete", "/y");
        var code = CommandRunner.Run("net.exe", "use", config.MappedDrive + ":", config.UncPath!, "/persistent:yes");
        if (code == 0 && Directory.Exists(config.MappedTestPath))
        {
            Console.WriteLine("Reconnected to the UNC path.");
            return true;
        }

        Console.Error.WriteLine("UNC path is not accessible.");
        return false;
    }

    private static AppConfig LoadShare(string[] args)
    {
        var config = AppConfig.Load(RequiredConfig(args));
        if (string.IsNullOrWhiteSpace(config.UncPath) || string.IsNullOrWhiteSpace(config.MappedDrive) || string.IsNullOrWhiteSpace(config.MappedTestPath))
        {
            throw new InvalidOperationException("Config requires uncPath, mappedDrive, and mappedTestPath.");
        }

        PathGuard.RequireSafePath(config.UncPath);
        PathGuard.RequireSafePath(config.MappedTestPath);
        PathGuard.RequireSafePath(config.LogDirectory);
        if (config.MappedDrive.Length != 1 || !char.IsLetter(config.MappedDrive[0]))
        {
            throw new InvalidOperationException("mappedDrive must be a single letter.");
        }

        if (!config.HealthUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || config.HealthUrl.Any(char.IsWhiteSpace) || config.HealthUrl.IndexOfAny(['"', '\'']) >= 0)
        {
            throw new InvalidOperationException("healthUrl must be an https URL with no spaces or quotes.");
        }

        return config;
    }

    private static int Qa(string[] args)
    {
        RequireWindows();
        var config = AppConfig.Load(RequiredConfig(args));
        var settings = CcsRegistry.Read();
        Console.WriteLine(settings.Found
            ? "CCS registry Enabled=" + settings.Enabled + " Location=" + settings.CertStoreLocation
            : "CCS registry key not found.");
        var path = settings.CertStoreLocation ?? config.CcsPhysicalPath;
        if (!string.IsNullOrWhiteSpace(path))
        {
            PathGuard.RequireSafePath(path);
            Console.WriteLine(Directory.Exists(path) ? "CCS path is accessible." : "CCS path is not accessible.");
        }

        return 0;
    }

    private static int QaWrite(string[] args)
    {
        RequireWindows();
        var path = Cli.Option(args, "--path") ?? throw new InvalidOperationException("--path is required.");
        PathGuard.RequireSafePath(path);
        Directory.CreateDirectory(path);
        var file = Path.Combine(path, "qa-write-ok.txt");
        PathGuard.RequireSafePath(file);
        File.WriteAllText(file, "OK");
        return 0;
    }

    private static string RequiredConfig(string[] args)
    {
        var configPath = Cli.Option(args, "--config") ?? throw new InvalidOperationException("--config is required.");
        PathGuard.RequireSafePath(configPath);
        return configPath;
    }

    private static void RequireWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("This command must run on Windows Server with IIS.");
        }
    }

    private static void RegisterTask(string taskName, string executable, string arguments, string description, bool eventTrigger)
    {
        var xml = eventTrigger
            ? TaskXml.BuildExportTask(taskName, executable, arguments)
            : TaskXml.BuildSystemCommand(taskName, executable, arguments, description);
        RegisterXml(taskName, xml);
    }

    private static void RegisterXml(string taskName, string xml)
    {
        var xmlPath = Path.Combine(Path.GetTempPath(), "iis-cert-task-" + Guid.NewGuid().ToString("N") + ".xml");
        File.WriteAllText(xmlPath, xml);
        try
        {
            var code = CommandRunner.Run("schtasks.exe", "/Create", "/TN", taskName, "/XML", xmlPath, "/F");
            if (code != 0)
            {
                throw new InvalidOperationException("schtasks failed to register " + taskName);
            }
        }
        finally
        {
            File.Delete(xmlPath);
        }
    }
}
