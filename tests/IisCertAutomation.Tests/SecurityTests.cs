using System.Xml.Linq;
using IisCertAutomation.Cert;
using IisCertAutomation.Commands;
using IisCertAutomation.Config;
using IisCertAutomation.Security;
using IisCertAutomation.Share;
using IisCertAutomation.Windows;
using Xunit;

namespace IisCertAutomation.Tests;

public class SecurityTests
{
    [Fact]
    public void PathGuard_rejects_shell_metacharacters()
    {
        Assert.Throws<InvalidOperationException>(() => PathGuard.RequireSafePath(@"C:\Logs\a&calc.exe"));
        Assert.Throws<InvalidOperationException>(() => PathGuard.RequireSafePath("C:\\Logs\\quote\".pfx"));
        PathGuard.RequireSafePath(@"C:\Logs");
        PathGuard.RequireSafePath(@"\\fileserver.example\IIS_Cert_Store");
    }

    [Fact]
    public void FileName_strips_traversal()
    {
        var name = FileNameSanitizer.ForPfx(@"..\..\evil.pfx");
        Assert.DoesNotContain("/", name, StringComparison.Ordinal);
        Assert.DoesNotContain("\\", name, StringComparison.Ordinal);
        Assert.DoesNotContain("..", name, StringComparison.Ordinal);
        Assert.EndsWith(".pfx", name, StringComparison.Ordinal);
        Assert.Equal("evil.pfx", name);
    }

    [Fact]
    public void Secret_is_not_described()
    {
        const string secret = "hunter2-example";
        var text = SecretLog.DescribePresence(secret);
        Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
        var redacted = SecretLog.Redact("wrote " + secret + " to disk", secret);
        Assert.Equal("wrote <redacted> to disk", redacted);
    }

    [Fact]
    public void Config_rejects_password_field()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """{"sniHostNames":["a.example"],"pfxPassword":"nope"}""");
            Assert.Throws<InvalidDataException>(() => AppConfig.Load(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Config_loads_site_values()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, """
                {"sniHostNames":["www.example.com"],"uncPath":"\\\\fileserver.example\\Share","mappedDrive":"E","allowInsecureHealthCheck":false}
                """);
            var cfg = AppConfig.Load(path);
            Assert.Equal("www.example.com", cfg.SniHostNames[0]);
            Assert.False(cfg.AllowInsecureHealthCheck);
            Assert.Equal("PFXCertPassword", cfg.CredentialTarget);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Backup_keeps_three_newest()
    {
        var now = DateTime.UtcNow;
        var files = Enumerable.Range(0, 5).Select(i => ($"f{i}", now.AddMinutes(i))).ToArray();
        var stale = BackupPlanner.SelectForDeletion(files, 3);
        Assert.Equal(2, stale.Count);
        Assert.Contains("f0", stale);
        Assert.Contains("f1", stale);
    }

    [Fact]
    public void Binding_parser_reads_sni()
    {
        var parsed = BindingParser.ParseAppCmdSites("SITE \"Default\" (id:1,bindings:https/*:443:www.example.com,state:Started)");
        Assert.Single(parsed);
        Assert.Equal("www.example.com", parsed[0].Host);
        Assert.Equal(443, parsed[0].Port);
        Assert.Equal("www.example.com.pfx", parsed[0].PfxFile);
    }

    [Fact]
    public void Export_plan_names_sni_and_nodes()
    {
        var names = ExportPlan.OutputNames("www.example.com", ["www.example.com", "other.example"], ["node1", "node2"]);
        Assert.Equal(["www.example.com", "node1", "node2"], names);
    }

    [Fact]
    public void Common_name_is_read_from_subject()
    {
        Assert.Equal("www.example.com", ExportPlan.CommonName("CN=www.example.com, O=Example"));
        Assert.Null(ExportPlan.CommonName("O=Example"));
    }

    [Fact]
    public void Cli_rejects_password_argument()
    {
        Assert.Throws<InvalidOperationException>(() => Cli.RejectPasswordOnCommandLine(["setup", "--password", "secret"]));
        Cli.RejectPasswordOnCommandLine(["export", "--config", @"C:\Scripts\iis-cert-automation.config.json"]);
    }

    [Fact]
    public void Task_xml_targets_system_and_has_no_password()
    {
        var xml = TaskXml.BuildExportTask(
            "Certificate Export on Renewal",
            @"C:\Tools\IisCertAutomation.exe",
            @"C:\Scripts\iis-cert-automation.config.json");
        Assert.Contains("S-1-5-18", xml, StringComparison.Ordinal);
        Assert.Contains("IisCertAutomation.exe", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("password", xml, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(XDocument.Parse(xml).Root);
    }

    [Fact]
    public void Confinement_blocks_traversal_name()
    {
        var root = Path.Combine(Path.GetTempPath(), "iis-cert-confine-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            Assert.Throws<InvalidOperationException>(() => PathGuard.CombineUnderRoot(root, @"..\evil.pfx"));
        }
        finally
        {
            Directory.Delete(root);
        }
    }

    [Fact]
    public void Package_pin_matches_vendored_module()
    {
        Assert.Equal(64, PackagePin.CredentialManagerNupkgSha256.Length);
        Assert.Equal("f520ddc58ab12e888bd9fb50d56ead511aa2b416df07ccef01800775f4501299", PackagePin.CredentialManagerNupkgSha256);
    }

    [Fact]
    public void Health_accepts_2xx_and_3xx_only()
    {
        Assert.True(SharePlan.IsHealthyStatus(200));
        Assert.True(SharePlan.IsHealthyStatus(302));
        Assert.False(SharePlan.IsHealthyStatus(404));
        Assert.False(SharePlan.IsHealthyStatus(500));
    }

    [Fact]
    public void Remap_only_when_the_test_path_is_down()
    {
        Assert.False(SharePlan.NeedsRemap(testPathExists: true));
        Assert.True(SharePlan.NeedsRemap(testPathExists: false));
    }

    [Fact]
    public void Log_rotation_keeps_certificate_export_logs()
    {
        var cutoff = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        var stale = SharePlan.SelectExpiredLogs(
        [
            ("UNC_Check_2026-09-01.log", cutoff.AddDays(-20)),
            ("CertificateExport_20260101.log", cutoff.AddDays(-40)),
            ("UNC_Check_2026-10-20.log", cutoff.AddDays(1))
        ],
        cutoff);
        Assert.Equal(["UNC_Check_2026-09-01.log"], stale);
    }

    [Fact]
    public void Share_task_is_hourly_system_and_has_no_password()
    {
        var xml = TaskXml.BuildShareTask(
            "UNC Connectivity Checker",
            @"C:\Tools\IisCertAutomation.exe",
            @"unc-check --config ""C:\Scripts\iis-cert-automation.config.json""",
            "Checks the UNC path.",
            hourly: true);
        Assert.Contains("PT1H", xml, StringComparison.Ordinal);
        Assert.Contains("S-1-5-18", xml, StringComparison.Ordinal);
        Assert.Contains("unc-check", xml, StringComparison.Ordinal);
        Assert.DoesNotContain("password", xml, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(XDocument.Parse(xml).Root);
    }
}
